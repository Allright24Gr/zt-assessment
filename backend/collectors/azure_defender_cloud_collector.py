"""azure_defender_cloud_collector.py — Microsoft Defender for Cloud 진단 함수 (Phase A: 15개)

entra_collector.py / defender_collector.py 와 동일한 추상을 가진 모듈.
Microsoft Defender for Cloud 는 Azure Resource Manager(ARM) 하위 리소스 공급자
`Microsoft.Security` 를 통해 REST API 로 제공된다.

인증: Microsoft Entra OAuth 2.0 client_credentials flow.
    POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
    scope: https://management.azure.com/.default
    이후 https://management.azure.com/subscriptions/{sub_id}/providers/Microsoft.Security/...

item_id 체계: {항목번호}.{성숙도번호}_{질문번호} — 다른 collector 와 동일하므로
dispatcher 자동매핑(_autodiscover) 에서 docstring 첫 줄로 자동 추출된다.

# ════════════════════════════════════════════════════════════════════════
# ASSESSMENT.PY 등록 가이드 (통합 시 참조)
# ════════════════════════════════════════════════════════════════════════
# 다른 작업자가 이 모듈을 assessment.py 에 등록할 때 아래 패치 포인트를 참조하라:
#
# ALL_TOOLS = (..., "aws_securityhub", "azure_defender")
# _TOOL_MODULE = {
#     ...,
#     "aws_securityhub": "collectors.aws_security_hub_collector",
#     "azure_defender":  "collectors.azure_defender_cloud_collector",
# }
#
# 새 카테고리: _CLOUD_TOOL_OF / _CLOUD_AUTO_TOOLS — ProfileSelect.cloud_type
#   - aws  → aws_securityhub
#   - azure→ azure_defender
#
# AssessmentRunRequest 필드 추가:
#   azure_defender_creds: Optional[dict] = None
#     # {tenant_id, client_id, client_secret, subscription_id}
#
# _mask_creds 가드 (assessment.py 안 함수에):
#   - azure_defender_creds.client_secret → "***"
#
# set_session_creds 호출 위치 (_run_collectors):
#   - azure_defender_cloud_collector.set_session_creds(req.azure_defender_creds)
# ════════════════════════════════════════════════════════════════════════
"""
from typing import Optional, Any, Tuple, List
from datetime import datetime, timezone
import os
import time
import logging

import httpx

CollectedResult = dict
logger = logging.getLogger(__name__)

# fallback 환경변수 — 사용자가 NewAssessment 에서 자격을 직접 입력하지 않은 경우 사용
AZURE_DEFENDER_TENANT_ID        = os.environ.get("AZURE_DEFENDER_TENANT_ID", "")
AZURE_DEFENDER_CLIENT_ID        = os.environ.get("AZURE_DEFENDER_CLIENT_ID", "")
AZURE_DEFENDER_CLIENT_SECRET    = os.environ.get("AZURE_DEFENDER_CLIENT_SECRET", "")
AZURE_DEFENDER_SUBSCRIPTION_ID  = os.environ.get("AZURE_DEFENDER_SUBSCRIPTION_ID", "")

LOGIN_BASE = "https://login.microsoftonline.com"
ARM_BASE   = "https://management.azure.com"
SCOPE      = "https://management.azure.com/.default"

# ─── session-scoped credential override ──────────────────────────────────────
_session_creds: Optional[dict] = None
_token_cache: Optional[dict] = None  # {"token": str, "expires_at": float}


def set_session_creds(creds: Optional[dict]) -> None:
    """세션 단위 Azure Defender 자격을 모듈 전역에 주입. None 이면 해제 + 토큰 캐시 무효화."""
    global _session_creds, _token_cache
    _session_creds = creds or None
    _token_cache = None


def _tenant_id() -> str:
    if _session_creds and _session_creds.get("tenant_id"):
        return str(_session_creds["tenant_id"])
    return AZURE_DEFENDER_TENANT_ID


def _client_id() -> str:
    if _session_creds and _session_creds.get("client_id"):
        return str(_session_creds["client_id"])
    return AZURE_DEFENDER_CLIENT_ID


def _client_secret() -> str:
    if _session_creds and _session_creds.get("client_secret"):
        return str(_session_creds["client_secret"])
    return AZURE_DEFENDER_CLIENT_SECRET


def _subscription_id() -> str:
    if _session_creds and _session_creds.get("subscription_id"):
        return str(_session_creds["subscription_id"])
    return AZURE_DEFENDER_SUBSCRIPTION_ID


# ─────────────────────────── internal helpers ───────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_result(
    item_id: str,
    maturity: str,
    metric_key: str,
    metric_value: float,
    threshold: float,
    result: str,
    raw_json: dict,
    error: Optional[str] = None,
) -> CollectedResult:
    return {
        "item_id":      item_id,
        "maturity":     maturity,
        "tool":         "azure_defender",
        "result":       result,
        "metric_key":   metric_key,
        "metric_value": float(metric_value),
        "threshold":    float(threshold),
        "raw_json":     raw_json,
        "collected_at": _now_iso(),
        "error":        error,
    }


def _ok(item_id, maturity, result, metric_key, metric_value, threshold, raw_json) -> CollectedResult:
    return _make_result(item_id, maturity, metric_key, metric_value, threshold, result, raw_json or {}, None)


def _err(item_id, maturity, metric_key, threshold, error_msg, raw_json=None) -> CollectedResult:
    return _make_result(item_id, maturity, metric_key, 0.0, threshold, "평가불가", raw_json or {}, error_msg)


def _unavailable(item_id, maturity, metric_key, threshold, error_msg, raw_json=None) -> CollectedResult:
    return _err(item_id, maturity, metric_key, threshold, error_msg, raw_json)


def _mask_creds(creds: dict) -> dict:
    """모듈 내부에서 raw_json/디버그에 자격을 노출해야 할 때 사용하는 가드."""
    safe = dict(creds or {})
    if safe.get("client_secret"):
        safe["client_secret"] = "***"
    return safe


def _get_access_token() -> Optional[str]:
    """Client credentials flow 로 ARM scope 액세스 토큰 발급. 캐시 60s 마진."""
    global _token_cache
    now = time.time()
    if _token_cache and _token_cache.get("expires_at", 0) > now + 60:
        return _token_cache["token"]
    tenant = _tenant_id()
    cid = _client_id()
    cs = _client_secret()
    if not (tenant and cid and cs):
        return None
    url = f"{LOGIN_BASE}/{tenant}/oauth2/v2.0/token"
    try:
        resp = httpx.post(
            url,
            data={
                "client_id":     cid,
                "client_secret": cs,
                "scope":         SCOPE,
                "grant_type":    "client_credentials",
            },
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        _token_cache = {
            "token":      data["access_token"],
            "expires_at": now + float(data.get("expires_in", 3600)),
        }
        return _token_cache["token"]
    except Exception as exc:
        logger.warning("[azure_defender] token fetch failed: %s", exc)
        return None


def _arm_get(
    path: str,
    api_version: str,
    params: Optional[dict] = None,
    timeout: int = 30,
) -> Tuple[Optional[dict], Optional[str]]:
    """ARM REST API GET. (data, error) 튜플. data is None 이면 error 존재.

    path 는 subscription scope 이하 절대 경로 (예: '/providers/Microsoft.Security/alerts').
    """
    token = _get_access_token()
    if not token:
        return None, "Azure Defender 인증 실패: tenant_id/client_id/client_secret 확인 필요"
    sub = _subscription_id()
    if not sub:
        return None, "Azure subscription_id 미설정"
    url = f"{ARM_BASE}/subscriptions/{sub}{path}"
    q = {"api-version": api_version}
    if params:
        q.update(params)
    try:
        resp = httpx.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params=q,
            timeout=timeout,
        )
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"

    if resp.status_code == 401:
        return None, "Azure Defender 권한 부족: 토큰 만료 또는 권한 없음"
    if resp.status_code == 403:
        return None, "Azure Defender 권한 부족: Security Reader 권한 필요"
    if resp.status_code == 404:
        return None, "Azure Defender 리소스 없음 (subscription 확인 필요)"
    try:
        body = resp.json()
    except Exception:
        body = {}
    if 400 <= resp.status_code:
        err = (body.get("error") or {}).get("message") or f"HTTP {resp.status_code}"
        return None, f"Azure Defender API 오류: {err}"
    return body, None


def _arm_collect_value(
    path: str,
    api_version: str,
    params: Optional[dict] = None,
    max_pages: int = 2,
) -> Tuple[Optional[List[dict]], Optional[str]]:
    """nextLink 페이지네이션 처리. value 배열을 합쳐 반환."""
    all_items: list = []
    page_params = dict(params or {})
    cur_path = path
    cur_api = api_version
    for _ in range(max_pages):
        data, err = _arm_get(cur_path, cur_api, page_params)
        if err:
            return None, err
        all_items.extend((data or {}).get("value") or [])
        next_link = (data or {}).get("nextLink")
        if not next_link:
            break
        # nextLink 는 절대 URL — 간단 처리: 더 이상 페이지 안 받음 (지표는 첫 2페이지로 충분)
        break
    return all_items, None


# ─────────────────────────── collectors (15) ───────────────────────────

def collect_sca_compliance(item_id: str, maturity: str) -> CollectedResult:
    """2.1.1.2_1: Secure Score ≥ 70 → 충족 / 40~70 → 부분충족 / 미만 → 미충족"""
    MK, TH = "secure_score_ratio", 0.7
    # GET /providers/Microsoft.Security/secureScores/ascScore?api-version=2020-01-01
    data, err = _arm_get(
        "/providers/Microsoft.Security/secureScores/ascScore",
        api_version="2020-01-01",
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    props = ((data or {}).get("properties") or {})
    score_obj = props.get("score") or {}
    # current/max → 비율로 정규화. percentage 가 0~100 으로 들어오는 경우도 처리.
    pct = score_obj.get("percentage")
    if pct is None:
        cur = float(score_obj.get("current") or 0)
        mx = float(score_obj.get("max") or 0)
        ratio = (cur / mx) if mx > 0 else 0.0
    else:
        ratio = float(pct) / 100.0 if pct > 1 else float(pct)
    if ratio >= TH:
        verdict = "충족"
    elif ratio >= 0.4:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, ratio, TH,
               {"secure_score": score_obj})


def collect_policy_violation_alerts(item_id: str, maturity: str) -> CollectedResult:
    """2.1.1.2_2: 활성(Active) 보안 경고 ≥ 1 → 충족(탐지 동작) / 0 → 미충족"""
    MK, TH = "active_alerts", 1.0
    items, err = _arm_collect_value(
        "/providers/Microsoft.Security/alerts",
        api_version="2022-01-01",
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    items = items or []
    active = [
        a for a in items
        if str(((a.get("properties") or {}).get("status") or "")).lower() == "active"
    ]
    count = len(active)
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"active_alerts": count, "total_alerts": len(items)})


def collect_realtime_threat_alerts(item_id: str, maturity: str) -> CollectedResult:
    """4.4.1.3_2: Severity=High 경고 ≥ 1 → 충족(실시간 위협 탐지 동작)"""
    MK, TH = "high_severity_alerts", 1.0
    items, err = _arm_collect_value(
        "/providers/Microsoft.Security/alerts",
        api_version="2022-01-01",
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    items = items or []
    count = 0
    for a in items:
        sev = str(((a.get("properties") or {}).get("severity") or "")).lower()
        if sev == "high":
            count += 1
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"high_severity_alerts": count, "total_alerts": len(items)})


def collect_threat_detection_alerts(item_id: str, maturity: str) -> CollectedResult:
    """5.2.1.4_1: 전체 보안 경고 ≥ 1 → 충족(위협 탐지 가시성)"""
    MK, TH = "all_alerts", 1.0
    items, err = _arm_collect_value(
        "/providers/Microsoft.Security/alerts",
        api_version="2022-01-01",
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    count = len(items or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"total_alerts": count})


def collect_vuln_summary(item_id: str, maturity: str) -> CollectedResult:
    """5.5.2.2_1: Unhealthy assessments ≥ 1 → 충족(취약점 인벤토리 가시성)"""
    MK, TH = "unhealthy_assessments", 1.0
    items, err = _arm_collect_value(
        "/providers/Microsoft.Security/assessments",
        api_version="2020-01-01",
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    items = items or []
    unhealthy = 0
    for a in items:
        props = a.get("properties") or {}
        status = ((props.get("status") or {}).get("code") or "").lower()
        if status == "unhealthy":
            unhealthy += 1
    verdict = "충족" if unhealthy >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(unhealthy), TH,
               {"unhealthy_assessments": unhealthy, "total_assessments": len(items)})


def collect_critical_unfixed_vulns(item_id: str, maturity: str) -> CollectedResult:
    """5.5.1.3_1: 심각도 High + Unhealthy assessments ≤ 5 → 충족 (적을수록 좋음)"""
    MK, TH = "critical_unhealthy_assessments", 5.0
    items, err = _arm_collect_value(
        "/providers/Microsoft.Security/assessments",
        api_version="2020-01-01",
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    items = items or []
    critical = 0
    for a in items:
        props = a.get("properties") or {}
        status = ((props.get("status") or {}).get("code") or "").lower()
        meta = props.get("metadata") or {}
        sev = str(meta.get("severity") or "").lower()
        if status == "unhealthy" and sev == "high":
            critical += 1
    # 적을수록 좋음
    if critical <= TH:
        verdict = "충족"
    elif critical <= TH * 2:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, float(critical), TH,
               {"critical_unhealthy_assessments": critical,
                "total_assessments": len(items)})


def collect_endpoint_inventory(item_id: str, maturity: str) -> CollectedResult:
    """2.2.1.1_1: Defender for Cloud 가 평가하는 리소스 수 ≥ 1 → 충족(엔드포인트 인벤토리)"""
    MK, TH = "covered_resources", 1.0
    # assessments 의 resourceDetails.Id 집합 = 보호 대상 리소스 근사
    items, err = _arm_collect_value(
        "/providers/Microsoft.Security/assessments",
        api_version="2020-01-01",
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    items = items or []
    resources: set = set()
    for a in items:
        props = a.get("properties") or {}
        rd = props.get("resourceDetails") or {}
        rid = rd.get("Id") or rd.get("id")
        if rid:
            resources.add(rid)
    count = len(resources)
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"covered_resources": count, "total_assessments": len(items)})


def collect_sca_auto_remediation(item_id: str, maturity: str) -> CollectedResult:
    """2.1.1.3_1: 자동 수정 가능 권고 비율 ≥ 30% → 충족 / 10~30% → 부분충족"""
    MK, TH = "remediable_ratio", 0.3
    items, err = _arm_collect_value(
        "/providers/Microsoft.Security/assessments",
        api_version="2020-01-01",
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    items = items or []
    if not items:
        return _err(item_id, maturity, MK, TH, "assessment 항목 없음 (분모 0)")
    total = len(items)
    remediable = 0
    for a in items:
        props = a.get("properties") or {}
        meta = props.get("metadata") or {}
        # remediationDescription 또는 implementationEffort 가 정의되면 수정 가능 권고로 간주
        if meta.get("remediationDescription") or meta.get("implementationEffort"):
            remediable += 1
    ratio = remediable / total
    if ratio >= TH:
        verdict = "충족"
    elif ratio >= 0.1:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, ratio, TH,
               {"total_assessments": total, "remediable": remediable})


def collect_auto_block(item_id: str, maturity: str) -> CollectedResult:
    """2.2.1.4_1: Just-in-time VM Access 정책 ≥ 1 → 충족"""
    MK, TH = "jit_policies", 1.0
    # GET /providers/Microsoft.Security/jitNetworkAccessPolicies?api-version=2020-01-01
    items, err = _arm_collect_value(
        "/providers/Microsoft.Security/jitNetworkAccessPolicies",
        api_version="2020-01-01",
    )
    if err:
        # 일부 region 미지원/권한 부족 — 미충족으로 fallback (Recommendations 의 JIT 권고로 보조)
        rec_items, rerr = _arm_collect_value(
            "/providers/Microsoft.Security/assessments",
            api_version="2020-01-01",
        )
        if rerr:
            return _err(item_id, maturity, MK, TH, err)
        count = 0
        for a in (rec_items or []):
            name = str(((a.get("properties") or {}).get("displayName") or "")).lower()
            if "just-in-time" in name or "jit" in name:
                count += 1
        verdict = "충족" if count >= TH else "미충족"
        return _ok(item_id, maturity, verdict, MK, float(count), TH,
                   {"source": "fallback_recommendations", "jit_recommendations": count})
    count = len(items or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"jit_policies": count})


def collect_ids_alerts(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.3_2: 네트워크 관련 경고 ≥ 1 → 충족(IDS 동작)"""
    MK, TH = "network_alerts", 1.0
    items, err = _arm_collect_value(
        "/providers/Microsoft.Security/alerts",
        api_version="2022-01-01",
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    items = items or []
    count = 0
    for a in items:
        props = a.get("properties") or {}
        # 카테고리 또는 intent 가 네트워크 관련인지 확인
        intents = props.get("intent") or ""
        product = str(props.get("productName") or "").lower()
        tactics = " ".join(str(t) for t in (props.get("kill_chain_intents") or []))
        combined = f"{intents} {product} {tactics}".lower()
        if any(k in combined for k in ("network", "lateral", "exfiltrat", "command and control", "c2")):
            count += 1
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"network_alerts": count, "total_alerts": len(items)})


def collect_icam_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1.2_1: 권한 관련(Privileged) 권고 ≥ 1 → 충족(ICAM 가시성)"""
    MK, TH = "privileged_recommendations", 1.0
    items, err = _arm_collect_value(
        "/providers/Microsoft.Security/assessments",
        api_version="2020-01-01",
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    items = items or []
    count = 0
    for a in items:
        props = a.get("properties") or {}
        meta = props.get("metadata") or {}
        name = str(props.get("displayName") or meta.get("displayName") or "").lower()
        desc = str(meta.get("description") or "").lower()
        if any(k in name or k in desc for k in ("privileged", "identity", "rbac", "iam", "permission")):
            count += 1
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"privileged_recommendations": count, "total_assessments": len(items)})


def collect_privilege_change_alerts(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.3_2: 신원 카테고리 경고 ≥ 1 → 충족 (권한 변경 탐지)"""
    MK, TH = "identity_alerts", 1.0
    items, err = _arm_collect_value(
        "/providers/Microsoft.Security/alerts",
        api_version="2022-01-01",
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    items = items or []
    count = 0
    for a in items:
        props = a.get("properties") or {}
        product = str(props.get("productName") or "").lower()
        name = str(props.get("alertDisplayName") or "").lower()
        intent = str(props.get("intent") or "").lower()
        if any(k in product or k in name or k in intent
               for k in ("identity", "credential", "privilege", "azure ad", "entra")):
            count += 1
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"identity_alerts": count, "total_alerts": len(items)})


def collect_rbac_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.2_1: RBAC 관련 assessment 활성 ≥ 1 → 충족"""
    MK, TH = "rbac_assessments", 1.0
    items, err = _arm_collect_value(
        "/providers/Microsoft.Security/assessments",
        api_version="2020-01-01",
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    items = items or []
    count = 0
    for a in items:
        props = a.get("properties") or {}
        meta = props.get("metadata") or {}
        name = str(props.get("displayName") or meta.get("displayName") or "").lower()
        desc = str(meta.get("description") or "").lower()
        if "rbac" in name or "rbac" in desc or "role-based" in name or "role-based" in desc:
            count += 1
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"rbac_assessments": count, "total_assessments": len(items)})


def collect_tls_services(item_id: str, maturity: str) -> CollectedResult:
    """3.3.1.1_2: TLS/암호화 관련 미준수 assessment ≤ 3 → 충족 (적을수록 좋음)"""
    MK, TH = "unencrypted_assessments", 3.0
    items, err = _arm_collect_value(
        "/providers/Microsoft.Security/assessments",
        api_version="2020-01-01",
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    items = items or []
    count = 0
    keywords = ("tls", "ssl", "encrypt", "in-transit", "https", "secure transfer")
    for a in items:
        props = a.get("properties") or {}
        status = ((props.get("status") or {}).get("code") or "").lower()
        if status != "unhealthy":
            continue
        meta = props.get("metadata") or {}
        name = str(props.get("displayName") or meta.get("displayName") or "").lower()
        desc = str(meta.get("description") or "").lower()
        if any(k in name or k in desc for k in keywords):
            count += 1
    if count <= TH:
        verdict = "충족"
    elif count <= 10:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"unencrypted_assessments": count, "total_assessments": len(items)})


def collect_data_abac_policy(item_id: str, maturity: str) -> CollectedResult:
    """6.2.1.3_1: 데이터 분류/보호 관련 assessment 활성 ≥ 1 → 충족 (Purview/데이터 ABAC 근사)"""
    MK, TH = "data_classification_assessments", 1.0
    items, err = _arm_collect_value(
        "/providers/Microsoft.Security/assessments",
        api_version="2020-01-01",
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    items = items or []
    count = 0
    keywords = ("data", "classification", "purview", "sensitivity", "encryption at rest",
                "storage", "sql", "key vault")
    for a in items:
        props = a.get("properties") or {}
        meta = props.get("metadata") or {}
        name = str(props.get("displayName") or meta.get("displayName") or "").lower()
        desc = str(meta.get("description") or "").lower()
        if any(k in name or k in desc for k in keywords):
            count += 1
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"data_classification_assessments": count, "total_assessments": len(items)})
