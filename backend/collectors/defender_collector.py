"""defender_collector.py — Microsoft Defender for Endpoint 진단 함수 (Phase A: 15개)

entra_collector.py 와 거의 동일한 구조. Microsoft 365 Defender REST API
(https://api.securitycenter.microsoft.com) 를 사용한다. OAuth scope 만 다르다.

인증: Microsoft Entra OAuth 2.0 client_credentials flow.
    POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
    scope: https://api.securitycenter.microsoft.com/.default

item_id 체계: {항목번호}.{성숙도번호}_{질문번호} — 다른 collector 와 동일하므로
dispatcher 자동매핑(_autodiscover) 에서 docstring 첫 줄로 자동 추출된다.
"""
from typing import Optional, Any, Tuple
from datetime import datetime, timezone, timedelta
import os
import time
import logging

import httpx

CollectedResult = dict
logger = logging.getLogger(__name__)

# fallback 환경변수 — 사용자가 NewAssessment 에서 자격을 직접 입력하지 않은 경우 사용
DEFENDER_TENANT_ID     = os.environ.get("DEFENDER_TENANT_ID", "")
DEFENDER_CLIENT_ID     = os.environ.get("DEFENDER_CLIENT_ID", "")
DEFENDER_CLIENT_SECRET = os.environ.get("DEFENDER_CLIENT_SECRET", "")

API_BASE   = "https://api.securitycenter.microsoft.com/api"
LOGIN_BASE = "https://login.microsoftonline.com"
SCOPE      = "https://api.securitycenter.microsoft.com/.default"

# ─── session-scoped credential override ──────────────────────────────────────
_session_creds: Optional[dict] = None
_token_cache: Optional[dict] = None  # {"token": str, "expires_at": float}


def set_session_creds(creds: Optional[dict]) -> None:
    """세션 단위 Defender 자격을 모듈 전역에 주입. None 이면 해제 + 토큰 캐시 무효화."""
    global _session_creds, _token_cache
    _session_creds = creds or None
    _token_cache = None


def _tenant_id() -> str:
    if _session_creds and _session_creds.get("tenant_id"):
        return str(_session_creds["tenant_id"])
    return DEFENDER_TENANT_ID


def _client_id() -> str:
    if _session_creds and _session_creds.get("client_id"):
        return str(_session_creds["client_id"])
    return DEFENDER_CLIENT_ID


def _client_secret() -> str:
    if _session_creds and _session_creds.get("client_secret"):
        return str(_session_creds["client_secret"])
    return DEFENDER_CLIENT_SECRET


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
        "tool":         "defender",
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


def _get_access_token() -> Tuple[Optional[str], Optional[str]]:
    """Entra OAuth client_credentials 로 Defender API 토큰 발급. (token, error) 반환."""
    global _token_cache
    now = time.time()
    if _token_cache and _token_cache.get("expires_at", 0) > now + 60:
        return _token_cache["token"], None
    tenant = _tenant_id()
    cid = _client_id()
    cs = _client_secret()
    if not (tenant and cid and cs):
        return None, "Defender 인증 실패: tenant_id/client_id/client_secret 미설정"
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
    except Exception as exc:
        return None, f"Defender 토큰 요청 실패: {type(exc).__name__}: {exc}"
    if resp.status_code in (401, 403):
        return None, "Defender 인증 실패: client_id/client_secret/scope 확인 필요"
    if resp.status_code >= 400:
        return None, f"Defender 토큰 발급 오류: HTTP {resp.status_code}"
    try:
        data = resp.json()
    except Exception:
        return None, "Defender 토큰 응답 파싱 실패"
    tok = data.get("access_token")
    if not tok:
        return None, "Defender 토큰 응답에 access_token 없음"
    _token_cache = {
        "token":      tok,
        "expires_at": now + float(data.get("expires_in", 3600)),
    }
    return tok, None


def _df_get(path: str, params: dict = None, timeout: int = 30) -> Tuple[Optional[dict], Optional[str]]:
    """Defender API GET. (data, error) 튜플. data 가 None 이면 error 존재."""
    token, terr = _get_access_token()
    if terr:
        return None, terr
    try:
        resp = httpx.get(
            f"{API_BASE}{path}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            params=params or {},
            timeout=timeout,
        )
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    if resp.status_code == 401:
        return None, "Defender 권한 부족: 토큰 만료 또는 권한 없음"
    if resp.status_code == 403:
        return None, "Defender 권한 부족: WindowsDefenderATP scope 부족"
    if resp.status_code == 429:
        return None, "Defender rate limit"
    try:
        body = resp.json()
    except Exception:
        body = {}
    if resp.status_code >= 400:
        err_obj = (body.get("error") or {})
        msg = err_obj.get("message") or err_obj.get("code") or ""
        return None, f"Defender API 오류: HTTP {resp.status_code} {msg}".strip()
    return body, None


def _df_count(path: str, params: dict = None) -> Tuple[Optional[int], Optional[str], Any]:
    """OData: $count=true 우선, 없으면 value 길이로 카운트."""
    base_params = dict(params or {})
    # OData v4 에서 카운트만 받고 싶으면 $count=true + $top=0 권장
    base_params.setdefault("$top", 1)
    base_params["$count"] = "true"
    data, err = _df_get(path, base_params)
    if err:
        return None, err, data
    total = (data or {}).get("@odata.count")
    if total is None:
        total = len((data or {}).get("value") or [])
    return int(total), None, data


# ─────────────────────────── collectors (15) ───────────────────────────

def collect_endpoint_inventory(item_id: str, maturity: str) -> CollectedResult:
    """2.2.1.1_1: 단말 자산 인벤토리 (전체 machine ≥ 1 → 충족)"""
    MK, TH = "machine_total", 1.0
    total, err, _ = _df_count("/machines")
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"machine_total": total})


def collect_agent_registration(item_id: str, maturity: str) -> CollectedResult:
    """2.3.1.1_2: 에이전트 등록률 (Active machine / 전체 ≥ 0.9 → 충족, 0.7~ → 부분)"""
    MK, TH = "agent_active_ratio", 0.9
    total, err, _ = _df_count("/machines")
    if err:
        return _err(item_id, maturity, MK, TH, err)
    active, aerr, _ = _df_count("/machines", {"$filter": "healthStatus eq 'Active'"})
    if aerr:
        return _err(item_id, maturity, MK, TH, aerr)
    if not total:
        return _err(item_id, maturity, MK, TH, "등록된 machine(분모)가 0")
    ratio = (active or 0) / total
    if ratio >= TH:
        verdict = "충족"
    elif ratio >= 0.7:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, ratio, TH,
               {"active": active, "total": total})


def collect_edr_agents(item_id: str, maturity: str) -> CollectedResult:
    """2.3.1.2_2: 활성 EDR 에이전트 수 (Active machine ≥ 1 → 충족)"""
    MK, TH = "edr_active_agents", 1.0
    total, err, _ = _df_count("/machines", {"$filter": "healthStatus eq 'Active'"})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"active_agents": total})


def collect_policy_violation_alerts(item_id: str, maturity: str) -> CollectedResult:
    """2.1.1.2_2: 정책 위반 알림 (category eq 'PolicyViolation' ≥ 1 → 충족)"""
    MK, TH = "policy_violation_alerts", 1.0
    total, err, _ = _df_count("/alerts", {"$filter": "category eq 'PolicyViolation'"})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"policy_violation_alerts": total})


def collect_realtime_threat_alerts(item_id: str, maturity: str) -> CollectedResult:
    """4.4.1.1_2: 실시간 위협 알림 (severity=High + status=New ≥ 1 → 충족)"""
    MK, TH = "realtime_high_alerts", 1.0
    total, err, _ = _df_count(
        "/alerts",
        {"$filter": "severity eq 'High' and status eq 'New'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"realtime_high_alerts": total})


def collect_threat_detection_alerts(item_id: str, maturity: str) -> CollectedResult:
    """5.2.1.4_2: 위협 탐지 알림 (status=New 알림 ≥ 1 → 충족)"""
    MK, TH = "new_alerts", 1.0
    total, err, _ = _df_count("/alerts", {"$filter": "status eq 'New'"})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"new_alerts": total})


def collect_privilege_escalation_alerts(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.3_2: 권한 상승 탐지 (category eq 'PrivilegeEscalation' ≥ 1 → 충족)"""
    MK, TH = "privilege_escalation_alerts", 1.0
    total, err, _ = _df_count(
        "/alerts",
        {"$filter": "category eq 'PrivilegeEscalation'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"privilege_escalation_alerts": total})


def collect_lateral_movement_alerts(item_id: str, maturity: str) -> CollectedResult:
    """3.4.1.1_2: 측면 이동 탐지 (category eq 'LateralMovement' ≥ 1 → 충족)"""
    MK, TH = "lateral_movement_alerts", 1.0
    total, err, _ = _df_count(
        "/alerts",
        {"$filter": "category eq 'LateralMovement'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"lateral_movement_alerts": total})


def collect_malware_blocked(item_id: str, maturity: str) -> CollectedResult:
    """2.1.1.3_1: 악성코드 차단 (category eq 'Malware' ≥ 1 → 충족)"""
    MK, TH = "malware_alerts", 1.0
    total, err, _ = _df_count("/alerts", {"$filter": "category eq 'Malware'"})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"malware_alerts": total})


def collect_auto_block(item_id: str, maturity: str) -> CollectedResult:
    """2.2.1.4_1: 자동 차단/격리 액션 (Isolate machineAction ≥ 1 → 충족)"""
    MK, TH = "isolate_actions", 1.0
    total, err, _ = _df_count("/machineActions", {"$filter": "type eq 'Isolate'"})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"isolate_actions": total})


def collect_vuln_summary(item_id: str, maturity: str) -> CollectedResult:
    """5.5.2.2_1: 취약점 요약 (TVM vulnerability count ≥ 1 → 충족)"""
    MK, TH = "vulnerability_total", 1.0
    total, err, _ = _df_count("/vulnerabilities")
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"vulnerability_total": total})


def collect_critical_unfixed_vulns(item_id: str, maturity: str) -> CollectedResult:
    """5.5.1.3_1: 미패치 Critical 취약점 (Critical + exposedMachines>0 → 0건 충족)"""
    MK, TH = "critical_open_vulns", 0.0
    total, err, _ = _df_count(
        "/vulnerabilities",
        {"$filter": "severity eq 'Critical' and exposedMachines gt 0"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    count = total or 0
    if count == 0:
        verdict = "충족"
    elif count <= 10:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"critical_open_vulns": count})


def collect_realtime_monitoring(item_id: str, maturity: str) -> CollectedResult:
    """2.2.1.3_1: 실시간 모니터링 (최근 5분 내 lastSeen machine ≥ 1 → 충족)"""
    MK, TH = "recent_seen_machines", 1.0
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    total, err, _ = _df_count(
        "/machines",
        {"$filter": f"lastSeen gt {cutoff}"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"recent_seen_machines": total, "cutoff": cutoff})


def collect_active_response_auth(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.4_1: Live Response 액션(원격 대응 권한) ≥ 1 → 충족"""
    MK, TH = "live_response_actions", 1.0
    total, err, _ = _df_count(
        "/machineActions",
        {"$filter": "type eq 'LiveResponse'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"live_response_actions": total})


def collect_agent_keepalive(item_id: str, maturity: str) -> CollectedResult:
    """2.3.1.1_3: 에이전트 keepalive (Onboarded machine ≥ 1 → 충족)"""
    MK, TH = "onboarded_machines", 1.0
    total, err, _ = _df_count(
        "/machines",
        {"$filter": "onboardingStatus eq 'Onboarded'"},
    )
    if err:
        # 일부 테넌트는 onboardingStatus 미노출 → fallback: 전체 machine
        total2, err2, _ = _df_count("/machines")
        if err2:
            return _err(item_id, maturity, MK, TH, err)
        total = total2
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"onboarded_machines": total})
