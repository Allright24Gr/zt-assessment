"""zscaler_collector.py — Zscaler Internet Access (ZIA) 진단 함수 (Phase A: 10개)

entra_collector.py / crowdstrike_collector.py 와 동일한 추상을 가진 ZTNA 모듈.
Zscaler OneAPI(OAuth2 client_credentials) 를 우선 사용한다.

인증:
    POST {api_base}/oauth2/v1/token (application/x-www-form-urlencoded)
    body: grant_type=client_credentials&client_id=<k>&client_secret=<s>
          [&audience=<aud>]
    응답: {"access_token": "...", "expires_in": 3600}
    이후 Authorization: Bearer <token>

item_id 체계: {항목번호}.{성숙도번호}_{질문번호} — 다른 collector 와 동일하므로
dispatcher 자동매핑(_autodiscover) 에서 docstring 첫 줄로 자동 추출된다.
"""
from typing import Optional, Any, Tuple
from datetime import datetime, timezone
import os
import time
import logging

import httpx

CollectedResult = dict
logger = logging.getLogger(__name__)

# fallback 환경변수 — 사용자가 NewAssessment 에서 자격을 직접 입력하지 않은 경우 사용
ZSCALER_API_BASE      = os.environ.get("ZSCALER_API_BASE", "")
ZSCALER_CLIENT_ID     = os.environ.get("ZSCALER_CLIENT_ID", "")
ZSCALER_CLIENT_SECRET = os.environ.get("ZSCALER_CLIENT_SECRET", "")
ZSCALER_CUSTOMER_ID   = os.environ.get("ZSCALER_CUSTOMER_ID", "")

# ─── session-scoped credential override ──────────────────────────────────────
_session_creds: Optional[dict] = None
_token_cache: Optional[dict] = None  # {"token": str, "expires_at": float}


def set_session_creds(creds: Optional[dict]) -> None:
    """세션 단위 Zscaler 자격을 모듈 전역에 주입. None 이면 해제 + 토큰 캐시 무효화."""
    global _session_creds, _token_cache
    _session_creds = creds or None
    _token_cache = None


def _api_base() -> str:
    if _session_creds and _session_creds.get("api_base"):
        return str(_session_creds["api_base"]).rstrip("/")
    return (ZSCALER_API_BASE or "").rstrip("/")


def _client_id() -> str:
    if _session_creds and _session_creds.get("client_id"):
        return str(_session_creds["client_id"])
    return ZSCALER_CLIENT_ID


def _client_secret() -> str:
    if _session_creds and _session_creds.get("client_secret"):
        return str(_session_creds["client_secret"])
    return ZSCALER_CLIENT_SECRET


def _customer_id() -> str:
    if _session_creds and _session_creds.get("customer_id"):
        return str(_session_creds["customer_id"])
    return ZSCALER_CUSTOMER_ID


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
        "tool":         "zscaler",
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


def _get_access_token() -> Optional[str]:
    """Zscaler OneAPI OAuth2 client_credentials flow. 60s 마진 캐시."""
    global _token_cache
    now = time.time()
    if _token_cache and _token_cache.get("expires_at", 0) > now + 60:
        return _token_cache["token"]
    base = _api_base()
    cid = _client_id()
    cs = _client_secret()
    if not (base and cid and cs):
        return None
    body = {
        "grant_type":    "client_credentials",
        "client_id":     cid,
        "client_secret": cs,
    }
    # audience 는 OneAPI 의 경우 https://api.zscaler.com 등으로 지정 가능 — customer_id 가 있으면 함께 전달
    if _customer_id():
        body["audience"] = "https://api.zscaler.com"
    try:
        resp = httpx.post(
            f"{base}/oauth2/v1/token",
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
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
        logger.warning("[zscaler] token fetch failed: %s", exc)
        return None


def _zia_get(path: str, params: dict = None, timeout: int = 30) -> Tuple[Optional[Any], Optional[str]]:
    """ZIA API GET. (data, error) 튜플 반환. data is None 이면 error 가 있음."""
    token = _get_access_token()
    if not token:
        return None, "Zscaler 인증 실패: api_base/client_id/client_secret 확인 필요"
    base = _api_base()
    try:
        resp = httpx.get(
            f"{base}{path}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept":        "application/json",
            },
            params=params or {},
            timeout=timeout,
        )
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"

    if resp.status_code == 401:
        return None, "Zscaler 권한 부족: 토큰 만료 또는 권한 없음"
    if resp.status_code == 403:
        return None, "Zscaler 권한 부족: API client 권한 확인 필요"
    if resp.status_code == 404:
        return None, f"Zscaler 엔드포인트 미지원: {path}"
    try:
        body = resp.json()
    except Exception:
        body = None
    if 400 <= resp.status_code:
        msg = ""
        if isinstance(body, dict):
            msg = body.get("message") or body.get("error") or ""
        return None, f"Zscaler API 오류: {msg or f'HTTP {resp.status_code}'}"
    return body, None


def _zia_count(path: str, params: dict = None) -> Tuple[Optional[int], Optional[str], Any]:
    """ZIA endpoint 호출 후 list 길이 카운트. (count, error, raw) 튜플."""
    data, err = _zia_get(path, params)
    if err:
        return None, err, data
    if isinstance(data, list):
        return len(data), None, data
    if isinstance(data, dict):
        for k in ("list", "data", "items", "value"):
            if isinstance(data.get(k), list):
                return len(data[k]), None, data
        # dict 자체가 단일 객체면 1로 간주
        return 1, None, data
    return 0, None, data


# ─────────────────────────── collectors (10) ───────────────────────────

def collect_subnet_topology(item_id: str, maturity: str) -> CollectedResult:
    """3.1.1.1_1: 등록된 network service ≥ 1 → 충족 (서브넷·토폴로지 가시화)"""
    MK, TH = "network_service_count", 1.0
    count, err, raw = _zia_count("/api/v1/networkServices")
    if err:
        return _err(item_id, maturity, MK, TH, err, raw if isinstance(raw, dict) else {"raw": raw})
    verdict = "충족" if (count or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count or 0), TH,
               {"network_service_count": count})


def collect_micro_segment_ports(item_id: str, maturity: str) -> CollectedResult:
    """3.1.2.1_1: URL filtering 기반 마이크로 세그먼트 정책 ≥ 1 → 충족"""
    MK, TH = "micro_segment_policy_count", 1.0
    # URL filtering policies = 자원 단위로 분리된 마이크로 세그먼트와 가장 가까운 ZIA 개념
    count, err, raw = _zia_count("/api/v1/urlFilteringRules")
    if err:
        # fallback: networkServices 의 정책 카운트
        count, err2, raw = _zia_count("/api/v1/networkServices", {"policyType": "urlFiltering"})
        if err2:
            return _err(item_id, maturity, MK, TH, err, raw if isinstance(raw, dict) else {"raw": raw})
    verdict = "충족" if (count or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count or 0), TH,
               {"micro_segment_policy_count": count})


def collect_tls_ratio(item_id: str, maturity: str) -> CollectedResult:
    """3.3.1.1_1: SSL inspection 룰 중 활성 비율 ≥ 80% → 충족 / 50~80% → 부분충족"""
    MK, TH = "ssl_inspection_active_ratio", 0.8
    data, err = _zia_get("/api/v1/sslInspectionRules")
    if err:
        return _err(item_id, maturity, MK, TH, err, {})
    rules = data if isinstance(data, list) else ((data or {}).get("list") or [])
    total = len(rules)
    if total == 0:
        return _ok(item_id, maturity, "미충족", MK, 0.0, TH,
                   {"total_rules": 0, "active_rules": 0})
    active = 0
    for r in rules:
        state = str(r.get("state") or r.get("status") or "").upper()
        # ZIA 룰 활성 표기는 "ENABLED" 또는 boolean enabled 필드
        if state == "ENABLED" or r.get("enabled") is True:
            active += 1
    ratio = active / total
    if ratio >= TH:
        verdict = "충족"
    elif ratio >= 0.5:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, ratio, TH,
               {"total_rules": total, "active_rules": active})


def collect_tls_services(item_id: str, maturity: str) -> CollectedResult:
    """3.3.1.1_2: SSL inspection 적용 서비스(룰) 수 ≥ 1 → 충족"""
    MK, TH = "ssl_inspection_service_count", 1.0
    count, err, raw = _zia_count("/api/v1/sslInspectionRules")
    if err:
        return _err(item_id, maturity, MK, TH, err, raw if isinstance(raw, dict) else {"raw": raw})
    verdict = "충족" if (count or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count or 0), TH,
               {"ssl_inspection_service_count": count})


def collect_subnet_segmentation(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.1_1: 분류된 URL 카테고리 ≥ 5 → 충족 (자원 단위 세그먼테이션)"""
    MK, TH = "url_category_count", 5.0
    count, err, raw = _zia_count("/api/v1/urlCategories")
    if err:
        return _err(item_id, maturity, MK, TH, err, raw if isinstance(raw, dict) else {"raw": raw})
    n = float(count or 0)
    if n >= TH:
        verdict = "충족"
    elif n >= 1:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, n, TH,
               {"url_category_count": count})


def collect_perimeter_model(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.1_2: 활성 firewall filtering rule ≥ 1 → 충족 (퍼리미터리스 ZTNA 게이트웨이)"""
    MK, TH = "firewall_filtering_rules", 1.0
    data, err = _zia_get("/api/v1/firewallFilteringRules")
    if err:
        return _err(item_id, maturity, MK, TH, err, {})
    rules = data if isinstance(data, list) else ((data or {}).get("list") or [])
    active = 0
    for r in rules:
        state = str(r.get("state") or "").upper()
        if state == "ENABLED" or r.get("enabled") is True:
            active += 1
    verdict = "충족" if active >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(active), TH,
               {"firewall_rule_total": len(rules), "firewall_rule_active": active})


def collect_dlp_alerts(item_id: str, maturity: str) -> CollectedResult:
    """5.1.1.4_1: DLP dictionary ≥ 1 → 충족 (DLP 룰 운영 중)"""
    MK, TH = "dlp_dictionary_count", 1.0
    count, err, raw = _zia_count("/api/v1/dlpDictionaries")
    if err:
        return _err(item_id, maturity, MK, TH, err, raw if isinstance(raw, dict) else {"raw": raw})
    verdict = "충족" if (count or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count or 0), TH,
               {"dlp_dictionary_count": count})


def collect_ids_alerts(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.3_2: Advanced threat 정책 ≥ 1 → 충족 (IDS/IPS 운영)"""
    MK, TH = "advanced_threat_policy_count", 1.0
    # advancedThreatSettings 단건 객체 또는 advancedThreatPolicy 리스트
    data, err = _zia_get("/api/v1/advancedThreatSettings")
    if err:
        # fallback: cloudFirewallIPSRules
        count, err2, raw = _zia_count("/api/v1/cloudFirewallIPSRules")
        if err2:
            return _err(item_id, maturity, MK, TH, err, {})
        verdict = "충족" if (count or 0) >= TH else "미충족"
        return _ok(item_id, maturity, verdict, MK, float(count or 0), TH,
                   {"advanced_threat_policy_count": count, "source": "cloudFirewallIPSRules"})
    # advancedThreatSettings 가 dict 면 1개 정책 운영으로 간주
    has_policy = bool(data)
    verdict = "충족" if has_policy else "미충족"
    return _ok(item_id, maturity, verdict, MK, 1.0 if has_policy else 0.0, TH,
               {"advanced_threat_settings_set": has_policy, "source": "advancedThreatSettings"})


def collect_conditional_auth(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.3_1: SAML SSO + 인증 프로파일 정책 ≥ 1 → 충족 (조건부 인증)"""
    MK, TH = "conditional_auth_count", 1.0
    # SAML 설정 단건
    saml_data, saml_err = _zia_get("/api/v1/samlSettings")
    if saml_err:
        # fallback: 사용자 인증 설정
        auth_data, auth_err = _zia_get("/api/v1/authSettings")
        if auth_err:
            return _err(item_id, maturity, MK, TH, saml_err, {})
        has = bool(auth_data)
        verdict = "충족" if has else "미충족"
        return _ok(item_id, maturity, verdict, MK, 1.0 if has else 0.0, TH,
                   {"auth_settings_set": has, "source": "authSettings"})
    # samlSettings 존재 + 활성 여부 확인
    enabled = False
    if isinstance(saml_data, dict):
        # ZIA samlSettings: enableSAMLAutoProvisioning 등 토글들
        for k in ("enableSAMLAutoProvisioning", "samlEnabled", "enabled"):
            if saml_data.get(k):
                enabled = True
                break
        # 토글이 없어도 idpUrl 등이 설정되어 있으면 활성으로 간주
        if not enabled and (saml_data.get("idpUrl") or saml_data.get("ssoUrl")):
            enabled = True
    verdict = "충족" if enabled else "미충족"
    return _ok(item_id, maturity, verdict, MK, 1.0 if enabled else 0.0, TH,
               {"saml_enabled": enabled, "source": "samlSettings"})


def collect_central_authz_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.2_1: Cloud Application Control 정책 ≥ 1 → 충족 (중앙화 인가 정책)"""
    MK, TH = "central_authz_policy_count", 1.0
    count, err, raw = _zia_count("/api/v1/webApplicationRules")
    if err:
        # fallback: cloudApplicationPolicy 단일
        count, err2, raw = _zia_count("/api/v1/cloudApplicationPolicy")
        if err2:
            # 마지막 fallback: urlFilteringRules
            count, err3, raw = _zia_count("/api/v1/urlFilteringRules")
            if err3:
                return _err(item_id, maturity, MK, TH, err, raw if isinstance(raw, dict) else {"raw": raw})
    verdict = "충족" if (count or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count or 0), TH,
               {"central_authz_policy_count": count})


# === ASSESSMENT.PY 통합 가이드 (후속 통합 작업자용) ===
# ALL_TOOLS += ("zscaler",)
# 새 카테고리: _ZTNA_TOOL_OF / _ZTNA_AUTO_TOOLS → ProfileSelect.ztna_type
# AssessmentRunRequest.zscaler_creds: ZscalerCreds(api_base, client_id, client_secret, customer_id?)
# _mask_creds: zscaler_creds.client_secret → "***"
# _run_collectors: zscaler_collector.set_session_creds({...}) 호출
# _autodiscover: 본 모듈 import 추가 → docstring 첫 줄 X.X.X.X_N 로 자동 매핑됨
# _tool_health / _tool_configured: api_base + client_id + client_secret 모두 비면 unavailable
