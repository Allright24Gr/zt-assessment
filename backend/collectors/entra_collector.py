"""entra_collector.py — MS Entra ID(Azure AD) 진단 함수 (Phase A: 20개)

keycloak_collector.py와 동등한 추상을 가진 모듈. Microsoft Graph API를 사용한다.
인증: OAuth 2.0 client credentials flow.

item_id 체계: {항목번호}.{성숙도번호}_{질문번호} — keycloak과 동일하므로 dispatcher
자동매핑(_autodiscover)에서 docstring 첫 줄로 자동 추출된다.
"""
from typing import Optional, Any, Tuple
from datetime import datetime, timezone
import os
import time
import logging

import httpx

CollectedResult = dict
logger = logging.getLogger(__name__)

# fallback 환경변수 — 사용자가 NewAssessment에서 자격을 직접 입력하지 않은 경우 사용
ENTRA_TENANT_ID     = os.environ.get("ENTRA_TENANT_ID", "")
ENTRA_CLIENT_ID     = os.environ.get("ENTRA_CLIENT_ID", "")
ENTRA_CLIENT_SECRET = os.environ.get("ENTRA_CLIENT_SECRET", "")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
LOGIN_BASE = "https://login.microsoftonline.com"

# ─── session-scoped credential override ──────────────────────────────────────
# 사용자가 NewAssessment에서 입력한 IdP 자격을 _run_collectors에서 주입한다.
_session_creds: Optional[dict] = None
_token_cache: Optional[dict] = None  # {"token": str, "expires_at": float}


def set_session_creds(creds: Optional[dict]) -> None:
    """세션 단위 Entra 자격을 모듈 전역에 주입. None 이면 해제 + 토큰 캐시 무효화."""
    global _session_creds, _token_cache
    _session_creds = creds or None
    _token_cache = None


def _tenant_id() -> str:
    if _session_creds and _session_creds.get("tenant_id"):
        return str(_session_creds["tenant_id"])
    return ENTRA_TENANT_ID


def _client_id() -> str:
    if _session_creds and _session_creds.get("client_id"):
        return str(_session_creds["client_id"])
    return ENTRA_CLIENT_ID


def _client_secret() -> str:
    if _session_creds and _session_creds.get("client_secret"):
        return str(_session_creds["client_secret"])
    return ENTRA_CLIENT_SECRET


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
        "tool":         "entra",
        "result":       result,
        "metric_key":   metric_key,
        "metric_value": float(metric_value),
        "threshold":    float(threshold),
        "raw_json":     raw_json,
        "collected_at": _now_iso(),
        "error":        error,
    }


def _ok(
    item_id: str,
    maturity: str,
    result: str,
    metric_key: str,
    metric_value: float,
    threshold: float,
    raw_json: dict,
) -> CollectedResult:
    return _make_result(item_id, maturity, metric_key, metric_value, threshold, result, raw_json or {}, None)


def _err(
    item_id: str,
    maturity: str,
    metric_key: str,
    threshold: float,
    error_msg: str,
    raw_json: dict = None,
) -> CollectedResult:
    return _make_result(item_id, maturity, metric_key, 0.0, threshold, "평가불가", raw_json or {}, error_msg)


def _unavailable(
    item_id: str,
    maturity: str,
    metric_key: str,
    threshold: float,
    error_msg: str,
    raw_json: dict = None,
) -> CollectedResult:
    """keycloak_collector와 동일 시그니처의 별칭(향후 통일성용)."""
    return _err(item_id, maturity, metric_key, threshold, error_msg, raw_json)


def _get_access_token() -> Optional[str]:
    """Client credentials flow로 액세스 토큰 발급. 캐싱 60s 마진."""
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
                "scope":         "https://graph.microsoft.com/.default",
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
        logger.warning("[entra] token fetch failed: %s", exc)
        return None


def _graph_get(path: str, params: dict = None, timeout: int = 30) -> Tuple[Optional[dict], Optional[str]]:
    """Graph API GET. (data, error) 튜플 반환. data is None 이면 error 가 있음."""
    token = _get_access_token()
    if not token:
        return None, "Entra 인증 실패: tenant_id/client_id/client_secret 확인 필요"
    try:
        resp = httpx.get(
            f"{GRAPH_BASE}{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=params or {},
            timeout=timeout,
        )
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"

    if resp.status_code == 401:
        return None, "Entra 권한 부족: 토큰 만료 또는 권한 없음"
    if resp.status_code == 403:
        return None, "Entra 권한 부족: Authorization_RequestDenied"
    try:
        body = resp.json()
    except Exception:
        body = {}
    if 400 <= resp.status_code:
        err = (body.get("error") or {}).get("message") or f"HTTP {resp.status_code}"
        return None, f"Entra API 오류: {err}"
    return body, None


def _graph_count(path: str) -> Tuple[Optional[int], Optional[str], Any]:
    """Graph API endpoint 호출 후 value 길이를 카운트. (count, error, raw) 튜플."""
    data, err = _graph_get(path)
    if err:
        return None, err, data
    values = (data or {}).get("value") or []
    return len(values), None, data


# ─────────────────────────── collectors (20) ───────────────────────────

def collect_user_role_ratio(item_id: str, maturity: str) -> CollectedResult:
    """1.1.1.2_1: 역할 부여 비율 ≥ 95% → 충족 / 80~95% → 부분충족 / 미만 → 미충족"""
    MK, TH = "user_role_ratio", 0.95
    users_data, err = _graph_get("/users", {"$select": "id", "$top": 999})
    if err:
        return _err(item_id, maturity, MK, TH, err, users_data or {})
    users = (users_data or {}).get("value") or []
    if not users:
        return _err(item_id, maturity, MK, TH, "활성 사용자(분모)가 0", users_data)

    roles_data, rerr = _graph_get("/directoryRoles")
    if rerr:
        return _err(item_id, maturity, MK, TH, rerr, roles_data or {})
    roles = (roles_data or {}).get("value") or []

    user_ids_with_role: set = set()
    for r in roles:
        rid = r.get("id")
        if not rid:
            continue
        mdata, _merr = _graph_get(f"/directoryRoles/{rid}/members", {"$select": "id"})
        for m in ((mdata or {}).get("value") or []):
            if m.get("id"):
                user_ids_with_role.add(m["id"])

    total = len(users)
    with_role = sum(1 for u in users if u.get("id") in user_ids_with_role)
    ratio = with_role / total if total else 0.0
    if ratio >= TH:
        verdict = "충족"
    elif ratio >= 0.8:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, ratio, TH,
               {"total_users": total, "with_role": with_role, "roles_inspected": len(roles)})


def collect_idp_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.1.1.3_1: tenant 본체가 IdP — /organization 조회 OK면 충족"""
    MK, TH = "idp_tenant_ok", 1.0
    data, err = _graph_get("/organization")
    if err:
        return _err(item_id, maturity, MK, TH, err, data or {})
    orgs = (data or {}).get("value") or []
    count = len(orgs)
    verdict = "충족" if count >= 1 else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"organization_count": count})


def collect_idp_registered(item_id: str, maturity: str) -> CollectedResult:
    """1.1.2.1_1: tenant_id 존재 → 충족 / 없음 → 미충족"""
    MK, TH = "idp_tenant_registered", 1.0
    tenant = _tenant_id()
    if tenant:
        return _ok(item_id, maturity, "충족", MK, 1.0, TH, {"tenant_id_set": True})
    return _ok(item_id, maturity, "미충족", MK, 0.0, TH, {"tenant_id_set": False})


def collect_active_idp_multi(item_id: str, maturity: str) -> CollectedResult:
    """1.1.2.2_1: 외부 federation/IdP ≥ 2 → 충족 / 1 → 부분충족 / 0 → 미충족"""
    MK, TH = "active_idp_count", 2.0
    # /identity/identityProviders 가 신형 SocialIdentityProvider 엔드포인트
    data, err = _graph_get("/identity/identityProviders")
    if err:
        return _err(item_id, maturity, MK, TH, err, data or {})
    count = len((data or {}).get("value") or [])
    if count >= TH:
        verdict = "충족"
    elif count == 1:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH, {"idp_count": count})


def collect_mfa_required(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.1_1: MFA require 정책 ≥ 1 → 충족"""
    MK, TH = "mfa_require_policies", 1.0
    data, err = _graph_get(
        "/identity/conditionalAccess/policies",
        {"$filter": "state eq 'enabled'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err, data or {})
    policies = (data or {}).get("value") or []
    count = 0
    for p in policies:
        gc = p.get("grantControls") or {}
        builtins = [str(x).lower() for x in (gc.get("builtInControls") or [])]
        if "mfa" in builtins:
            count += 1
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"mfa_require_policies": count, "total_enabled_policies": len(policies)})


def collect_otp_flow(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.2_1: microsoftAuthenticator/softwareOath 활성 ≥ 1 → 충족"""
    MK, TH = "otp_method_count", 1.0
    data, err = _graph_get("/policies/authenticationMethodsPolicy")
    if err:
        return _err(item_id, maturity, MK, TH, err, data or {})
    methods = ((data or {}).get("authenticationMethodConfigurations") or [])
    targets = {"microsoftauthenticator", "softwareoath"}
    count = 0
    for m in methods:
        mid = str(m.get("id") or "").lower()
        state = str(m.get("state") or "").lower()
        if mid in targets and state == "enabled":
            count += 1
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"otp_methods_enabled": count})


def collect_webauthn_status(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.2_2: fido2 인증 메서드 활성 → 충족"""
    MK, TH = "fido2_enabled", 1.0
    data, err = _graph_get("/policies/authenticationMethodsPolicy")
    if err:
        return _err(item_id, maturity, MK, TH, err, data or {})
    methods = ((data or {}).get("authenticationMethodConfigurations") or [])
    enabled = 0
    for m in methods:
        if str(m.get("id") or "").lower() == "fido2":
            if str(m.get("state") or "").lower() == "enabled":
                enabled += 1
    verdict = "충족" if enabled >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(enabled), TH,
               {"fido2_enabled_count": enabled})


def collect_conditional_auth(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.3_1: 활성 Conditional Access 정책 ≥ 1 → 충족"""
    MK, TH = "ca_active_policies", 1.0
    data, err = _graph_get(
        "/identity/conditionalAccess/policies",
        {"$filter": "state eq 'enabled'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err, data or {})
    count = len((data or {}).get("value") or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"active_ca_policies": count})


def collect_session_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.2.2.1_1: 세션 컨트롤(sign-in frequency 등) 포함 정책 ≥ 1 → 충족"""
    MK, TH = "session_control_policies", 1.0
    data, err = _graph_get(
        "/identity/conditionalAccess/policies",
        {"$filter": "state eq 'enabled'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err, data or {})
    policies = (data or {}).get("value") or []
    count = 0
    for p in policies:
        sc = p.get("sessionControls") or {}
        # signInFrequency / persistentBrowser / cloudAppSecurity 중 하나라도 설정되면 카운트
        if any(sc.get(k) for k in ("signInFrequency", "persistentBrowser", "cloudAppSecurity")):
            count += 1
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"session_control_policies": count, "total_enabled_policies": len(policies)})


def collect_stepup_auth(item_id: str, maturity: str) -> CollectedResult:
    """1.2.2.2_1: authenticationStrength 지정 CA 정책 ≥ 1 → 충족"""
    MK, TH = "stepup_strength_policies", 1.0
    data, err = _graph_get(
        "/identity/conditionalAccess/policies",
        {"$filter": "state eq 'enabled'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err, data or {})
    policies = (data or {}).get("value") or []
    count = 0
    for p in policies:
        gc = p.get("grantControls") or {}
        if gc.get("authenticationStrength"):
            count += 1
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"stepup_strength_policies": count})


def collect_realm_count(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1.1_1: Entra는 tenant 단일 → /organization 조회 OK면 충족(=1)"""
    MK, TH = "realm_count", 1.0
    data, err = _graph_get("/organization")
    if err:
        return _err(item_id, maturity, MK, TH, err, data or {})
    count = len((data or {}).get("value") or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"realm_count": count, "note": "Entra tenant 단일 모델"})


def collect_icam_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1.2_1: 앱 등록 수(applications) ≥ 1 → 충족"""
    MK, TH = "application_count", 1.0
    count, err, raw = _graph_count("/applications")
    if err:
        return _err(item_id, maturity, MK, TH, err, raw or {})
    verdict = "충족" if (count or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count or 0), TH,
               {"application_count": count})


def collect_webauthn_users(item_id: str, maturity: str) -> CollectedResult:
    """1.3.2.2_1: FIDO2 등록 사용자 ≥ 1 → 충족 (불가 시 reports/credentialUserRegistrationDetails)"""
    MK, TH = "fido2_registered_users", 1.0
    # 신형 엔드포인트: /reports/authenticationMethods/userRegistrationDetails
    data, err = _graph_get(
        "/reports/authenticationMethods/userRegistrationDetails",
        {"$filter": "methodsRegistered/any(m:m eq 'fido2SecurityKey')", "$top": 999},
    )
    if err:
        # fallback: 구버전 credentialUserRegistrationDetails
        data2, err2 = _graph_get("/reports/credentialUserRegistrationDetails")
        if err2:
            return _err(item_id, maturity, MK, TH, err, data or {})
        users = (data2 or {}).get("value") or []
        # authMethods 에 'fido' 포함 사용자 카운트
        count = sum(
            1 for u in users
            if any("fido" in str(m).lower() for m in (u.get("authMethods") or []))
        )
        verdict = "충족" if count >= TH else "미충족"
        return _ok(item_id, maturity, verdict, MK, float(count), TH,
                   {"fido2_users": count, "source": "credentialUserRegistrationDetails"})
    users = (data or {}).get("value") or []
    count = len(users)
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"fido2_users": count, "source": "userRegistrationDetails"})


def collect_authz_clients(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.1_3: applications + servicePrincipals 합 ≥ 1 → 충족"""
    MK, TH = "authz_client_count", 1.0
    app_count, aerr, _ = _graph_count("/applications")
    sp_count, sperr, _ = _graph_count("/servicePrincipals")
    if aerr and sperr:
        return _err(item_id, maturity, MK, TH, f"applications: {aerr}; servicePrincipals: {sperr}", {})
    total = (app_count or 0) + (sp_count or 0)
    verdict = "충족" if total >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total), TH,
               {"applications": app_count, "servicePrincipals": sp_count})


def collect_rbac_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.2_1: 활성 directoryRoles ≥ 1 → 충족"""
    MK, TH = "active_directory_roles", 1.0
    count, err, _ = _graph_count("/directoryRoles")
    if err:
        return _err(item_id, maturity, MK, TH, err, {})
    verdict = "충족" if (count or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count or 0), TH,
               {"directory_role_count": count})


def collect_aggregate_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.3_2: 여러 grant control 조합 CA 정책 ≥ 1 → 충족 / 단일 → 부분충족"""
    MK, TH = "aggregate_grant_policies", 1.0
    data, err = _graph_get(
        "/identity/conditionalAccess/policies",
        {"$filter": "state eq 'enabled'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err, data or {})
    policies = (data or {}).get("value") or []
    agg = 0
    single = 0
    for p in policies:
        gc = p.get("grantControls") or {}
        builtins = gc.get("builtInControls") or []
        # 조합 조건: builtInControls 2개 이상 OR builtInControls + authenticationStrength
        controls_count = len(builtins)
        if gc.get("authenticationStrength"):
            controls_count += 1
        if controls_count >= 2:
            agg += 1
        elif controls_count == 1:
            single += 1
    if agg >= TH:
        verdict = "충족"
    elif single >= 1:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, float(agg), TH,
               {"aggregate_count": agg, "single_count": single})


def collect_resource_permission(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.3_3: 앱의 requiredResourceAccess 항목 ≥ 1 → 충족"""
    MK, TH = "resource_permission_count", 1.0
    data, err = _graph_get("/applications", {"$select": "id,requiredResourceAccess", "$top": 999})
    if err:
        return _err(item_id, maturity, MK, TH, err, data or {})
    apps = (data or {}).get("value") or []
    total_perms = 0
    for a in apps:
        for rra in (a.get("requiredResourceAccess") or []):
            total_perms += len(rra.get("resourceAccess") or [])
    verdict = "충족" if total_perms >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total_perms), TH,
               {"resource_permission_count": total_perms, "applications": len(apps)})


def collect_password_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.2_1: 패스워드 메서드 정책 활성 → 충족"""
    MK, TH = "password_policy_set", 1.0
    data, err = _graph_get("/policies/authenticationMethodsPolicy")
    if err:
        return _err(item_id, maturity, MK, TH, err, data or {})
    methods = ((data or {}).get("authenticationMethodConfigurations") or [])
    has_password = False
    for m in methods:
        if str(m.get("id") or "").lower() == "password":
            # password 메서드가 정책에 포함되어 있으면 정책이 명시적으로 관리되는 것으로 간주
            has_password = True
            break
    value = 1.0 if has_password else 0.0
    verdict = "충족" if has_password else "미충족"
    return _ok(item_id, maturity, verdict, MK, value, TH,
               {"password_method_configured": has_password})


def collect_central_authz_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.2_1: 활성 CA 정책 ≥ 1 → 충족 (중앙 집중 인가 정책)"""
    MK, TH = "central_ca_policies", 1.0
    data, err = _graph_get(
        "/identity/conditionalAccess/policies",
        {"$filter": "state eq 'enabled'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err, data or {})
    count = len((data or {}).get("value") or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"central_ca_policies": count})


def collect_abac_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.3_1: 속성 기반(users/group/risk) 조건 CA 정책 ≥ 1 → 충족"""
    MK, TH = "abac_ca_policies", 1.0
    data, err = _graph_get(
        "/identity/conditionalAccess/policies",
        {"$filter": "state eq 'enabled'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err, data or {})
    policies = (data or {}).get("value") or []
    count = 0
    for p in policies:
        conds = p.get("conditions") or {}
        users = conds.get("users") or {}
        # 속성 기반: user/group 지정 또는 signInRiskLevels/userRiskLevels 사용
        if (users.get("includeGroups") or users.get("excludeGroups")
                or users.get("includeRoles") or users.get("excludeRoles")
                or conds.get("signInRiskLevels")
                or conds.get("userRiskLevels")):
            count += 1
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"abac_ca_policies": count, "total_enabled_policies": len(policies)})
