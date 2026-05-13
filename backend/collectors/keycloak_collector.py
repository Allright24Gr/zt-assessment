"""keycloak_collector.py — 65개 진단 함수 (item_id 체계: {항목번호}.{성숙도번호}_{질문번호})"""
from typing import Optional, List, Any
from datetime import datetime, timezone
import os
import time
import requests

CollectedResult = dict

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "master")
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "admin-cli")
KEYCLOAK_ADMIN_USER = os.environ.get("KEYCLOAK_ADMIN_USER", "")
KEYCLOAK_ADMIN_PASS = os.environ.get("KEYCLOAK_ADMIN_PASS", "")

_SYSTEM_ROLES = frozenset({"offline_access", "uma_authorization"})
_token_cache: dict = {"token": None, "expires_at": 0.0}


# ─────────────────────────── internal helpers ───────────────────────────

def _get_admin_token() -> str:
    """Return cached token; re-issue when within 30s of expiry."""
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires_at"] - 30:
        return _token_cache["token"]
    url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    resp = requests.post(
        url,
        data={
            "grant_type": "password",
            "client_id": KEYCLOAK_CLIENT_ID,
            "username": KEYCLOAK_ADMIN_USER,
            "password": KEYCLOAK_ADMIN_PASS,
        },
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    _token_cache["token"] = data["access_token"]
    _token_cache["expires_at"] = now + data.get("expires_in", 300)
    return _token_cache["token"]


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
        "item_id": item_id,
        "maturity": maturity,
        "tool": "keycloak",
        "result": result,
        "metric_key": metric_key,
        "metric_value": float(metric_value),
        "threshold": float(threshold),
        "raw_json": raw_json,
        "collected_at": _now_iso(),
        "error": error,
    }


def _unavailable(
    item_id: str,
    maturity: str,
    metric_key: str,
    threshold: float,
    error_msg: str,
    raw_json: dict = None,
) -> CollectedResult:
    return _make_result(
        item_id, maturity, metric_key, 0.0, threshold, "평가불가", raw_json or {}, error_msg
    )


def _kc_get(path: str, params: dict = None, token: str = None) -> Any:
    """GET with 401 token-refresh (1 retry) and 5xx (3 retries), 10s timeout."""
    url = f"{KEYCLOAK_URL}{path}"
    current_token = token
    token_refreshed = False
    server_errors = 0

    while True:
        headers = {"Authorization": f"Bearer {current_token}"}
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=10)
        except requests.exceptions.Timeout:
            raise TimeoutError(f"Timeout: {url}")
        except requests.exceptions.ConnectionError as exc:
            raise ConnectionError(f"Connection failed: {url}: {exc}")

        if resp.status_code == 401 and not token_refreshed:
            _token_cache["token"] = None
            _token_cache["expires_at"] = 0.0
            current_token = _get_admin_token()
            token_refreshed = True
            continue

        if 500 <= resp.status_code < 600:
            server_errors += 1
            if server_errors < 4:
                time.sleep(1)
                continue
            raise RuntimeError(f"Server error {resp.status_code} after 3 retries: {url}")

        resp.raise_for_status()
        return resp.json()


def _get_all_users(token: str, realm: str = None) -> List[dict]:
    if realm is None:
        realm = KEYCLOAK_REALM
    users: List[dict] = []
    first = 0
    while True:
        page = _kc_get(
            f"/admin/realms/{realm}/users",
            params={"briefRepresentation": "false", "first": first, "max": 100},
            token=token,
        )
        if not page:
            break
        users.extend(page)
        if len(page) < 100:
            break
        first += 100
    return users


def _active_human_users(users: List[dict]) -> List[dict]:
    return [u for u in users if u.get("enabled") and not u.get("serviceAccountClientId")]


def _is_default_role(name: str) -> bool:
    return name.startswith("default-roles-") or name in _SYSTEM_ROLES


def _flows_with_executions(token: str, realm: str = None) -> List[dict]:
    if realm is None:
        realm = KEYCLOAK_REALM
    flows = _kc_get(f"/admin/realms/{realm}/authentication/flows", token=token)
    result = []
    for flow in flows:
        fid = flow.get("id")
        try:
            execs = _kc_get(
                f"/admin/realms/{realm}/authentication/flows/{fid}/executions",
                token=token,
            )
        except Exception:
            execs = []
        result.append({"flow": flow, "executions": execs or []})
    return result


def _get_authz_clients(token: str, realm: str = None) -> List[dict]:
    if realm is None:
        realm = KEYCLOAK_REALM
    clients = _kc_get(f"/admin/realms/{realm}/clients", token=token)
    return [c for c in clients if c.get("authorizationServicesEnabled") and c.get("enabled")]


def _get_all_authz_policies(token: str, realm: str = None) -> List[dict]:
    if realm is None:
        realm = KEYCLOAK_REALM
    authz_clients = _get_authz_clients(token, realm)
    policies: List[dict] = []
    for c in authz_clients:
        try:
            page = _kc_get(
                f"/admin/realms/{realm}/clients/{c['id']}/authz/resource-server/policy",
                params={"max": 1000},
                token=token,
            )
            if isinstance(page, list):
                policies.extend(page)
        except Exception:
            pass
    return policies


def _get_all_authz_permissions(token: str, realm: str = None) -> List[dict]:
    if realm is None:
        realm = KEYCLOAK_REALM
    authz_clients = _get_authz_clients(token, realm)
    perms: List[dict] = []
    for c in authz_clients:
        try:
            page = _kc_get(
                f"/admin/realms/{realm}/clients/{c['id']}/authz/resource-server/permission",
                params={"max": 1000},
                token=token,
            )
            if isinstance(page, list):
                perms.extend(page)
        except Exception:
            pass
    return perms


# ─────────────────────────── collectors ───────────────────────────

def collect_user_role_ratio(item_id: str, maturity: str) -> CollectedResult:
    """1.1.1.2_1: 역할 부여 비율 ≥ 95% → 충족 / 80~95% → 부분충족 / 미만 → 미충족"""
    MK, TH = "user_role_ratio", 0.95
    try:
        token = _get_admin_token()
        users = _get_all_users(token)
        human = _active_human_users(users)
        if not human:
            return _unavailable(item_id, maturity, MK, TH, "활성 사용자(분모)가 0")
        with_role = 0
        for u in human:
            roles = _kc_get(
                f"/admin/realms/{KEYCLOAK_REALM}/users/{u['id']}/role-mappings/realm",
                token=token,
            )
            non_default = [r for r in (roles or []) if not _is_default_role(r.get("name", ""))]
            if non_default:
                with_role += 1
        ratio = with_role / len(human)
        if ratio >= TH:
            verdict = "충족"
        elif ratio >= 0.8:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, ratio, TH, verdict,
                            {"total": len(human), "with_role": with_role})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_idp_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.1.1.3_1: 활성 IdP ≥ 1 AND 외부 IdP 출처 사용자 비율 ≥ 50% → 충족 / IdP만 → 부분충족"""
    MK, TH = "idp_user_ratio", 0.5
    try:
        token = _get_admin_token()
        idps = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/identity-provider/instances", token=token)
        active_idps = [i for i in (idps or []) if i.get("enabled")]
        users = _get_all_users(token)
        human = _active_human_users(users)
        if not human:
            return _unavailable(item_id, maturity, MK, TH, "활성 사용자 없음")
        fed_count = sum(1 for u in human if u.get("federatedIdentities"))
        ratio = fed_count / len(human)
        if len(active_idps) >= 1 and ratio >= TH:
            verdict = "충족"
        elif len(active_idps) >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, ratio, TH, verdict,
                            {"active_idps": len(active_idps), "fed_users": fed_count, "total_users": len(human)})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_client_group_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.1.1.4_2: 활성 클라이언트 ≥ 3 AND 그룹 ≥ 1 → 충족 / 1~2 → 부분충족"""
    MK, TH = "client_group_count", 3.0
    try:
        token = _get_admin_token()
        clients = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/clients", token=token)
        active_count = sum(1 for c in (clients or []) if c.get("enabled") and not c.get("surrogateAuthRequired"))
        groups = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/groups", token=token)
        group_count = len(groups or [])
        if active_count >= TH and group_count >= 1:
            verdict = "충족"
        elif active_count >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(active_count), TH, verdict,
                            {"active_clients": active_count, "groups": group_count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_idp_registered(item_id: str, maturity: str) -> CollectedResult:
    """1.1.2.1_1: IdP ≥ 1 → 충족 / 0 → 미충족"""
    MK, TH = "idp_count", 1.0
    try:
        token = _get_admin_token()
        idps = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/identity-provider/instances", token=token)
        count = len(idps or [])
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"idp_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_active_idp_multi(item_id: str, maturity: str) -> CollectedResult:
    """1.1.2.2_1: 활성 IdP ≥ 2 → 충족 / 1 → 부분충족 / 0 → 미충족"""
    MK, TH = "active_idp_count", 2.0
    try:
        token = _get_admin_token()
        idps = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/identity-provider/instances", token=token)
        count = sum(1 for i in (idps or []) if i.get("enabled"))
        if count >= TH:
            verdict = "충족"
        elif count == 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"active_idp_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_mfa_required(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.1_1: 필수 MFA ≥ 1 → 충족 / OPTIONAL만 → 부분충족 / 미설정 → 미충족"""
    MK, TH = "mfa_required_count", 1.0
    try:
        token = _get_admin_token()
        flows = _flows_with_executions(token)
        if not flows:
            return _unavailable(item_id, maturity, MK, TH, "인증 흐름 없음")
        required_count = 0
        optional_count = 0
        for fdata in flows:
            for ex in fdata["executions"]:
                provider = ex.get("providerId", "").lower()
                req = ex.get("requirement", "")
                if "otp" in provider or "totp" in provider or "webauthn" in provider:
                    if req == "REQUIRED":
                        required_count += 1
                    elif req == "OPTIONAL":
                        optional_count += 1
        if required_count >= TH:
            verdict = "충족"
        elif optional_count >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(required_count), TH, verdict,
                            {"required": required_count, "optional": optional_count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_otp_flow(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.2_1: OTP 포함 흐름 ≥ 1 → 충족 / 0 → 미충족"""
    MK, TH = "otp_flow_count", 1.0
    try:
        token = _get_admin_token()
        flows = _flows_with_executions(token)
        count = sum(
            1 for fdata in flows
            if any("otp" in ex.get("providerId", "").lower() or "totp" in ex.get("providerId", "").lower()
                   for ex in fdata["executions"])
        )
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"otp_flow_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_webauthn_status(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.2_2: webauthn enabled=true ≥ 1 → 충족 / 등록만 → 부분충족"""
    MK, TH = "webauthn_enabled", 1.0
    try:
        token = _get_admin_token()
        flows = _flows_with_executions(token)
        enabled = 0
        registered = 0
        for fdata in flows:
            for ex in fdata["executions"]:
                prov = ex.get("providerId", "").lower()
                if "webauthn" in prov:
                    req = ex.get("requirement", "")
                    if req in ("REQUIRED", "ALTERNATIVE"):
                        enabled += 1
                    elif "register" in prov:
                        registered += 1
        if enabled >= TH:
            verdict = "충족"
        elif registered >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(enabled), TH, verdict,
                            {"webauthn_enabled": enabled, "webauthn_registered": registered})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_conditional_auth(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.3_1: 조건부 MFA 흐름 ≥ 1 → 충족 / 0 → 미충족"""
    MK, TH = "conditional_auth_count", 1.0
    try:
        token = _get_admin_token()
        flows = _flows_with_executions(token)
        count = sum(
            1 for fdata in flows
            if any("conditional" in ex.get("providerId", "").lower()
                   for ex in fdata["executions"])
        )
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"conditional_flow_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_session_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.2.2.1_1: 유휴 타임아웃 > 0 AND 최대 수명 > 0 → 충족 / 한쪽만 → 부분충족"""
    MK, TH = "session_policy_set", 1.0
    try:
        token = _get_admin_token()
        realm_info = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}", token=token)
        idle = realm_info.get("ssoSessionIdleTimeout", 0)
        max_life = realm_info.get("ssoSessionMaxLifespan", 0)
        if idle > 0 and max_life > 0:
            verdict = "충족"
            value = 1.0
        elif idle > 0 or max_life > 0:
            verdict = "부분충족"
            value = 0.5
        else:
            verdict = "미충족"
            value = 0.0
        return _make_result(item_id, maturity, MK, value, TH, verdict,
                            {"ssoSessionIdleTimeout": idle, "ssoSessionMaxLifespan": max_life})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_stepup_auth(item_id: str, maturity: str) -> CollectedResult:
    """1.2.2.2_1: step-up flow ≥ 1 → 충족 / 0 → 미충족"""
    MK, TH = "stepup_flow_count", 1.0
    try:
        token = _get_admin_token()
        flows = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/authentication/flows", token=token)
        count = sum(
            1 for f in (flows or [])
            if "step" in f.get("alias", "").lower() or "stepup" in f.get("alias", "").lower()
        )
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"stepup_flow_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_dynamic_auth_flow(item_id: str, maturity: str) -> CollectedResult:
    """1.2.2.3_1: 커스텀 flow ≥ 1 → 충족 / 0 → 미충족"""
    MK, TH = "dynamic_flow_count", 1.0
    try:
        token = _get_admin_token()
        flows = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/authentication/flows", token=token)
        count = sum(1 for f in (flows or []) if not f.get("builtIn", True))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"custom_flow_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_realm_count(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1.1_1: master 제외 realm ≥ 1 → 충족 / master만 → 부분충족"""
    MK, TH = "realm_count", 1.0
    try:
        token = _get_admin_token()
        realms = _kc_get("/admin/realms", token=token)
        count = sum(1 for r in (realms or []) if r.get("realm") != "master")
        if count >= TH:
            verdict = "충족"
        else:
            verdict = "부분충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"realm_count": count, "total_realms": len(realms or [])})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_icam_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1.2_1: users ≥ 1, clients ≥ 1, groups ≥ 1 모두 → 충족 / 일부만 → 부분충족"""
    MK, TH = "icam_item_count", 3.0
    try:
        token = _get_admin_token()
        users = _get_all_users(token)
        clients = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/clients", token=token)
        groups = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/groups", token=token)
        u_count = len(_active_human_users(users))
        c_count = sum(1 for c in (clients or []) if c.get("enabled"))
        g_count = len(groups or [])
        total = sum(1 for x in [u_count, c_count, g_count] if x >= 1)
        if total == 3:
            verdict = "충족"
        elif total >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(total), TH, verdict,
                            {"users": u_count, "clients": c_count, "groups": g_count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_custom_auth_flow(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1.2_2: 커스텀 flow ≥ 1 → 충족 / 기본 flow만 → 미충족"""
    MK, TH = "custom_flow_count", 1.0
    try:
        token = _get_admin_token()
        flows = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/authentication/flows", token=token)
        count = sum(1 for f in (flows or []) if not f.get("builtIn", True))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"custom_flow_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_icam_central(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1.3_1: users + clients + idps + groups 합산 ≥ 3 → 충족 / 1~2 → 부분충족"""
    MK, TH = "icam_central_count", 3.0
    try:
        token = _get_admin_token()
        users = _get_all_users(token)
        clients = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/clients", token=token)
        idps = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/identity-provider/instances", token=token)
        groups = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/groups", token=token)
        items = {
            "users": len(_active_human_users(users)),
            "clients": sum(1 for c in (clients or []) if c.get("enabled")),
            "idps": len(idps or []),
            "groups": len(groups or []),
        }
        total = sum(1 for v in items.values() if v >= 1)
        if total >= TH:
            verdict = "충족"
        elif total >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(total), TH, verdict, items)
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_webauthn_users(item_id: str, maturity: str) -> CollectedResult:
    """1.3.2.2_1: webauthn 사용자 비율 ≥ 30% → 충족 / 10~30% → 부분충족"""
    MK, TH = "webauthn_user_ratio", 0.3
    try:
        token = _get_admin_token()
        users = _get_all_users(token)
        human = _active_human_users(users)
        if not human:
            return _unavailable(item_id, maturity, MK, TH, "활성 사용자(분모)가 0")
        wn_count = 0
        for u in human:
            try:
                creds = _kc_get(
                    f"/admin/realms/{KEYCLOAK_REALM}/users/{u['id']}/credentials",
                    token=token,
                )
                if any("webauthn" in c.get("type", "").lower() for c in (creds or [])):
                    wn_count += 1
            except Exception:
                pass
        ratio = wn_count / len(human)
        if ratio >= TH:
            verdict = "충족"
        elif ratio >= 0.1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, ratio, TH, verdict,
                            {"webauthn_users": wn_count, "total_users": len(human)})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_context_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.3.2.2_2: 컨텍스트 정책 ≥ 1 → 충족 / 0 → 미충족"""
    MK, TH = "context_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = sum(1 for p in policies if p.get("type") in ("js", "time", "client-scope"))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"context_policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_authz_clients(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.1_3: authz 클라이언트 ≥ 1 → 충족 / 0 → 미충족"""
    MK, TH = "authz_client_count", 1.0
    try:
        token = _get_admin_token()
        count = len(_get_authz_clients(token))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"authz_client_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_rbac_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.2_1: role 정책 ≥ 1 → 충족 / 0 → 미충족"""
    MK, TH = "rbac_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = sum(1 for p in policies if p.get("type") == "role")
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"role_policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_session_policy_advanced(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.3_1: offlineSessionIdle 설정 → 충족"""
    MK, TH = "advanced_session_policy", 1.0
    try:
        token = _get_admin_token()
        realm_info = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}", token=token)
        offline_idle = realm_info.get("offlineSessionIdleTimeout", 0)
        value = 1.0 if offline_idle > 0 else 0.0
        verdict = "충족" if offline_idle > 0 else "미충족"
        return _make_result(item_id, maturity, MK, value, TH, verdict,
                            {"offlineSessionIdleTimeout": offline_idle})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_aggregate_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.3_2: aggregate 정책 ≥ 1 → 충족 / 단일 조건만 → 부분충족"""
    MK, TH = "aggregate_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        agg_count = sum(1 for p in policies if p.get("type") == "aggregate")
        other_count = sum(1 for p in policies if p.get("type") not in ("aggregate",))
        if agg_count >= TH:
            verdict = "충족"
        elif other_count >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(agg_count), TH, verdict,
                            {"aggregate_count": agg_count, "other_count": other_count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_resource_permission(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.3_3: permission ≥ 1 → 충족 / 0 → 미충족"""
    MK, TH = "resource_permission_count", 1.0
    try:
        token = _get_admin_token()
        perms = _get_all_authz_permissions(token)
        count = len(perms)
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"permission_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_password_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.2_1: 정책 항목 ≥ 3 → 충족 / 1~2 → 부분충족"""
    MK, TH = "password_policy_count", 3.0
    try:
        token = _get_admin_token()
        realm_info = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}", token=token)
        policy_str = realm_info.get("passwordPolicy", "")
        items = [p.strip() for p in policy_str.split(" and ") if p.strip()] if policy_str else []
        count = len(items)
        if count >= TH:
            verdict = "충족"
        elif count >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"policy_items": items, "count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_role_change_events(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.2_2: 이벤트 수집 활성화 AND 이력 ≥ 1 → 충족 / 수집만 → 부분충족"""
    MK, TH = "role_change_event_count", 1.0
    try:
        token = _get_admin_token()
        realm_info = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}", token=token)
        events_enabled = realm_info.get("eventsEnabled", False)
        admin_events = _kc_get(
            f"/admin/realms/{KEYCLOAK_REALM}/admin-events",
            params={"operationTypes": "UPDATE", "resourceTypes": "REALM_ROLE_MAPPING", "max": 10},
            token=token,
        )
        count = len(admin_events or [])
        if events_enabled and count >= TH:
            verdict = "충족"
        elif events_enabled:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"events_enabled": events_enabled, "event_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_stepup_authz(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.3_1: step-up flow ≥ 1 AND Shuffle 연동 → 충족 / flow만 → 부분충족"""
    MK, TH = "stepup_with_shuffle", 1.0
    try:
        token = _get_admin_token()
        flows = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/authentication/flows", token=token)
        stepup_count = sum(
            1 for f in (flows or [])
            if "step" in f.get("alias", "").lower()
        )
        shuffle_url = os.environ.get("SHUFFLE_URL", "")
        shuffle_connected = bool(shuffle_url)
        if stepup_count >= TH and shuffle_connected:
            verdict = "충족"
        elif stepup_count >= TH:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(stepup_count), TH, verdict,
                            {"stepup_flow_count": stepup_count, "shuffle_configured": shuffle_connected})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_rbac_central(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.1_2: RBAC 정책 ≥ 1 → 충족 / 0 → 미충족"""
    MK, TH = "rbac_central_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = sum(1 for p in policies if p.get("type") == "role")
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"rbac_policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_central_authz_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.2_1: authz 클라이언트 ≥ 1 → 충족"""
    MK, TH = "central_authz_client_count", 1.0
    try:
        token = _get_admin_token()
        count = len(_get_authz_clients(token))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"authz_client_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_realtime_authz(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.2_2: 정책 ≥ 1 → 충족"""
    MK, TH = "realtime_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = len(policies)
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_auto_access_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.2_4: 정책 ≥ 1 → 충족"""
    MK, TH = "auto_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = len(policies)
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_abac_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.3_1: ABAC(js/time) 정책 ≥ 1 → 충족"""
    MK, TH = "abac_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = sum(1 for p in policies if p.get("type") in ("js", "time"))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"abac_policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_conditional_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.3_2: aggregate/js 정책 ≥ 1 → 충족"""
    MK, TH = "conditional_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = sum(1 for p in policies if p.get("type") in ("aggregate", "js"))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"conditional_policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_central_authz_ratio(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.4_2: authz 클라이언트 비율 ≥ 90% → 충족 / 50~90% → 부분충족"""
    MK, TH = "central_authz_ratio", 0.9
    try:
        token = _get_admin_token()
        clients = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/clients", token=token)
        enabled = [c for c in (clients or []) if c.get("enabled")]
        if not enabled:
            return _unavailable(item_id, maturity, MK, TH, "활성 클라이언트 없음")
        authz_count = sum(1 for c in enabled if c.get("authorizationServicesEnabled"))
        ratio = authz_count / len(enabled)
        if ratio >= TH:
            verdict = "충족"
        elif ratio >= 0.5:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, ratio, TH, verdict,
                            {"authz_clients": authz_count, "total_clients": len(enabled)})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_pam_stepup(item_id: str, maturity: str) -> CollectedResult:
    """4.2.1.2_2: step-up flow ≥ 1 → 충족"""
    MK, TH = "pam_stepup_count", 1.0
    try:
        token = _get_admin_token()
        flows = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/authentication/flows", token=token)
        count = sum(1 for f in (flows or []) if "step" in f.get("alias", "").lower())
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"stepup_flow_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_password_policy_basic(item_id: str, maturity: str) -> CollectedResult:
    """4.2.2.1_2: passwordPolicy 설정 → 충족"""
    MK, TH = "password_policy_set", 1.0
    try:
        token = _get_admin_token()
        realm_info = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}", token=token)
        policy_str = realm_info.get("passwordPolicy", "")
        value = 1.0 if policy_str else 0.0
        verdict = "충족" if policy_str else "미충족"
        return _make_result(item_id, maturity, MK, value, TH, verdict,
                            {"passwordPolicy": policy_str})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_credential_central(item_id: str, maturity: str) -> CollectedResult:
    """4.2.2.2_1: authz 클라이언트 ≥ 1 → 충족"""
    MK, TH = "authz_client_count", 1.0
    try:
        token = _get_admin_token()
        count = len(_get_authz_clients(token))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"authz_client_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_mfa_required_actions(item_id: str, maturity: str) -> CollectedResult:
    """4.2.2.2_2: CONFIGURE_TOTP 또는 webauthn-register enabled ≥ 1 → 충족"""
    MK, TH = "mfa_action_count", 1.0
    try:
        token = _get_admin_token()
        actions = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/authentication/required-actions", token=token)
        count = sum(
            1 for a in (actions or [])
            if a.get("enabled") and a.get("alias") in ("CONFIGURE_TOTP", "webauthn-register")
        )
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"mfa_action_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_webauthn_credential_users(item_id: str, maturity: str) -> CollectedResult:
    """4.2.2.3_1: webauthn 자격증명 보유 사용자 ≥ 1 → 충족"""
    MK, TH = "webauthn_credential_count", 1.0
    try:
        token = _get_admin_token()
        users = _get_all_users(token)
        human = _active_human_users(users)
        wn_count = 0
        for u in human:
            try:
                creds = _kc_get(
                    f"/admin/realms/{KEYCLOAK_REALM}/users/{u['id']}/credentials",
                    token=token,
                )
                if any("webauthn" in c.get("type", "").lower() for c in (creds or [])):
                    wn_count += 1
            except Exception:
                pass
        verdict = "충족" if wn_count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(wn_count), TH, verdict,
                            {"webauthn_users": wn_count, "total_users": len(human)})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_advanced_credential_mgmt(item_id: str, maturity: str) -> CollectedResult:
    """4.2.2.3_2: authz client ≥ 1 AND webauthn 사용자 ≥ 1 → 충족 / 한쪽만 → 부분충족"""
    MK, TH = "authz_with_webauthn", 1.0
    try:
        token = _get_admin_token()
        authz_count = len(_get_authz_clients(token))
        users = _get_all_users(token)
        human = _active_human_users(users)
        wn_count = 0
        for u in human:
            try:
                creds = _kc_get(
                    f"/admin/realms/{KEYCLOAK_REALM}/users/{u['id']}/credentials",
                    token=token,
                )
                if any("webauthn" in c.get("type", "").lower() for c in (creds or [])):
                    wn_count += 1
            except Exception:
                pass
        if authz_count >= 1 and wn_count >= 1:
            verdict = "충족"
        elif authz_count >= 1 or wn_count >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(min(authz_count, wn_count)), TH, verdict,
                            {"authz_clients": authz_count, "webauthn_users": wn_count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_abnormal_auth_block(item_id: str, maturity: str) -> CollectedResult:
    """4.2.2.4_1: 탐지 룰 활성화 AND 자동 차단 → 충족 / 탐지만 → 부분충족"""
    MK, TH = "block_flow_count", 1.0
    try:
        token = _get_admin_token()
        flows = _flows_with_executions(token)
        detect_count = sum(
            1 for fdata in flows
            if any("deny" in ex.get("providerId", "").lower() or "block" in ex.get("providerId", "").lower()
                   for ex in fdata["executions"])
        )
        cond_count = sum(
            1 for fdata in flows
            if any("condition" in ex.get("providerId", "").lower()
                   for ex in fdata["executions"])
        )
        if detect_count >= TH and cond_count >= 1:
            verdict = "충족"
        elif detect_count >= TH or cond_count >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(detect_count + cond_count), TH, verdict,
                            {"detect_count": detect_count, "cond_count": cond_count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_realtime_auth_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.2.2.4_2: 이벤트 ≥ 1 → 충족 / 구성만 → 부분충족"""
    MK, TH = "auth_event_count", 1.0
    try:
        token = _get_admin_token()
        realm_info = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}", token=token)
        events_enabled = realm_info.get("eventsEnabled", False)
        events = _kc_get(
            f"/admin/realms/{KEYCLOAK_REALM}/events",
            params={"type": "LOGIN_ERROR", "max": 10},
            token=token,
        )
        count = len(events or [])
        if events_enabled and count >= TH:
            verdict = "충족"
        elif events_enabled:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"events_enabled": events_enabled, "event_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_autonomous_credential_mgmt(item_id: str, maturity: str) -> CollectedResult:
    """4.2.2.4_3: authz client ≥ 1 AND IdP ≥ 1 → 충족 / 한쪽만 → 부분충족"""
    MK, TH = "autonomous_mgmt_count", 1.0
    try:
        token = _get_admin_token()
        authz_count = len(_get_authz_clients(token))
        idps = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/identity-provider/instances", token=token)
        idp_count = len(idps or [])
        if authz_count >= 1 and idp_count >= 1:
            verdict = "충족"
        elif authz_count >= 1 or idp_count >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(min(authz_count, idp_count)), TH, verdict,
                            {"authz_clients": authz_count, "idp_count": idp_count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_inter_group_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.3_2: 정책 ≥ 1 → 충족"""
    MK, TH = "inter_group_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = len(policies)
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_sso_clients(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.3_5: standardFlowEnabled=true 클라이언트 ≥ 1 → 충족"""
    MK, TH = "sso_client_count", 1.0
    try:
        token = _get_admin_token()
        clients = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/clients", token=token)
        count = sum(1 for c in (clients or []) if c.get("standardFlowEnabled") and c.get("enabled"))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"sso_client_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_resource_static_policy(item_id: str, maturity: str) -> CollectedResult:
    """5.1.1.1_2: 정책 ≥ 1 → 충족"""
    MK, TH = "static_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = len(policies)
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_workload_central_authz(item_id: str, maturity: str) -> CollectedResult:
    """5.1.1.2_1: authz 관리 클라이언트 ≥ 1 → 충족"""
    MK, TH = "workload_authz_count", 1.0
    try:
        token = _get_admin_token()
        count = len(_get_authz_clients(token))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"authz_client_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_central_resource_mgmt(item_id: str, maturity: str) -> CollectedResult:
    """5.1.1.2_2: 리소스 ≥ 1 → 충족"""
    MK, TH = "resource_count", 1.0
    try:
        token = _get_admin_token()
        authz_clients = _get_authz_clients(token)
        total = 0
        for c in authz_clients:
            try:
                rs = _kc_get(
                    f"/admin/realms/{KEYCLOAK_REALM}/clients/{c['id']}/authz/resource-server/resource",
                    params={"max": 1000},
                    token=token,
                )
                total += len(rs or [])
            except Exception:
                pass
        verdict = "충족" if total >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(total), TH, verdict, {"resource_count": total})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_context_access_policy(item_id: str, maturity: str) -> CollectedResult:
    """5.1.1.3_1: 컨텍스트 정책 ≥ 1 → 충족"""
    MK, TH = "context_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = sum(1 for p in policies if p.get("type") in ("js", "time", "client-scope"))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"context_policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_fine_grained_policy(item_id: str, maturity: str) -> CollectedResult:
    """5.1.1.3_2: 세분화 정책 ≥ 1 → 충족"""
    MK, TH = "fine_grained_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = sum(1 for p in policies if p.get("type") in ("scope", "resource", "role"))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"fine_grained_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_auto_grant_revoke(item_id: str, maturity: str) -> CollectedResult:
    """5.1.1.4_2: 이벤트 ≥ 1 → 충족 / 구성만 → 부분충족"""
    MK, TH = "grant_revoke_event_count", 1.0
    try:
        token = _get_admin_token()
        realm_info = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}", token=token)
        events_enabled = realm_info.get("eventsEnabled", False)
        events = _kc_get(
            f"/admin/realms/{KEYCLOAK_REALM}/admin-events",
            params={"operationTypes": "CREATE,DELETE", "resourceTypes": "USER", "max": 10},
            token=token,
        )
        count = len(events or [])
        if events_enabled and count >= TH:
            verdict = "충족"
        elif events_enabled:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"events_enabled": events_enabled, "event_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_full_authz_ratio(item_id: str, maturity: str) -> CollectedResult:
    """5.1.1.4_4: authz 비율 ≥ 90% → 충족 / 50~90% → 부분충족"""
    MK, TH = "full_authz_ratio", 0.9
    try:
        token = _get_admin_token()
        clients = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/clients", token=token)
        enabled = [c for c in (clients or []) if c.get("enabled")]
        if not enabled:
            return _unavailable(item_id, maturity, MK, TH, "활성 클라이언트 없음")
        authz_count = sum(1 for c in enabled if c.get("authorizationServicesEnabled"))
        ratio = authz_count / len(enabled)
        if ratio >= TH:
            verdict = "충족"
        elif ratio >= 0.5:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, ratio, TH, verdict,
                            {"authz_clients": authz_count, "total_clients": len(enabled)})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_approval_automation(item_id: str, maturity: str) -> CollectedResult:
    """5.2.1.3_2: 이벤트 ≥ 1 → 충족 / 구성만 → 부분충족"""
    MK, TH = "approval_event_count", 1.0
    try:
        token = _get_admin_token()
        realm_info = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}", token=token)
        events_enabled = realm_info.get("adminEventsEnabled", False)
        events = _kc_get(
            f"/admin/realms/{KEYCLOAK_REALM}/admin-events",
            params={"max": 10},
            token=token,
        )
        count = len(events or [])
        if events_enabled and count >= TH:
            verdict = "충족"
        elif events_enabled:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"admin_events_enabled": events_enabled, "event_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_app_access_policy(item_id: str, maturity: str) -> CollectedResult:
    """5.3.1.1_2: 정책 ≥ 1 → 충족"""
    MK, TH = "app_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = len(policies)
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_remote_scenario_policy(item_id: str, maturity: str) -> CollectedResult:
    """5.3.1.3_2: 시나리오 정책 ≥ 1 → 충족"""
    MK, TH = "scenario_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = sum(1 for p in policies if p.get("type") in ("aggregate", "js"))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"scenario_policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_dynamic_app_policy(item_id: str, maturity: str) -> CollectedResult:
    """5.3.1.4_1: 이벤트 ≥ 1 → 충족 / 구성만 → 부분충족"""
    MK, TH = "dynamic_policy_event", 1.0
    try:
        token = _get_admin_token()
        realm_info = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}", token=token)
        events_enabled = realm_info.get("adminEventsEnabled", False)
        events = _kc_get(
            f"/admin/realms/{KEYCLOAK_REALM}/admin-events",
            params={"resourceTypes": "AUTHORIZATION_POLICY", "max": 10},
            token=token,
        )
        count = len(events or [])
        if events_enabled and count >= TH:
            verdict = "충족"
        elif events_enabled:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"admin_events_enabled": events_enabled, "policy_event_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_deploy_access_policy(item_id: str, maturity: str) -> CollectedResult:
    """5.4.1.1_3: 배포 접근제어 정책 ≥ 1 → 충족"""
    MK, TH = "deploy_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = len(policies)
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_auto_deploy_authz(item_id: str, maturity: str) -> CollectedResult:
    """5.4.1.4_1: authz 클라이언트 ≥ 1 → 충족"""
    MK, TH = "auto_deploy_authz_count", 1.0
    try:
        token = _get_admin_token()
        count = len(_get_authz_clients(token))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"authz_client_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_app_inventory_security(item_id: str, maturity: str) -> CollectedResult:
    """5.4.2.3_1: authz 활성 비율 ≥ 80% → 충족 / 50~80% → 부분충족"""
    MK, TH = "app_security_ratio", 0.8
    try:
        token = _get_admin_token()
        clients = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/clients", token=token)
        enabled = [c for c in (clients or []) if c.get("enabled")]
        if not enabled:
            return _unavailable(item_id, maturity, MK, TH, "활성 클라이언트 없음")
        authz_count = sum(1 for c in enabled if c.get("authorizationServicesEnabled"))
        ratio = authz_count / len(enabled)
        if ratio >= TH:
            verdict = "충족"
        elif ratio >= 0.5:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, ratio, TH, verdict,
                            {"authz_clients": authz_count, "total_clients": len(enabled)})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_app_inventory_integrated(item_id: str, maturity: str) -> CollectedResult:
    """5.4.2.4_2: authz client ≥ 1 AND IdP ≥ 1 → 충족 / 한쪽만 → 부분충족"""
    MK, TH = "integrated_count", 1.0
    try:
        token = _get_admin_token()
        authz_count = len(_get_authz_clients(token))
        idps = _kc_get(f"/admin/realms/{KEYCLOAK_REALM}/identity-provider/instances", token=token)
        idp_count = len(idps or [])
        if authz_count >= 1 and idp_count >= 1:
            verdict = "충족"
        elif authz_count >= 1 or idp_count >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(min(authz_count, idp_count)), TH, verdict,
                            {"authz_clients": authz_count, "idp_count": idp_count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_data_central_authz(item_id: str, maturity: str) -> CollectedResult:
    """6.2.1.2_1: authz 클라이언트 ≥ 1 → 충족"""
    MK, TH = "data_authz_client_count", 1.0
    try:
        token = _get_admin_token()
        count = len(_get_authz_clients(token))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"authz_client_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_data_rbac_policy(item_id: str, maturity: str) -> CollectedResult:
    """6.2.1.2_2: role 정책 ≥ 1 → 충족"""
    MK, TH = "data_role_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = sum(1 for p in policies if p.get("type") == "role")
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"role_policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_data_abac_policy(item_id: str, maturity: str) -> CollectedResult:
    """6.2.1.3_1: ABAC 정책 ≥ 1 → 충족"""
    MK, TH = "data_abac_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = sum(1 for p in policies if p.get("type") in ("js", "time"))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"abac_policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_data_permission_central(item_id: str, maturity: str) -> CollectedResult:
    """6.3.1.2_2: authz 클라이언트 ≥ 1 → 충족"""
    MK, TH = "data_permission_client_count", 1.0
    try:
        token = _get_admin_token()
        count = len(_get_authz_clients(token))
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"authz_client_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_data_combined_policy(item_id: str, maturity: str) -> CollectedResult:
    """6.3.1.3_2: RBAC+ABAC 결합 정책 ≥ 1 → 충족 / 단일 방식만 → 부분충족"""
    MK, TH = "combined_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        rbac_count = sum(1 for p in policies if p.get("type") == "role")
        abac_count = sum(1 for p in policies if p.get("type") in ("js", "time"))
        agg_count = sum(1 for p in policies if p.get("type") == "aggregate")
        combined = agg_count
        if combined >= TH:
            verdict = "충족"
        elif rbac_count >= 1 or abac_count >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(combined), TH, verdict,
                            {"rbac": rbac_count, "abac": abac_count, "aggregate": agg_count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_sensitive_data_policy(item_id: str, maturity: str) -> CollectedResult:
    """6.4.1.2_3: 민감 데이터 정책 ≥ 1 → 충족"""
    MK, TH = "sensitive_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = len(policies)
        verdict = "충족" if count >= TH else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {"policy_count": count})
    except Exception as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))
