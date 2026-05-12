from typing import Optional, List, Any
from datetime import datetime, timezone, timedelta
import os
import time
import requests

CollectedResult = dict

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "master")
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "admin-cli")
KEYCLOAK_ADMIN = os.environ.get("KEYCLOAK_ADMIN", "")
KEYCLOAK_ADMIN_PASSWORD = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "")

_SYSTEM_ROLES = frozenset({"offline_access", "uma_authorization"})


# ─────────────────────────── internal helpers ───────────────────────────

def _get_admin_token() -> str:
    """POST to master realm token endpoint, return access_token."""
    url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    resp = requests.post(
        url,
        data={
            "grant_type": "password",
            "client_id": KEYCLOAK_CLIENT_ID,
            "username": KEYCLOAK_ADMIN,
            "password": KEYCLOAK_ADMIN_PASSWORD,
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


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


def _api_get(path: str, params: dict = None, token: str = None) -> Any:
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
    """Paginate /admin/realms/{realm}/users, 100 per page."""
    if realm is None:
        realm = KEYCLOAK_REALM
    users: List[dict] = []
    first = 0
    while True:
        page = _api_get(
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


def _get_user_realm_roles(user_id: str, token: str, realm: str = None) -> List[dict]:
    if realm is None:
        realm = KEYCLOAK_REALM
    return _api_get(f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm", token=token)


def _active_human_users(users: List[dict]) -> List[dict]:
    return [u for u in users if u.get("enabled") and not u.get("serviceAccountClientId")]


def _is_default_role(name: str) -> bool:
    return name.startswith("default-roles-") or name in _SYSTEM_ROLES


def _flows_with_executions(token: str, realm: str = None) -> List[dict]:
    if realm is None:
        realm = KEYCLOAK_REALM
    flows = _api_get(f"/admin/realms/{realm}/authentication/flows", token=token)
    result = []
    for flow in flows:
        fid = flow.get("id")
        try:
            execs = _api_get(
                f"/admin/realms/{realm}/authentication/flows/{fid}/executions",
                token=token,
            )
        except Exception:
            execs = []
        result.append({"flow": flow, "executions": execs or []})
    return result


def _get_all_authz_policies(token: str, realm: str = None) -> List[dict]:
    if realm is None:
        realm = KEYCLOAK_REALM
    clients = _api_get(f"/admin/realms/{realm}/clients", token=token)
    policies: List[dict] = []
    for c in clients:
        if c.get("authorizationServicesEnabled") and c.get("enabled"):
            try:
                page = _api_get(
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
    clients = _api_get(f"/admin/realms/{realm}/clients", token=token)
    perms: List[dict] = []
    for c in clients:
        if c.get("authorizationServicesEnabled") and c.get("enabled"):
            try:
                page = _api_get(
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
    """1.1.1_초기: 사용자 역할에 따른 상세 인벤토리"""
    MK, TH = "role_assigned_ratio", 0.95
    try:
        token = _get_admin_token()
        users = _get_all_users(token)
        humans = _active_human_users(users)
        denom = len(humans)
        if denom == 0:
            return _unavailable(item_id, maturity, MK, TH, "활성 사용자(분모)가 0")
        num = 0
        for u in humans:
            roles = _get_user_realm_roles(u["id"], token)
            if any(not _is_default_role(r.get("name", "")) for r in (roles or [])):
                num += 1
        ratio = num / denom
        if ratio >= 0.95:
            verdict = "충족"
        elif ratio >= 0.80:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, ratio, TH, verdict,
                            {"denominator": denom, "numerator": num})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_idp_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.1.1_향상: 자동화된 인벤토리 관리"""
    MK, TH = "idp_user_ratio", 0.5
    try:
        token = _get_admin_token()
        realm = KEYCLOAK_REALM
        idps = _api_get(f"/admin/realms/{realm}/identity-provider/instances", token=token)
        active_idps = [i for i in idps if i.get("enabled")]
        users = _get_all_users(token)
        humans = _active_human_users(users)
        denom = len(humans)
        if denom == 0:
            return _unavailable(item_id, maturity, MK, TH, "활성 사용자 없음")
        federated = sum(1 for u in humans if u.get("federatedIdentities"))
        ratio = federated / denom
        if len(active_idps) >= 1 and ratio >= 0.5:
            verdict = "충족"
        elif len(active_idps) >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, ratio, TH, verdict, {
            "active_idp_count": len(active_idps),
            "federated_user_count": federated,
            "denominator": denom,
        })
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_client_group_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.1.1_최적화: 인벤토리 통합 및 권한 관리 최적화"""
    MK, TH = "active_client_count", 3.0
    try:
        token = _get_admin_token()
        realm = KEYCLOAK_REALM
        clients = _api_get(f"/admin/realms/{realm}/clients", token=token)
        groups = _api_get(f"/admin/realms/{realm}/groups", token=token)
        active_clients = [c for c in clients if c.get("enabled") and not c.get("serviceAccountsEnabled")]
        active_count = len(active_clients)
        group_count = len(groups)
        if active_count >= 3 and group_count >= 1:
            verdict = "충족"
        elif active_count >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(active_count), TH, verdict,
                            {"active_client_count": active_count, "group_count": group_count})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_idp_count(item_id: str, maturity: str) -> CollectedResult:
    """1.1.2_기존: ID 연계 솔루션 적용"""
    MK, TH = "idp_count", 1.0
    try:
        token = _get_admin_token()
        idps = _api_get(f"/admin/realms/{KEYCLOAK_REALM}/identity-provider/instances", token=token)
        count = len(idps)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"idps": [i.get("alias") for i in idps]})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_active_idp_count(item_id: str, maturity: str) -> CollectedResult:
    """1.1.2_초기: 여러 시스템 간 사용자 자격 증명 연동"""
    MK, TH = "active_idp_count", 2.0
    try:
        token = _get_admin_token()
        idps = _api_get(f"/admin/realms/{KEYCLOAK_REALM}/identity-provider/instances", token=token)
        active = [i for i in idps if i.get("enabled")]
        count = len(active)
        if count >= 2:
            verdict = "충족"
        elif count == 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"active_idps": [i.get("alias") for i in active]})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_mfa_required(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1_기존: 패스워드 + 단순 MFA 적용"""
    MK, TH = "required_mfa_count", 1.0
    _MFA_KEYWORDS = {"otp", "totp", "hotp", "sms", "email"}
    try:
        token = _get_admin_token()
        flows_data = _flows_with_executions(token)
        if not flows_data:
            return _unavailable(item_id, maturity, MK, TH, "인증 흐름 없음")
        required_count = 0
        optional_count = 0
        raw: List[dict] = []
        for fd in flows_data:
            for ex in fd["executions"]:
                pid = (ex.get("providerId") or "").lower()
                req = ex.get("requirement", "")
                if any(k in pid for k in _MFA_KEYWORDS):
                    if req == "REQUIRED":
                        required_count += 1
                    elif req == "OPTIONAL":
                        optional_count += 1
                    raw.append({"providerId": pid, "requirement": req})
        if required_count >= 1:
            verdict = "충족"
        elif optional_count >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(required_count), TH, verdict, {
            "required_mfa_count": required_count,
            "optional_mfa_count": optional_count,
            "mfa_executions": raw,
        })
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_otp_flow(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1_초기: 다양한 MFA (인증 앱, 하드웨어 토큰 등)"""
    MK, TH = "otp_flow_count", 1.0
    _OTP_KEYWORDS = {"totp", "otp", "hotp"}
    try:
        token = _get_admin_token()
        flows_data = _flows_with_executions(token)
        otp_flows = [
            fd["flow"].get("alias")
            for fd in flows_data
            if any(any(k in (ex.get("providerId") or "").lower() for k in _OTP_KEYWORDS)
                   for ex in fd["executions"])
        ]
        count = len(otp_flows)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"otp_flows": otp_flows})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_webauthn_status(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1_초기 (FIDO): FIDO 기반 인증 기법 적용"""
    MK, TH = "webauthn_active_count", 1.0
    try:
        token = _get_admin_token()
        actions = _api_get(f"/admin/realms/{KEYCLOAK_REALM}/authentication/required-actions", token=token)
        active = [a for a in actions if "webauthn" in (a.get("alias") or "").lower() and a.get("enabled")]
        registered = [a for a in actions if "webauthn" in (a.get("alias") or "").lower()]
        count = len(active)
        if count >= 1:
            verdict = "충족"
        elif len(registered) >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {
            "active_webauthn_actions": [a.get("alias") for a in active],
            "registered_webauthn_actions": [a.get("alias") for a in registered],
        })
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_conditional_auth(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1_향상: 상황에 따른 맞춤형 MFA"""
    MK, TH = "conditional_flow_count", 1.0
    try:
        token = _get_admin_token()
        flows_data = _flows_with_executions(token)
        conditional_flows = [
            fd["flow"].get("alias")
            for fd in flows_data
            if any(ex.get("requirement") == "CONDITIONAL" for ex in fd["executions"])
        ]
        count = len(conditional_flows)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"conditional_flows": conditional_flows})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_session_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.2.2_기존: 세션 기반 인증"""
    MK, TH = "session_idle_timeout", 1.0
    try:
        token = _get_admin_token()
        realm_info = _api_get(f"/admin/realms/{KEYCLOAK_REALM}", token=token)
        idle = realm_info.get("ssoSessionIdleTimeout", 0) or 0
        max_life = realm_info.get("ssoSessionMaxLifespan", 0) or 0
        if idle > 0 and max_life > 0:
            verdict = "충족"
        elif idle > 0 or max_life > 0:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(idle), TH, verdict, {
            "ssoSessionIdleTimeout": idle,
            "ssoSessionMaxLifespan": max_life,
            "accessTokenLifespan": realm_info.get("accessTokenLifespan"),
        })
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_stepup_auth(item_id: str, maturity: str) -> CollectedResult:
    """1.2.2_초기: 이상행위 탐지 시 세션 중간 추가 인증"""
    MK, TH = "stepup_flow_count", 1.0
    _KEYWORDS = {"step-up", "auth-conditional", "step_up"}
    try:
        token = _get_admin_token()
        flows_data = _flows_with_executions(token)
        stepup_flows = [
            fd["flow"].get("alias")
            for fd in flows_data
            if any(any(k in (ex.get("providerId") or "").lower() for k in _KEYWORDS)
                   for ex in fd["executions"])
        ]
        count = len(stepup_flows)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"stepup_flows": stepup_flows})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_dynamic_auth_flow(item_id: str, maturity: str) -> CollectedResult:
    """1.2.2_향상: 동적 인증 기술 기반 실시간 인증 상태 조정"""
    MK, TH = "dynamic_flow_count", 1.0
    try:
        token = _get_admin_token()
        flows_data = _flows_with_executions(token)
        dynamic_flows = [
            fd["flow"].get("alias")
            for fd in flows_data
            if any(ex.get("requirement") == "CONDITIONAL" for ex in fd["executions"])
        ]
        count = len(dynamic_flows)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"dynamic_flows": dynamic_flows})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_realm_count(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1_기존: ICAM 시스템 구축"""
    MK, TH = "realm_count", 1.0
    try:
        token = _get_admin_token()
        realms = _api_get("/admin/realms", token=token)
        op_realms = [r for r in realms if r.get("enabled") and r.get("realm") != "master"]
        count = len(op_realms)
        if count >= 1:
            verdict = "충족"
        elif any(r.get("realm") == "master" for r in realms):
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {
            "all_realms": [r.get("realm") for r in realms],
            "operational_realms": [r.get("realm") for r in op_realms],
        })
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_icam_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1_초기: ICAM 시스템 기반 중앙 집중 관리 및 모니터링"""
    MK, TH = "icam_resource_count", 3.0
    try:
        token = _get_admin_token()
        realm = KEYCLOAK_REALM
        user_count = _api_get(f"/admin/realms/{realm}/users/count", token=token)
        clients = _api_get(f"/admin/realms/{realm}/clients", token=token)
        groups = _api_get(f"/admin/realms/{realm}/groups", token=token)
        client_count = len([c for c in clients if c.get("enabled")])
        group_count = len(groups)
        present = sum([user_count > 0, client_count > 0, group_count > 0])
        total = user_count + client_count + group_count
        if present == 3:
            verdict = "충족"
        elif present >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(total), TH, verdict, {
            "user_count": user_count,
            "client_count": client_count,
            "group_count": group_count,
        })
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_custom_auth_flow(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1_초기 (정책 표준화): 사용자 인증 및 접근 관리 정책 표준화"""
    MK, TH = "custom_flow_count", 1.0
    try:
        token = _get_admin_token()
        flows = _api_get(f"/admin/realms/{KEYCLOAK_REALM}/authentication/flows", token=token)
        custom = [f for f in flows if not f.get("builtIn")]
        count = len(custom)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"custom_flows": [f.get("alias") for f in custom]})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_idp_oidc_saml(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1_향상: 다양한 보안 기술 통합으로 ICAM 플랫폼 안정화"""
    MK, TH = "icam_integration_count", 3.0
    try:
        token = _get_admin_token()
        realm = KEYCLOAK_REALM
        idps = _api_get(f"/admin/realms/{realm}/identity-provider/instances", token=token)
        clients = _api_get(f"/admin/realms/{realm}/clients", token=token)
        active_idps = [i for i in idps if i.get("enabled")]
        oidc_saml = [
            c for c in clients
            if c.get("enabled") and c.get("protocol") in ("openid-connect", "saml")
        ]
        total = len(active_idps) + len(oidc_saml)
        if total >= 3:
            verdict = "충족"
        elif total >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(total), TH, verdict, {
            "active_idp_count": len(active_idps),
            "oidc_saml_client_count": len(oidc_saml),
        })
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_webauthn_users(item_id: str, maturity: str) -> CollectedResult:
    """1.3.2_초기: 행동 및 생체 인식 기술 통합 인증"""
    MK, TH = "webauthn_user_ratio", 0.3
    try:
        token = _get_admin_token()
        realm = KEYCLOAK_REALM
        users = _get_all_users(token)
        humans = _active_human_users(users)
        denom = len(humans)
        if denom == 0:
            return _unavailable(item_id, maturity, MK, TH, "활성 사용자(분모)가 0")
        num = 0
        for u in humans:
            creds = _api_get(f"/admin/realms/{realm}/users/{u['id']}/credentials", token=token)
            if any(c.get("type") == "webauthn" for c in (creds or [])):
                num += 1
        ratio = num / denom
        if ratio >= 0.3:
            verdict = "충족"
        elif ratio >= 0.1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, ratio, TH, verdict,
                            {"denominator": denom, "webauthn_user_count": num})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_context_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.3.2_초기 (컨텍스트 기반): 컨텍스트 정보 기반 접근권한 조정"""
    MK, TH = "context_policy_count", 1.0
    try:
        token = _get_admin_token()
        flows_data = _flows_with_executions(token)
        cond_execs = [
            {"flow": fd["flow"].get("alias"), "providerId": (ex.get("providerId") or "")}
            for fd in flows_data
            for ex in fd["executions"]
            if "conditional" in (ex.get("providerId") or "").lower()
        ]
        count = len(cond_execs)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"conditional_executions": cond_execs})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_authz_clients(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1_기존: 시스템별 접속 관리 기능"""
    MK, TH = "authz_client_count", 1.0
    try:
        token = _get_admin_token()
        clients = _api_get(f"/admin/realms/{KEYCLOAK_REALM}/clients", token=token)
        authz = [c for c in clients if c.get("authorizationServicesEnabled")]
        count = len(authz)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"authz_clients": [c.get("clientId") for c in authz]})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_conditional_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1_초기: 특정 조건에 따른 사용자 접근제어"""
    MK, TH = "conditional_policy_count", 1.0
    _COND_TYPES = {"user", "role", "group"}
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        cond = [p for p in policies if p.get("type") in _COND_TYPES]
        count = len(cond)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"conditional_policies": [p.get("name") for p in cond]})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_session_policy_advanced(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1_향상 (세션별 접근권한): 세션별 접근권한 부여"""
    MK, TH = "session_policy_count", 1.0
    _SESSION_TYPES = {"time", "scope"}
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        session_ps = [p for p in policies if p.get("type") in _SESSION_TYPES]
        count = len(session_ps)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"session_policies": [p.get("name") for p in session_ps]})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_aggregate_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1_향상 (다단계): 다단계 접근 정책"""
    MK, TH = "aggregate_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        agg_multi = [
            p for p in policies
            if p.get("type") == "aggregate"
            and len(p.get("associatedPolicies") or []) >= 2
        ]
        single_cond = [p for p in policies if p.get("type") in {"user", "role", "group", "js"}]
        count = len(agg_multi)
        if count >= 1:
            verdict = "충족"
        elif len(single_cond) >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"aggregate_policies": [p.get("name") for p in agg_multi]})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_resource_permission(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1_향상 (리소스별): 리소스별 접근권한 부여"""
    MK, TH = "resource_permission_count", 1.0
    try:
        token = _get_admin_token()
        perms = _get_all_authz_permissions(token)
        resource_perms = [p for p in perms if p.get("resources")]
        count = len(resource_perms)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"resource_permissions": [p.get("name") for p in resource_perms[:20]]})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_custom_roles(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2_초기: 권한 부여 절차 표준화"""
    MK, TH = "custom_role_count", 3.0
    try:
        token = _get_admin_token()
        roles = _api_get(f"/admin/realms/{KEYCLOAK_REALM}/roles", token=token)
        custom = [r for r in roles if not _is_default_role(r.get("name", ""))]
        count = len(custom)
        if count >= 3:
            verdict = "충족"
        elif count >= 1:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"custom_roles": [r.get("name") for r in custom]})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_role_change_events(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2_초기 (권한 변경 관리): 권한 요청 및 변경 관리 시스템"""
    MK, TH = "role_change_event_count", 1.0
    try:
        token = _get_admin_token()
        realm = KEYCLOAK_REALM
        realm_info = _api_get(f"/admin/realms/{realm}", token=token)
        if not realm_info.get("eventsEnabled"):
            return _make_result(item_id, maturity, MK, 0.0, TH, "미충족",
                                {"eventsEnabled": False})
        thirty_days_ms = int(
            (datetime.now(timezone.utc) - timedelta(days=30)).timestamp() * 1000
        )
        events = _api_get(
            f"/admin/realms/{realm}/events",
            params={"type": ["GRANT_CONSENT", "REVOKE_GRANT"], "dateFrom": thirty_days_ms, "max": 100},
            token=token,
        )
        count = len(events) if events else 0
        verdict = "충족" if count >= 1 else "부분충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict, {
            "event_count": count,
            "eventsEnabled": True,
        })
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_rbac_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1_기존: RBAC 기반 접근제어"""
    MK, TH = "rbac_policy_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        rbac = [p for p in policies if p.get("type") == "role"]
        count = len(rbac)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"rbac_policies": [p.get("name") for p in rbac]})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_central_authz_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1_초기 (중앙 집중형): 역할과 권한 기반 중앙 집중형 권한 부여"""
    MK, TH = "central_authz_count", 1.0
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        count = len(policies)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"total_authz_policies": count})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_abac_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1_향상: ABAC 기반 접근제어"""
    MK, TH = "abac_policy_count", 1.0
    _ABAC_TYPES = {"js", "user-attribute", "script"}
    try:
        token = _get_admin_token()
        policies = _get_all_authz_policies(token)
        abac = [p for p in policies if p.get("type") in _ABAC_TYPES]
        count = len(abac)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"abac_policies": [p.get("name") for p in abac]})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_central_authz_ratio(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1_최적화: 모든 접근제어 중앙집중적 실시간 관리"""
    MK, TH = "central_authz_ratio", 0.9
    try:
        token = _get_admin_token()
        clients = _api_get(f"/admin/realms/{KEYCLOAK_REALM}/clients", token=token)
        active = [c for c in clients if c.get("enabled")]
        denom = len(active)
        if denom == 0:
            return _unavailable(item_id, maturity, MK, TH, "활성 클라이언트 없음")
        authz_count = sum(1 for c in active if c.get("authorizationServicesEnabled"))
        ratio = authz_count / denom
        if ratio >= 0.9:
            verdict = "충족"
        elif ratio >= 0.5:
            verdict = "부분충족"
        else:
            verdict = "미충족"
        return _make_result(item_id, maturity, MK, ratio, TH, verdict, {
            "total_active_clients": denom,
            "authz_enabled_count": authz_count,
        })
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_password_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.2.2_기존: 패스워드 기반 인증 방식"""
    MK, TH = "password_policy_set", 1.0
    try:
        token = _get_admin_token()
        realm_info = _api_get(f"/admin/realms/{KEYCLOAK_REALM}", token=token)
        policy = realm_info.get("passwordPolicy", "") or ""
        is_set = bool(policy.strip())
        verdict = "충족" if is_set else "미충족"
        return _make_result(item_id, maturity, MK, 1.0 if is_set else 0.0, TH, verdict,
                            {"passwordPolicy": policy})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_mfa_required_actions(item_id: str, maturity: str) -> CollectedResult:
    """4.2.2_초기 (MFA 안전 인증): MFA 등 보다 안전한 인증 방식"""
    MK, TH = "mfa_action_count", 1.0
    _MFA_KEYWORDS = {"otp", "totp", "webauthn"}
    try:
        token = _get_admin_token()
        actions = _api_get(f"/admin/realms/{KEYCLOAK_REALM}/authentication/required-actions", token=token)
        mfa = [
            a for a in actions
            if a.get("enabled")
            and any(k in (a.get("alias") or "").lower() for k in _MFA_KEYWORDS)
        ]
        count = len(mfa)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"mfa_actions": [a.get("alias") for a in mfa]})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_webauthn_credential_users(item_id: str, maturity: str) -> CollectedResult:
    """4.2.2_향상 (생체 인증): 생체 인증 등 고급 인증 방식 도입"""
    MK, TH = "webauthn_user_count", 1.0
    try:
        token = _get_admin_token()
        realm = KEYCLOAK_REALM
        users = _get_all_users(token)
        humans = _active_human_users(users)
        count = 0
        for u in humans:
            creds = _api_get(f"/admin/realms/{realm}/users/{u['id']}/credentials", token=token)
            if any(c.get("type") == "webauthn" for c in (creds or [])):
                count += 1
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"webauthn_user_count": count})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


def collect_sso_clients(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1_향상 (재인증 없는 이동): 재인증 없는 그룹 간 이동"""
    MK, TH = "sso_client_count", 1.0
    try:
        token = _get_admin_token()
        clients = _api_get(f"/admin/realms/{KEYCLOAK_REALM}/clients", token=token)
        sso = [c for c in clients if c.get("enabled") and c.get("protocol") == "openid-connect"]
        count = len(sso)
        verdict = "충족" if count >= 1 else "미충족"
        return _make_result(item_id, maturity, MK, float(count), TH, verdict,
                            {"sso_clients": [c.get("clientId") for c in sso[:20]]})
    except (TimeoutError, ConnectionError, RuntimeError) as exc:
        return _unavailable(item_id, maturity, MK, TH, str(exc))


# ─────────────────────────── unit tests ───────────────────────────

if __name__ == "__main__":
    import unittest
    from unittest.mock import patch, MagicMock

    _M = "__main__"

    class TestHelpers(unittest.TestCase):
        def test_is_default_role(self):
            self.assertTrue(_is_default_role("default-roles-myrealm"))
            self.assertTrue(_is_default_role("offline_access"))
            self.assertTrue(_is_default_role("uma_authorization"))
            self.assertFalse(_is_default_role("admin"))
            self.assertFalse(_is_default_role("custom-role"))

        def test_active_human_users(self):
            users = [
                {"id": "1", "enabled": True},
                {"id": "2", "enabled": False},
                {"id": "3", "enabled": True, "serviceAccountClientId": "svc"},
            ]
            result = _active_human_users(users)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["id"], "1")

        def test_make_result_keys(self):
            r = _make_result("id", "mat", "key", 0.5, 1.0, "충족", {})
            for k in ("item_id", "maturity", "tool", "result", "metric_key",
                      "metric_value", "threshold", "raw_json", "collected_at", "error"):
                self.assertIn(k, r)
            self.assertEqual(r["tool"], "keycloak")

    class TestUserRoleRatio(unittest.TestCase):
        @patch(f"{_M}._get_user_realm_roles", return_value=[{"name": "custom"}])
        @patch(f"{_M}._get_all_users", return_value=[
            {"id": "u1", "enabled": True}, {"id": "u2", "enabled": True}
        ])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_충족(self, *_):
            r = collect_user_role_ratio("1.1.1", "초기")
            self.assertEqual(r["result"], "충족")
            self.assertAlmostEqual(r["metric_value"], 1.0)

        @patch(f"{_M}._get_user_realm_roles", return_value=[{"name": "default-roles-test"}])
        @patch(f"{_M}._get_all_users", return_value=[{"id": "u1", "enabled": True}])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_미충족_only_default_roles(self, *_):
            r = collect_user_role_ratio("1.1.1", "초기")
            self.assertEqual(r["result"], "미충족")
            self.assertAlmostEqual(r["metric_value"], 0.0)

        @patch(f"{_M}._get_all_users", return_value=[])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_평가불가_no_users(self, *_):
            r = collect_user_role_ratio("1.1.1", "초기")
            self.assertEqual(r["result"], "평가불가")
            self.assertIsNotNone(r["error"])

        @patch(f"{_M}._get_admin_token", side_effect=ConnectionError("연결 실패"))
        def test_평가불가_connection_error(self, *_):
            r = collect_user_role_ratio("1.1.1", "초기")
            self.assertEqual(r["result"], "평가불가")

        @patch(f"{_M}._get_user_realm_roles")
        @patch(f"{_M}._get_all_users")
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_부분충족(self, _, mock_users, mock_roles):
            mock_users.return_value = [{"id": f"u{i}", "enabled": True} for i in range(20)]
            def roles_side(uid, token):
                return [{"name": "custom"}] if int(uid[1:]) < 17 else [{"name": "default-roles-x"}]
            mock_roles.side_effect = roles_side
            r = collect_user_role_ratio("1.1.1", "초기")
            self.assertEqual(r["result"], "부분충족")
            self.assertAlmostEqual(r["metric_value"], 0.85)

    class TestIdpCount(unittest.TestCase):
        @patch(f"{_M}._api_get", return_value=[{"alias": "idp1"}, {"alias": "idp2"}])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_충족(self, *_):
            r = collect_idp_count("1.1.2", "기존")
            self.assertEqual(r["result"], "충족")
            self.assertEqual(r["metric_value"], 2.0)

        @patch(f"{_M}._api_get", return_value=[])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_미충족(self, *_):
            r = collect_idp_count("1.1.2", "기존")
            self.assertEqual(r["result"], "미충족")

    class TestActiveIdpCount(unittest.TestCase):
        @patch(f"{_M}._api_get", return_value=[
            {"alias": "a", "enabled": True}, {"alias": "b", "enabled": True}
        ])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_충족(self, *_):
            r = collect_active_idp_count("1.1.2", "초기")
            self.assertEqual(r["result"], "충족")

        @patch(f"{_M}._api_get", return_value=[{"alias": "a", "enabled": True}])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_부분충족(self, *_):
            r = collect_active_idp_count("1.1.2", "초기")
            self.assertEqual(r["result"], "부분충족")

        @patch(f"{_M}._api_get", return_value=[{"alias": "a", "enabled": False}])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_미충족(self, *_):
            r = collect_active_idp_count("1.1.2", "초기")
            self.assertEqual(r["result"], "미충족")

    class TestMfaRequired(unittest.TestCase):
        @patch(f"{_M}._flows_with_executions", return_value=[{
            "flow": {"alias": "browser"},
            "executions": [{"providerId": "auth-otp-form", "requirement": "REQUIRED"}],
        }])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_충족(self, *_):
            r = collect_mfa_required("1.2.1", "기존")
            self.assertEqual(r["result"], "충족")

        @patch(f"{_M}._flows_with_executions", return_value=[{
            "flow": {"alias": "browser"},
            "executions": [{"providerId": "auth-otp-form", "requirement": "OPTIONAL"}],
        }])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_부분충족(self, *_):
            r = collect_mfa_required("1.2.1", "기존")
            self.assertEqual(r["result"], "부분충족")

        @patch(f"{_M}._flows_with_executions", return_value=[{
            "flow": {"alias": "browser"},
            "executions": [{"providerId": "auth-username-password-form", "requirement": "REQUIRED"}],
        }])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_미충족_no_mfa(self, *_):
            r = collect_mfa_required("1.2.1", "기존")
            self.assertEqual(r["result"], "미충족")

    class TestWebauthnStatus(unittest.TestCase):
        @patch(f"{_M}._api_get", return_value=[
            {"alias": "webauthn-register", "enabled": True}
        ])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_충족(self, *_):
            r = collect_webauthn_status("1.2.1", "초기")
            self.assertEqual(r["result"], "충족")

        @patch(f"{_M}._api_get", return_value=[
            {"alias": "webauthn-register", "enabled": False}
        ])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_부분충족(self, *_):
            r = collect_webauthn_status("1.2.1", "초기")
            self.assertEqual(r["result"], "부분충족")

        @patch(f"{_M}._api_get", return_value=[
            {"alias": "CONFIGURE_TOTP", "enabled": True}
        ])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_미충족(self, *_):
            r = collect_webauthn_status("1.2.1", "초기")
            self.assertEqual(r["result"], "미충족")

    class TestSessionPolicy(unittest.TestCase):
        @patch(f"{_M}._api_get", return_value={
            "ssoSessionIdleTimeout": 1800, "ssoSessionMaxLifespan": 36000
        })
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_충족(self, *_):
            r = collect_session_policy("1.2.2", "기존")
            self.assertEqual(r["result"], "충족")

        @patch(f"{_M}._api_get", return_value={
            "ssoSessionIdleTimeout": 1800, "ssoSessionMaxLifespan": 0
        })
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_부분충족(self, *_):
            r = collect_session_policy("1.2.2", "기존")
            self.assertEqual(r["result"], "부분충족")

        @patch(f"{_M}._api_get", return_value={
            "ssoSessionIdleTimeout": 0, "ssoSessionMaxLifespan": 0
        })
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_미충족(self, *_):
            r = collect_session_policy("1.2.2", "기존")
            self.assertEqual(r["result"], "미충족")

    class TestRealmCount(unittest.TestCase):
        @patch(f"{_M}._api_get", return_value=[
            {"realm": "master", "enabled": True},
            {"realm": "myrealm", "enabled": True},
        ])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_충족(self, *_):
            r = collect_realm_count("1.3.1", "기존")
            self.assertEqual(r["result"], "충족")
            self.assertEqual(r["metric_value"], 1.0)

        @patch(f"{_M}._api_get", return_value=[{"realm": "master", "enabled": True}])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_부분충족_only_master(self, *_):
            r = collect_realm_count("1.3.1", "기존")
            self.assertEqual(r["result"], "부분충족")

    class TestCustomAuthFlow(unittest.TestCase):
        @patch(f"{_M}._api_get", return_value=[
            {"alias": "my-browser", "builtIn": False},
            {"alias": "browser", "builtIn": True},
        ])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_충족(self, *_):
            r = collect_custom_auth_flow("1.3.1", "초기")
            self.assertEqual(r["result"], "충족")

        @patch(f"{_M}._api_get", return_value=[{"alias": "browser", "builtIn": True}])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_미충족(self, *_):
            r = collect_custom_auth_flow("1.3.1", "초기")
            self.assertEqual(r["result"], "미충족")

    class TestCustomRoles(unittest.TestCase):
        @patch(f"{_M}._api_get", return_value=[
            {"name": "admin"}, {"name": "editor"}, {"name": "viewer"},
            {"name": "offline_access"}, {"name": "default-roles-realm"},
        ])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_충족(self, *_):
            r = collect_custom_roles("1.4.2", "초기")
            self.assertEqual(r["result"], "충족")
            self.assertEqual(r["metric_value"], 3.0)

        @patch(f"{_M}._api_get", return_value=[
            {"name": "admin"}, {"name": "offline_access"}
        ])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_부분충족(self, *_):
            r = collect_custom_roles("1.4.2", "초기")
            self.assertEqual(r["result"], "부분충족")

    class TestPasswordPolicy(unittest.TestCase):
        @patch(f"{_M}._api_get", return_value={"passwordPolicy": "length(8) and upperCase(1)"})
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_충족(self, *_):
            r = collect_password_policy("4.2.2", "기존")
            self.assertEqual(r["result"], "충족")
            self.assertEqual(r["metric_value"], 1.0)

        @patch(f"{_M}._api_get", return_value={"passwordPolicy": ""})
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_미충족(self, *_):
            r = collect_password_policy("4.2.2", "기존")
            self.assertEqual(r["result"], "미충족")

    class TestCentralAuthzRatio(unittest.TestCase):
        @patch(f"{_M}._api_get", return_value=[
            {"enabled": True, "authorizationServicesEnabled": True},
            {"enabled": True, "authorizationServicesEnabled": True},
            {"enabled": True, "authorizationServicesEnabled": False},
        ])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_부분충족(self, *_):
            r = collect_central_authz_ratio("4.1.1", "최적화")
            # 2/3 ≈ 0.667 → 부분충족
            self.assertEqual(r["result"], "부분충족")

        @patch(f"{_M}._api_get", return_value=[])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_평가불가_no_clients(self, *_):
            r = collect_central_authz_ratio("4.1.1", "최적화")
            self.assertEqual(r["result"], "평가불가")

    class TestRoleChangeEvents(unittest.TestCase):
        @patch(f"{_M}._api_get")
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_미충족_events_disabled(self, _, mock_api):
            mock_api.return_value = {"eventsEnabled": False}
            r = collect_role_change_events("1.4.2", "초기")
            self.assertEqual(r["result"], "미충족")

        @patch(f"{_M}._api_get")
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_충족_with_events(self, _, mock_api):
            def side(path, params=None, token=None):
                if path.endswith(f"/{KEYCLOAK_REALM}"):
                    return {"eventsEnabled": True}
                return [{"type": "GRANT_CONSENT", "userId": "u1", "time": 1234567890}]
            mock_api.side_effect = side
            r = collect_role_change_events("1.4.2", "초기")
            self.assertEqual(r["result"], "충족")

    class TestSsoClients(unittest.TestCase):
        @patch(f"{_M}._api_get", return_value=[
            {"clientId": "app1", "enabled": True, "protocol": "openid-connect"},
            {"clientId": "app2", "enabled": True, "protocol": "saml"},
        ])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_충족(self, *_):
            r = collect_sso_clients("4.3.1", "향상")
            self.assertEqual(r["result"], "충족")
            self.assertEqual(r["metric_value"], 1.0)

        @patch(f"{_M}._api_get", return_value=[
            {"clientId": "app1", "enabled": False, "protocol": "openid-connect"}
        ])
        @patch(f"{_M}._get_admin_token", return_value="tok")
        def test_미충족_disabled(self, *_):
            r = collect_sso_clients("4.3.1", "향상")
            self.assertEqual(r["result"], "미충족")

    class TestApiGetRetry(unittest.TestCase):
        @patch("requests.get")
        @patch(f"{_M}._get_admin_token", return_value="new_tok")
        def test_401_refreshes_token(self, mock_token, mock_get):
            r401 = MagicMock()
            r401.status_code = 401
            r200 = MagicMock()
            r200.status_code = 200
            r200.json.return_value = {"ok": True}
            mock_get.side_effect = [r401, r200]
            result = _api_get("/test/path", token="old_tok")
            self.assertEqual(result, {"ok": True})
            self.assertEqual(mock_token.call_count, 1)

        @patch("requests.get")
        def test_timeout_raises(self, mock_get):
            import requests as req
            mock_get.side_effect = req.exceptions.Timeout()
            with self.assertRaises(TimeoutError):
                _api_get("/test/path", token="tok")

        @patch("requests.get")
        def test_connection_error_raises(self, mock_get):
            import requests as req
            mock_get.side_effect = req.exceptions.ConnectionError("refused")
            with self.assertRaises(ConnectionError):
                _api_get("/test/path", token="tok")

    unittest.main(verbosity=2)
