"""okta_collector.py — Okta Identity Cloud 진단 함수 (Phase A: 15개)

entra_collector.py 와 동일한 추상을 가진 모듈. Okta REST API v1 을 사용한다.
인증: SSWS API token (Authorization: SSWS <token>).

item_id 체계: {항목번호}.{성숙도번호}_{질문번호} — keycloak/entra 와 동일하므로
dispatcher 자동매핑(_autodiscover)에서 docstring 첫 줄로 자동 추출된다.
"""
from typing import Optional, Any, Tuple
from datetime import datetime, timezone
import os
import logging

import httpx

CollectedResult = dict
logger = logging.getLogger(__name__)

# fallback 환경변수 — 사용자가 NewAssessment에서 자격을 직접 입력하지 않은 경우 사용
OKTA_DOMAIN    = os.environ.get("OKTA_DOMAIN", "")
OKTA_API_TOKEN = os.environ.get("OKTA_API_TOKEN", "")

# ─── session-scoped credential override ──────────────────────────────────────
# 사용자가 NewAssessment에서 입력한 IdP 자격을 _run_collectors에서 주입한다.
_session_creds: Optional[dict] = None


def set_session_creds(creds: Optional[dict]) -> None:
    """세션 단위 Okta 자격을 모듈 전역에 주입. None 이면 해제."""
    global _session_creds
    _session_creds = creds or None


def _okta_domain() -> str:
    if _session_creds and _session_creds.get("domain"):
        return str(_session_creds["domain"]).strip()
    return OKTA_DOMAIN.strip()


def _okta_token() -> str:
    if _session_creds and _session_creds.get("api_token"):
        return str(_session_creds["api_token"])
    return OKTA_API_TOKEN


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
        "tool":         "okta",
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


def _base_url() -> Optional[str]:
    dom = _okta_domain()
    if not dom:
        return None
    # 사용자가 https://...을 통째로 넣었어도 처리
    if dom.startswith("http://") or dom.startswith("https://"):
        return dom.rstrip("/")
    return f"https://{dom}".rstrip("/")


def _okta_get(path: str, params: dict = None, timeout: int = 30) -> Tuple[Optional[Any], Optional[str]]:
    """Okta API GET. (data, error) 튜플 반환. data 가 None 이면 error 존재."""
    base = _base_url()
    token = _okta_token()
    if not base:
        return None, "Okta 미연결: domain 미설정"
    if not token:
        return None, "Okta 미연결: api_token 미설정"
    url = f"{base}/api/v1{path}"
    try:
        resp = httpx.get(
            url,
            headers={
                "Authorization": f"SSWS {token}",
                "Accept": "application/json",
            },
            params=params or {},
            timeout=timeout,
        )
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"

    if resp.status_code == 401:
        return None, "Okta 인증 실패: api_token 확인 필요"
    if resp.status_code == 403:
        return None, "Okta 권한 부족: 토큰 scope 부족"
    try:
        body = resp.json()
    except Exception:
        body = None
    if 400 <= resp.status_code:
        msg = ""
        if isinstance(body, dict):
            msg = body.get("errorSummary") or body.get("errorCode") or ""
        return None, f"Okta API 오류: HTTP {resp.status_code} {msg}".strip()
    return body, None


def _okta_count(path: str, params: dict = None) -> Tuple[Optional[int], Optional[str], Any]:
    data, err = _okta_get(path, params)
    if err:
        return None, err, data
    if isinstance(data, list):
        return len(data), None, data
    return 0, None, data


# ─────────────────────────── collectors (15) ───────────────────────────

def collect_user_role_ratio(item_id: str, maturity: str) -> CollectedResult:
    """1.1.1.2_1: 역할(=admin role) 보유 사용자 비율 ≥ 95% → 충족 / 80~95% → 부분충족"""
    MK, TH = "user_role_ratio", 0.95
    users_data, err = _okta_get("/users", {"limit": 200})
    if err:
        return _err(item_id, maturity, MK, TH, err, {"raw": users_data})
    users = users_data if isinstance(users_data, list) else []
    if not users:
        return _err(item_id, maturity, MK, TH, "활성 사용자(분모)가 0", {})

    # admin role 부여된 사용자 ID 집합 수집
    # /iam/assignees/users 가 1차 선택지지만 권한이 까다로워 /users/{id}/roles 접근 가능한
    # 표본 200명에 대해 role 조회 (대규모 org 는 _userRoleSampleLimit 로 절단).
    sample = users[:200]
    with_role = 0
    inspected = 0
    last_err = None
    for u in sample:
        uid = u.get("id")
        if not uid:
            continue
        inspected += 1
        roles, rerr = _okta_get(f"/users/{uid}/roles")
        if rerr:
            last_err = rerr
            continue
        if isinstance(roles, list) and len(roles) > 0:
            with_role += 1
    total = inspected if inspected else len(users)
    ratio = (with_role / total) if total else 0.0
    if ratio >= TH:
        verdict = "충족"
    elif ratio >= 0.8:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, ratio, TH,
               {"total_sampled": total, "with_role": with_role, "users_total": len(users),
                "last_role_err": last_err})


def collect_idp_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.1.1.3_1: 외부 IdP 등록 수(/idps) ≥ 1 → 충족"""
    MK, TH = "external_idp_count", 1.0
    count, err, _ = _okta_count("/idps")
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (count or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count or 0), TH,
               {"external_idp_count": count})


def collect_idp_registered(item_id: str, maturity: str) -> CollectedResult:
    """1.1.2.1_1: Okta 도메인 응답 가능하면 1(=IdP 등록) → 충족"""
    MK, TH = "idp_domain_registered", 1.0
    # 가벼운 ping: /users?limit=1
    data, err = _okta_get("/users", {"limit": 1})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    return _ok(item_id, maturity, "충족", MK, 1.0, TH,
               {"domain": _okta_domain(), "ping_ok": True})


def collect_active_idp_multi(item_id: str, maturity: str) -> CollectedResult:
    """1.1.2.2_1: 다중 IdP(/idps) ≥ 2 → 충족 / 1 → 부분충족"""
    MK, TH = "active_idp_count", 2.0
    data, err = _okta_get("/idps")
    if err:
        return _err(item_id, maturity, MK, TH, err)
    count = len(data) if isinstance(data, list) else 0
    if count >= TH:
        verdict = "충족"
    elif count == 1:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"idp_count": count})


def collect_mfa_required(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.1_1: 활성 MFA_ENROLL 정책 ≥ 1 → 충족"""
    MK, TH = "mfa_enroll_policies", 1.0
    data, err = _okta_get("/policies", {"type": "MFA_ENROLL"})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    policies = data if isinstance(data, list) else []
    active = sum(1 for p in policies if str(p.get("status") or "").upper() == "ACTIVE")
    verdict = "충족" if active >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(active), TH,
               {"active_mfa_enroll_policies": active, "total_mfa_enroll_policies": len(policies)})


def collect_otp_flow(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.2_1: OTP factor(google_authenticator/okta_verify) 활성 ≥ 1 → 충족"""
    MK, TH = "otp_factor_count", 1.0
    # /org/factors 가 표준 엔드포인트 (org-wide factor enablement)
    data, err = _okta_get("/org/factors")
    if err:
        # fallback — policy rule 안의 enrollFactors 검사
        pdata, perr = _okta_get("/policies", {"type": "MFA_ENROLL"})
        if perr:
            return _err(item_id, maturity, MK, TH, err)
        policies = pdata if isinstance(pdata, list) else []
        otp_in_policy = 0
        for p in policies:
            settings = (p.get("settings") or {}).get("factors") or {}
            for fid in ("google_otp", "okta_otp"):
                if str((settings.get(fid) or {}).get("enroll", {}).get("self") or "").upper() == "REQUIRED":
                    otp_in_policy += 1
                    break
        verdict = "충족" if otp_in_policy >= TH else "미충족"
        return _ok(item_id, maturity, verdict, MK, float(otp_in_policy), TH,
                   {"source": "policy_factors", "otp_policies": otp_in_policy})
    factors = data if isinstance(data, list) else []
    targets = {"google_otp", "okta_otp"}
    active = sum(
        1 for f in factors
        if str(f.get("provider") or "").lower() in {"google", "okta"}
        and str(f.get("factorType") or "").lower() == "token:software:totp"
        and str(f.get("status") or "").upper() == "ACTIVE"
    )
    # 보조 매칭: id 기반
    if active == 0:
        active = sum(
            1 for f in factors
            if str(f.get("id") or "").lower() in targets
            and str(f.get("status") or "").upper() == "ACTIVE"
        )
    verdict = "충족" if active >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(active), TH,
               {"source": "org_factors", "otp_active": active, "factors_total": len(factors)})


def collect_webauthn_status(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.2_2: WebAuthn(FIDO2) factor 활성 → 충족"""
    MK, TH = "webauthn_active", 1.0
    data, err = _okta_get("/org/factors")
    if err:
        return _err(item_id, maturity, MK, TH, err)
    factors = data if isinstance(data, list) else []
    active = sum(
        1 for f in factors
        if (str(f.get("factorType") or "").lower() == "webauthn"
            or str(f.get("provider") or "").lower() == "fido")
        and str(f.get("status") or "").upper() == "ACTIVE"
    )
    verdict = "충족" if active >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(active), TH,
               {"webauthn_active": active})


def collect_conditional_auth(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.3_1: 활성 Access(Sign-on) 정책 ≥ 1 → 충족"""
    MK, TH = "access_policies_active", 1.0
    data, err = _okta_get("/policies", {"type": "ACCESS_POLICY"})
    if err:
        # 구버전 OKTA_SIGN_ON 도 시도
        data2, err2 = _okta_get("/policies", {"type": "OKTA_SIGN_ON"})
        if err2:
            return _err(item_id, maturity, MK, TH, err)
        data = data2
    policies = data if isinstance(data, list) else []
    active = sum(1 for p in policies if str(p.get("status") or "").upper() == "ACTIVE")
    verdict = "충족" if active >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(active), TH,
               {"active_access_policies": active})


def collect_session_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.2.2.1_1: Sign-on 정책 rule 에 session lifetime 지정 ≥ 1 → 충족"""
    MK, TH = "session_lifetime_rules", 1.0
    pol, err = _okta_get("/policies", {"type": "OKTA_SIGN_ON"})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    policies = pol if isinstance(pol, list) else []
    rules_with_session = 0
    for p in policies:
        pid = p.get("id")
        if not pid:
            continue
        rules, rerr = _okta_get(f"/policies/{pid}/rules")
        if rerr or not isinstance(rules, list):
            continue
        for rule in rules:
            actions = (rule.get("actions") or {}).get("signon") or {}
            sess = actions.get("session") or {}
            if sess.get("maxSessionLifetimeMinutes") or sess.get("maxSessionIdleMinutes"):
                rules_with_session += 1
    verdict = "충족" if rules_with_session >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(rules_with_session), TH,
               {"session_lifetime_rules": rules_with_session, "policies_inspected": len(policies)})


def collect_stepup_auth(item_id: str, maturity: str) -> CollectedResult:
    """1.2.2.2_1: sign-on rule 에 MFA(step-up) 요구 ≥ 1 → 충족"""
    MK, TH = "stepup_mfa_rules", 1.0
    pol, err = _okta_get("/policies", {"type": "OKTA_SIGN_ON"})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    policies = pol if isinstance(pol, list) else []
    mfa_rules = 0
    for p in policies:
        pid = p.get("id")
        if not pid:
            continue
        rules, rerr = _okta_get(f"/policies/{pid}/rules")
        if rerr or not isinstance(rules, list):
            continue
        for rule in rules:
            signon = (rule.get("actions") or {}).get("signon") or {}
            if str(signon.get("requireFactor") or "").lower() == "true" or signon.get("factorPromptMode"):
                mfa_rules += 1
    verdict = "충족" if mfa_rules >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(mfa_rules), TH,
               {"stepup_mfa_rules": mfa_rules})


def collect_realm_count(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1.1_1: Okta org 단일 — domain 응답 OK 면 1 → 충족"""
    MK, TH = "realm_count", 1.0
    data, err = _okta_get("/org")  # 응답 안되면 /users 로 fallback
    if err:
        data2, err2 = _okta_get("/users", {"limit": 1})
        if err2:
            return _err(item_id, maturity, MK, TH, err)
    return _ok(item_id, maturity, "충족", MK, 1.0, TH,
               {"realm_count": 1, "note": "Okta org 단일 모델"})


def collect_icam_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1.2_1: SSO 앱(/apps) 등록 수 ≥ 1 → 충족"""
    MK, TH = "app_count", 1.0
    count, err, _ = _okta_count("/apps", {"limit": 200})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (count or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count or 0), TH,
               {"app_count": count})


def collect_authz_clients(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.1_3: /apps 등록된 SSO/OAuth 클라이언트 수 ≥ 1 → 충족"""
    MK, TH = "authz_client_count", 1.0
    data, err = _okta_get("/apps", {"limit": 200})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    apps = data if isinstance(data, list) else []
    # OAuth/OIDC sign-on mode 만 별도 카운트 (전체 앱은 metric 으로 노출)
    oauth_count = sum(
        1 for a in apps
        if str(a.get("signOnMode") or "").upper() in {"OPENID_CONNECT", "OAUTH2"}
    )
    total = len(apps)
    verdict = "충족" if total >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total), TH,
               {"apps_total": total, "oauth_apps": oauth_count})


def collect_rbac_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.2_1: 빌트인 그룹(role 매핑 기준 그룹) ≥ 1 → 충족"""
    MK, TH = "rbac_groups", 1.0
    data, err = _okta_get("/groups", {"filter": "type eq \"BUILT_IN\""})
    if err:
        # 필터 비지원 환경 → 전체 그룹 중 BUILT_IN 카운트
        data2, err2 = _okta_get("/groups", {"limit": 200})
        if err2:
            return _err(item_id, maturity, MK, TH, err)
        groups = data2 if isinstance(data2, list) else []
        count = sum(1 for g in groups if str(g.get("type") or "").upper() == "BUILT_IN")
    else:
        groups = data if isinstance(data, list) else []
        count = len(groups)
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"builtin_groups": count})


def collect_password_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.2_1: PASSWORD 정책 minLength ≥ 8 및 complexity 설정 → 충족"""
    MK, TH = "password_policy_score", 1.0
    data, err = _okta_get("/policies", {"type": "PASSWORD"})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    policies = data if isinstance(data, list) else []
    if not policies:
        return _ok(item_id, maturity, "미충족", MK, 0.0, TH, {"policy_count": 0})
    # 각 정책의 complexity 충족 비율: minLength≥8 + minLowerCase/UpperCase/Number 중 2개 이상.
    met = 0
    for p in policies:
        if str(p.get("status") or "").upper() != "ACTIVE":
            continue
        compl = ((p.get("settings") or {}).get("password") or {}).get("complexity") or {}
        ml = int(compl.get("minLength") or 0)
        flags = sum(int(bool(compl.get(k))) for k in ("minLowerCase", "minUpperCase", "minNumber", "minSymbol"))
        if ml >= 8 and flags >= 2:
            met += 1
    ratio = (met / len(policies)) if policies else 0.0
    if ratio >= 1.0:
        verdict = "충족"
    elif ratio > 0:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, ratio, TH,
               {"policies_total": len(policies), "policies_met": met})
