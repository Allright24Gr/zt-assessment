"""supabase_collector.py — Supabase (Auth/Database/Storage) 기반 진단 모듈

T-Markov 같은 Supabase-backed 시스템을 위해 Keycloak 자리에서 IdP/Auth/Data
항목을 자동 진단한다. assessment.py 의 _resolve_supported_tools 가
profile_select.idp_type='supabase' 일 때 이 collector 를 활성화한다.

자격:
  - Management API PAT (sbp_...) : 권장. RLS dump, Auth config, 사용자 목록 등 전부 가능.
  - service_role key (JWT)      : 대안. RPC/REST 풀 권한.
  - anon key (JWT)              : 제한적. /auth/v1/settings 공개 endpoint 만.

세션 단위 자격 주입: set_session_creds({"project_ref": "...", "pat": "...",
"service_role": "...", "anon_key": "..."})
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
import os

import httpx

CollectedResult = dict

# ─── env fallback ────────────────────────────────────────────────────────────
SUPABASE_PROJECT_REF = os.environ.get("SUPABASE_PROJECT_REF", "")
SUPABASE_MGMT_PAT    = os.environ.get("SUPABASE_MGMT_PAT", "")
SUPABASE_SERVICE_ROLE = os.environ.get("SUPABASE_SERVICE_ROLE", "")
SUPABASE_ANON_KEY    = os.environ.get("SUPABASE_ANON_KEY", "")

_TIMEOUT = 8.0
MGMT_BASE = "https://api.supabase.com/v1"

# ─── session creds 주입 ──────────────────────────────────────────────────────
_session_creds: Optional[dict] = None


def set_session_creds(creds: Optional[dict]) -> None:
    """세션 단위 Supabase 자격을 모듈 전역에 주입. None 이면 해제."""
    global _session_creds
    _session_creds = creds or None


def _get_project_ref() -> str:
    if _session_creds and _session_creds.get("project_ref"):
        return str(_session_creds["project_ref"]).strip()
    return SUPABASE_PROJECT_REF


def _get_pat() -> str:
    if _session_creds and _session_creds.get("pat"):
        return str(_session_creds["pat"]).strip()
    return SUPABASE_MGMT_PAT


def _get_service_role() -> str:
    if _session_creds and _session_creds.get("service_role"):
        return str(_session_creds["service_role"]).strip()
    return SUPABASE_SERVICE_ROLE


def _get_anon_key() -> str:
    if _session_creds and _session_creds.get("anon_key"):
        return str(_session_creds["anon_key"]).strip()
    return SUPABASE_ANON_KEY


def _project_url() -> str:
    ref = _get_project_ref()
    if not ref:
        return ""
    return f"https://{ref}.supabase.co"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─── 결과 표준 포맷 ──────────────────────────────────────────────────────────

def _result(item_id: str, maturity: str, metric_key: str, metric_value: float,
            threshold: float, verdict: str, raw: dict,
            error: Optional[str] = None) -> CollectedResult:
    return {
        "item_id": item_id,
        "maturity": maturity,
        "tool": "supabase",
        "result": verdict,
        "metric_key": metric_key,
        "metric_value": float(metric_value),
        "threshold": float(threshold),
        "raw_json": raw,
        "collected_at": _now_iso(),
        "error": error,
    }


def _unavailable(item_id: str, maturity: str, metric_key: str, threshold: float,
                 error_msg: str, raw: Optional[dict] = None) -> CollectedResult:
    return _result(item_id, maturity, metric_key, 0.0, threshold,
                   "평가불가", raw or {}, error_msg)


# ─── Management API helpers ──────────────────────────────────────────────────

def _mgmt_get(path: str, timeout: float = _TIMEOUT) -> tuple[Any, Optional[str]]:
    pat = _get_pat()
    if not pat:
        return None, "Supabase Management PAT 미설정"
    try:
        resp = httpx.get(
            f"{MGMT_BASE}{path}",
            headers={"Authorization": f"Bearer {pat}", "Accept": "application/json"},
            timeout=timeout,
        )
        if resp.status_code in (401, 403):
            return None, f"권한 부족: HTTP {resp.status_code}"
        if resp.status_code >= 400:
            return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
        return resp.json(), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _auth_settings(timeout: float = _TIMEOUT) -> tuple[dict, Optional[str]]:
    """GET <project>/auth/v1/settings — anon key 로도 접근 가능한 공개 설정."""
    base = _project_url()
    if not base:
        return {}, "Supabase project_ref 미설정"
    anon = _get_anon_key() or _get_service_role()
    if not anon:
        return {}, "Supabase anon/service key 미설정"
    try:
        resp = httpx.get(
            f"{base}/auth/v1/settings",
            headers={"apikey": anon, "Authorization": f"Bearer {anon}"},
            timeout=timeout,
        )
        if resp.status_code >= 400:
            return {}, f"HTTP {resp.status_code}: {resp.text[:200]}"
        return resp.json() or {}, None
    except Exception as exc:
        return {}, f"{type(exc).__name__}: {exc}"


def _auth_config(timeout: float = _TIMEOUT) -> tuple[dict, Optional[str]]:
    """Management API: GET /projects/{ref}/config/auth — 전체 auth config dump."""
    ref = _get_project_ref()
    if not ref:
        return {}, "project_ref 미설정"
    data, err = _mgmt_get(f"/projects/{ref}/config/auth", timeout=timeout)
    if err:
        return {}, err
    return data or {}, None


def _list_users(timeout: float = _TIMEOUT, per_page: int = 200) -> tuple[list, Optional[str]]:
    """Admin Auth API: GET <project>/auth/v1/admin/users — service_role 필요."""
    base = _project_url()
    if not base:
        return [], "project_ref 미설정"
    key = _get_service_role()
    if not key:
        return [], "service_role key 미설정"
    try:
        resp = httpx.get(
            f"{base}/auth/v1/admin/users",
            headers={"apikey": key, "Authorization": f"Bearer {key}"},
            params={"per_page": per_page},
            timeout=timeout,
        )
        if resp.status_code >= 400:
            return [], f"HTTP {resp.status_code}: {resp.text[:200]}"
        data = resp.json() or {}
        return data.get("users", []) or [], None
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"


def _rls_policies(timeout: float = _TIMEOUT) -> tuple[list, Optional[str]]:
    """Management DB API: pg_policies 조회 (PG REST 메타)."""
    ref = _get_project_ref()
    if not ref:
        return [], "project_ref 미설정"
    # /v1/projects/{ref}/database/query — POST SQL
    pat = _get_pat()
    if not pat:
        return [], "Management PAT 미설정"
    try:
        resp = httpx.post(
            f"{MGMT_BASE}/projects/{ref}/database/query",
            headers={"Authorization": f"Bearer {pat}", "Accept": "application/json"},
            json={"query": "SELECT schemaname, tablename, policyname, cmd, qual FROM pg_policies;"},
            timeout=timeout,
        )
        if resp.status_code >= 400:
            return [], f"HTTP {resp.status_code}: {resp.text[:200]}"
        data = resp.json()
        if isinstance(data, list):
            return data, None
        return [], None
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"


def _tables(timeout: float = _TIMEOUT) -> tuple[list, Optional[str]]:
    ref = _get_project_ref()
    if not ref:
        return [], "project_ref 미설정"
    pat = _get_pat()
    if not pat:
        return [], "Management PAT 미설정"
    try:
        resp = httpx.post(
            f"{MGMT_BASE}/projects/{ref}/database/query",
            headers={"Authorization": f"Bearer {pat}"},
            json={"query": "SELECT schemaname, tablename, rowsecurity FROM pg_tables WHERE schemaname IN ('public','auth');"},
            timeout=timeout,
        )
        if resp.status_code >= 400:
            return [], f"HTTP {resp.status_code}: {resp.text[:200]}"
        data = resp.json()
        return data if isinstance(data, list) else [], None
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"


# ─────────────────────────────────────────────────────────────────────────────
# Collector functions — item_id 는 Keycloak 매핑과 동일(다중 매핑). IdP 카테고리.
# profile_select.idp_type='supabase' 일 때만 _resolve_supported_tools 가 활성화.
# ─────────────────────────────────────────────────────────────────────────────


def collect_user_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.1.1.2_1: Supabase 활성 사용자 수 ≥ 1 → 충족."""
    MK, TH = "active_user_count", 1.0
    users, err = _list_users()
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    active = [u for u in users if not u.get("banned_until")]
    count = float(len(active))
    verdict = "충족" if count >= TH else "미충족"
    return _result(item_id, maturity, MK, count, TH, verdict,
                   {"total": len(users), "active": len(active)})


def collect_idp_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.1.1.3_1: 외부 IdP 등록 수 (OAuth providers enabled) ≥ 1 → 충족."""
    MK, TH = "external_idp_count", 1.0
    settings, err = _auth_settings()
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    external = settings.get("external") or {}
    enabled = [k for k, v in external.items()
               if isinstance(v, bool) and v]
    count = float(len(enabled))
    verdict = "충족" if count >= TH else "미충족"
    return _result(item_id, maturity, MK, count, TH, verdict,
                   {"enabled_providers": enabled, "all": list(external.keys())})


def collect_idp_registered(item_id: str, maturity: str) -> CollectedResult:
    """1.1.2.1_1: Supabase Auth 활성 여부 (signup 가능 또는 외부 provider)."""
    MK, TH = "auth_active", 1.0
    settings, err = _auth_settings()
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    disable_signup = bool(settings.get("disable_signup"))
    external = settings.get("external") or {}
    has_provider = any(v for v in external.values() if isinstance(v, bool))
    active = 1.0 if (not disable_signup or has_provider) else 0.0
    verdict = "충족" if active >= TH else "미충족"
    return _result(item_id, maturity, MK, active, TH, verdict,
                   {"disable_signup": disable_signup, "has_external": has_provider})


def collect_active_idp_multi(item_id: str, maturity: str) -> CollectedResult:
    """1.1.2.2_1: 활성 IdP/Provider 수 ≥ 2 → 충족."""
    MK, TH = "active_provider_count", 2.0
    settings, err = _auth_settings()
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    external = settings.get("external") or {}
    enabled = [k for k, v in external.items() if isinstance(v, bool) and v]
    # 이메일+외부 1개 = 2개로 카운트
    count = float(len(enabled) + (1 if settings.get("external_email_enabled") else 0))
    if count >= TH:
        verdict = "충족"
    elif count == 1:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _result(item_id, maturity, MK, count, TH, verdict,
                   {"providers": enabled, "email_enabled": settings.get("external_email_enabled")})


def collect_mfa_required(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.1_1: MFA 활성 여부 (mfa_enabled or totp_enabled) → 충족."""
    MK, TH = "mfa_enabled", 1.0
    settings, err = _auth_settings()
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    mfa = bool(settings.get("mfa_enabled")) or bool(
        (settings.get("mfa") or {}).get("totp", {}).get("enroll_enabled")
    )
    verdict = "충족" if mfa else "미충족"
    return _result(item_id, maturity, MK, 1.0 if mfa else 0.0, TH, verdict,
                   {"mfa_settings": settings.get("mfa"), "mfa_enabled": settings.get("mfa_enabled")})


def collect_otp_flow(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.2_1: OTP/이메일 인증 흐름 활성 → 충족."""
    MK, TH = "otp_flow_enabled", 1.0
    settings, err = _auth_settings()
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    otp = bool(settings.get("external_email_enabled") or settings.get("external_phone_enabled"))
    verdict = "충족" if otp else "미충족"
    return _result(item_id, maturity, MK, 1.0 if otp else 0.0, TH, verdict,
                   {"email": settings.get("external_email_enabled"),
                    "phone": settings.get("external_phone_enabled")})


def collect_webauthn_status(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.2_2: WebAuthn factor 활성 여부 → 충족."""
    MK, TH = "webauthn_enabled", 1.0
    cfg, err = _auth_config()
    if err:
        # anon으로는 webauthn 세부설정 못 봄 → 평가불가
        return _unavailable(item_id, maturity, MK, TH, err)
    mfa = cfg.get("mfa") if isinstance(cfg.get("mfa"), dict) else {}
    enabled = bool(mfa.get("webauthn_enabled") or mfa.get("phone_enroll_enabled"))
    verdict = "충족" if enabled else "미충족"
    return _result(item_id, maturity, MK, 1.0 if enabled else 0.0, TH, verdict,
                   {"mfa_config": mfa})


def collect_session_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.2.2.1_1: JWT 세션 만료 시간 ≤ 3600초 → 충족."""
    MK, TH = "jwt_exp_seconds", 3600.0
    cfg, err = _auth_config()
    if err:
        # /auth/v1/settings 에서 폴백
        settings, serr = _auth_settings()
        if serr:
            return _unavailable(item_id, maturity, MK, TH, err)
        exp = settings.get("jwt_exp") or 3600
    else:
        exp = cfg.get("jwt_exp") or 3600
    exp_val = float(exp)
    verdict = "충족" if exp_val <= TH else "부분충족" if exp_val <= 7200 else "미충족"
    return _result(item_id, maturity, MK, exp_val, TH, verdict, {"jwt_exp": exp_val})


def collect_password_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.2_1: 비밀번호 정책 (min length ≥ 8, 영문+숫자) → 충족."""
    MK, TH = "password_min_length", 8.0
    cfg, err = _auth_config()
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    pw = cfg.get("password") if isinstance(cfg.get("password"), dict) else {}
    min_len = float(pw.get("min_length") or cfg.get("password_min_length") or 0)
    requirements = pw.get("required_characters") or ""
    has_complex = bool(requirements)
    if min_len >= TH and has_complex:
        verdict = "충족"
    elif min_len >= TH or has_complex:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _result(item_id, maturity, MK, min_len, TH, verdict,
                   {"min_length": min_len, "requirements": requirements})


def collect_rbac_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.2_1: 사용자 role/raw_app_meta_data 기반 RBAC 활용 → 충족."""
    MK, TH = "users_with_role_ratio", 0.5
    users, err = _list_users()
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    if not users:
        return _result(item_id, maturity, MK, 0.0, TH, "미충족", {"users": 0})
    with_role = [u for u in users
                 if (u.get("app_metadata") or {}).get("role")
                 or (u.get("user_metadata") or {}).get("role")
                 or u.get("role")]
    ratio = len(with_role) / len(users)
    if ratio >= TH:
        verdict = "충족"
    elif ratio > 0:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _result(item_id, maturity, MK, ratio, TH, verdict,
                   {"total": len(users), "with_role": len(with_role)})


def collect_abac_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.3_1: RLS 정책 수 (public schema) ≥ 1 → 충족."""
    MK, TH = "rls_policy_count", 1.0
    policies, err = _rls_policies()
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    pub = [p for p in policies if (p.get("schemaname") or "") == "public"]
    count = float(len(pub))
    verdict = "충족" if count >= TH else "미충족"
    return _result(item_id, maturity, MK, count, TH, verdict,
                   {"total_policies": len(policies), "public_policies": len(pub)})


def collect_data_abac_policy(item_id: str, maturity: str) -> CollectedResult:
    """6.2.1.3_1: 데이터 테이블 RLS 적용 비율 ≥ 0.8 → 충족."""
    MK, TH = "rls_enabled_ratio", 0.8
    tables, err = _tables()
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    public = [t for t in tables if (t.get("schemaname") or "") == "public"]
    if not public:
        return _result(item_id, maturity, MK, 0.0, TH, "평가불가",
                       {"reason": "public 테이블 없음"})
    rls_on = [t for t in public if t.get("rowsecurity") is True]
    ratio = len(rls_on) / len(public)
    if ratio >= TH:
        verdict = "충족"
    elif ratio > 0:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _result(item_id, maturity, MK, ratio, TH, verdict,
                   {"total_tables": len(public), "rls_enabled": len(rls_on)})


def collect_mfa_required_actions(item_id: str, maturity: str) -> CollectedResult:
    """4.2.2.2_2: MFA 활성 사용자 비율 ≥ 0.5 → 충족."""
    MK, TH = "mfa_enrolled_ratio", 0.5
    users, err = _list_users()
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    if not users:
        return _result(item_id, maturity, MK, 0.0, TH, "미충족", {"users": 0})
    with_mfa = [u for u in users if (u.get("factors") or [])]
    ratio = len(with_mfa) / len(users)
    if ratio >= TH:
        verdict = "충족"
    elif ratio > 0:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _result(item_id, maturity, MK, ratio, TH, verdict,
                   {"total": len(users), "with_mfa": len(with_mfa)})


def collect_role_change_events(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.2_2: 최근 30일 신규/업데이트 사용자 비율 (역할 변경 추적 대용) — 활동성 ≥ 0.1."""
    MK, TH = "recent_user_activity_ratio", 0.1
    users, err = _list_users()
    if err:
        return _unavailable(item_id, maturity, MK, TH, err)
    if not users:
        return _result(item_id, maturity, MK, 0.0, TH, "미충족", {"users": 0})
    from datetime import datetime as _dt
    now = _dt.now(timezone.utc)
    recent = 0
    for u in users:
        upd = u.get("updated_at") or u.get("created_at")
        if not upd:
            continue
        try:
            dt = _dt.fromisoformat(upd.replace("Z", "+00:00"))
            if (now - dt).days <= 30:
                recent += 1
        except Exception:
            continue
    ratio = recent / len(users)
    verdict = "충족" if ratio >= TH else "부분충족" if ratio > 0 else "미충족"
    return _result(item_id, maturity, MK, ratio, TH, verdict,
                   {"total": len(users), "recent": recent})
