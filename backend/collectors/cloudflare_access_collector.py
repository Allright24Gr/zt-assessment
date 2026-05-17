"""cloudflare_access_collector.py — Cloudflare Access(ZTNA) 진단 함수 (Phase A: 10개)

entra_collector.py / zscaler_collector.py 와 동일한 추상을 가진 ZTNA 모듈.
Cloudflare API v4 의 Access 영역을 사용한다.

인증: API Token (Account 단위)
    Header: Authorization: Bearer <api_token>
    Base:   https://api.cloudflare.com/client/v4/accounts/{account_id}/access/

item_id 체계: {항목번호}.{성숙도번호}_{질문번호} — 다른 collector 와 동일하므로
dispatcher 자동매핑(_autodiscover) 에서 docstring 첫 줄로 자동 추출된다.
"""
from typing import Optional, Any, Tuple
from datetime import datetime, timezone, timedelta
import os
import logging

import httpx

CollectedResult = dict
logger = logging.getLogger(__name__)

# fallback 환경변수 — 사용자가 NewAssessment 에서 자격을 직접 입력하지 않은 경우 사용
CLOUDFLARE_API_TOKEN  = os.environ.get("CLOUDFLARE_API_TOKEN", "")
CLOUDFLARE_ACCOUNT_ID = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")

API_BASE = "https://api.cloudflare.com/client/v4"

# ─── session-scoped credential override ──────────────────────────────────────
_session_creds: Optional[dict] = None


def set_session_creds(creds: Optional[dict]) -> None:
    """세션 단위 Cloudflare 자격을 모듈 전역에 주입. None 이면 해제."""
    global _session_creds
    _session_creds = creds or None


def _api_token() -> str:
    if _session_creds and _session_creds.get("api_token"):
        return str(_session_creds["api_token"])
    return CLOUDFLARE_API_TOKEN


def _account_id() -> str:
    if _session_creds and _session_creds.get("account_id"):
        return str(_session_creds["account_id"])
    return CLOUDFLARE_ACCOUNT_ID


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
        "tool":         "cloudflare_access",
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


def _cf_get(path: str, params: dict = None, timeout: int = 30) -> Tuple[Optional[dict], Optional[str]]:
    """Cloudflare API GET. account 경로는 path 가 "/access/..." 처럼 시작하면 자동 보강.

    path 가 "/access/..." 또는 "/tunnels" 등 account 하위로 시작하면
    /accounts/{account_id} 를 prefix 로 자동 붙인다.
    path 가 "/zones/..." 처럼 다른 영역이면 그대로 사용.
    """
    token = _api_token()
    aid = _account_id()
    if not token:
        return None, "Cloudflare 인증 실패: api_token 미설정"
    if not aid:
        return None, "Cloudflare 인증 실패: account_id 미설정"

    if path.startswith("/zones") or path.startswith("/user"):
        url = f"{API_BASE}{path}"
    else:
        # access/, tunnels, logs/, members/ 등은 모두 account 하위
        url = f"{API_BASE}/accounts/{aid}{path}"

    try:
        resp = httpx.get(
            url,
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
        return None, "Cloudflare 권한 부족: api_token 만료/오류"
    if resp.status_code == 403:
        return None, "Cloudflare 권한 부족: token scope 확인 필요 (Access:Apps Read 등)"
    if resp.status_code == 404:
        return None, f"Cloudflare 엔드포인트 미지원: {path}"
    try:
        body = resp.json()
    except Exception:
        body = {}
    if 400 <= resp.status_code:
        msg = ""
        if isinstance(body, dict):
            errs = body.get("errors") or []
            if errs and isinstance(errs[0], dict):
                msg = errs[0].get("message") or ""
        return None, f"Cloudflare API 오류: {msg or f'HTTP {resp.status_code}'}"
    if isinstance(body, dict) and body.get("success") is False:
        errs = body.get("errors") or []
        msg = errs[0].get("message") if errs else "unknown"
        return None, f"Cloudflare API 응답 success=false: {msg}"
    return body, None


def _cf_list(path: str, params: dict = None) -> Tuple[Optional[list], Optional[str], dict]:
    """Cloudflare API 의 result(list) 추출. (list, error, raw)."""
    data, err = _cf_get(path, params)
    if err:
        return None, err, (data or {})
    result = (data or {}).get("result")
    if isinstance(result, list):
        return result, None, data
    if isinstance(result, dict):
        return [result], None, data
    return [], None, data


# ─────────────────────────── collectors (10) ───────────────────────────

def collect_idp_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.1.1.3_1: Access identity providers ≥ 1 → 충족 / 2+ → 다중 IdP"""
    MK, TH = "cf_idp_count", 1.0
    idps, err, _ = _cf_list("/access/identity_providers")
    if err:
        return _err(item_id, maturity, MK, TH, err, {})
    count = len(idps or [])
    if count >= 2:
        verdict = "충족"
    elif count == 1:
        verdict = "충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"idp_count": count, "idp_types": [i.get("type") for i in (idps or [])]})


def collect_mfa_required(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.1_1: MFA 강제 정책 ≥ 1 → 충족 (require: mfa 포함 Access policy)"""
    MK, TH = "mfa_required_policy_count", 1.0
    # Access policy 는 application 별로 조회 — 우선 apps 목록 받고 각 app 의 policies 순회
    apps, err, _ = _cf_list("/access/apps")
    if err:
        return _err(item_id, maturity, MK, TH, err, {})
    apps = apps or []
    if not apps:
        return _ok(item_id, maturity, "미충족", MK, 0.0, TH, {"apps": 0})
    mfa_count = 0
    inspected = 0
    for app in apps[:50]:  # 과도한 호출 방지 50개 제한
        app_id = app.get("id")
        if not app_id:
            continue
        polices, perr, _ = _cf_list(f"/access/apps/{app_id}/policies")
        if perr:
            continue
        inspected += 1
        for p in (polices or []):
            # require 블록 안 'auth_method' 또는 'mfa' 식별자
            requires = p.get("require") or []
            for r in requires:
                if isinstance(r, dict):
                    if r.get("mfa") or r.get("auth_method"):
                        mfa_count += 1
                        break
    verdict = "충족" if mfa_count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(mfa_count), TH,
               {"mfa_required_policy_count": mfa_count, "apps_inspected": inspected, "apps_total": len(apps)})


def collect_conditional_auth(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.3_1: app 에 연결된 활성 Access policy ≥ 1 → 충족"""
    MK, TH = "cf_active_access_policy_count", 1.0
    apps, err, _ = _cf_list("/access/apps")
    if err:
        return _err(item_id, maturity, MK, TH, err, {})
    apps = apps or []
    total_policies = 0
    apps_with_policy = 0
    for app in apps[:50]:
        app_id = app.get("id")
        if not app_id:
            continue
        polices, perr, _ = _cf_list(f"/access/apps/{app_id}/policies")
        if perr:
            continue
        n = len(polices or [])
        if n >= 1:
            apps_with_policy += 1
        total_policies += n
    verdict = "충족" if total_policies >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total_policies), TH,
               {"active_access_policies": total_policies,
                "apps_with_policy": apps_with_policy,
                "apps_total": len(apps)})


def collect_authz_clients(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.1_3: Access 보호 application ≥ 1 → 충족 (인가 client 등록 수)"""
    MK, TH = "cf_protected_app_count", 1.0
    apps, err, _ = _cf_list("/access/apps")
    if err:
        return _err(item_id, maturity, MK, TH, err, {})
    count = len(apps or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"protected_app_count": count})


def collect_central_authz_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.2_1: app 의 default action=deny(또는 명시적 allow 정책 보유) 비율 ≥ 80% → 충족"""
    MK, TH = "central_authz_default_deny_ratio", 0.8
    apps, err, _ = _cf_list("/access/apps")
    if err:
        return _err(item_id, maturity, MK, TH, err, {})
    apps = apps or []
    if not apps:
        return _ok(item_id, maturity, "미충족", MK, 0.0, TH, {"apps": 0})
    covered = 0
    inspected = 0
    for app in apps[:50]:
        app_id = app.get("id")
        if not app_id:
            continue
        inspected += 1
        polices, perr, _ = _cf_list(f"/access/apps/{app_id}/policies")
        if perr:
            continue
        # Cloudflare Access 는 정책 하나라도 등록되면 default 가 deny — 정책 보유 비율로 측정
        if (polices or []):
            covered += 1
    ratio = covered / inspected if inspected else 0.0
    if ratio >= TH:
        verdict = "충족"
    elif ratio >= 0.5:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, ratio, TH,
               {"apps_with_policy": covered, "apps_inspected": inspected})


def collect_perimeter_model(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.1_2: Cloudflare Tunnel 등록 수 ≥ 1 → 충족 (퍼리미터리스 게이트웨이)"""
    MK, TH = "cloudflare_tunnel_count", 1.0
    # cfd_tunnel = Cloudflare Tunnel (cloudflared) 신엔드포인트
    tunnels, err, _ = _cf_list("/cfd_tunnel")
    if err:
        # 구버전 호환
        tunnels, err2, _ = _cf_list("/tunnels")
        if err2:
            return _err(item_id, maturity, MK, TH, err, {})
    count = len(tunnels or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"tunnel_count": count})


def collect_ids_alerts(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.3_2: 최근 24h access_requests 중 deny/blocked 이벤트 ≥ 1 → 충족"""
    MK, TH = "access_denied_24h", 1.0
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    # Access logs 엔드포인트는 access/logs/access_requests
    data, err = _cf_get(
        "/access/logs/access_requests",
        {"since": since, "limit": 1000},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err, {})
    events = (data or {}).get("result") or []
    if not isinstance(events, list):
        events = []
    denied = 0
    for e in events:
        action = str(e.get("action") or e.get("decision") or "").lower()
        allowed = e.get("allowed")
        if action in ("deny", "denied", "blocked", "block") or allowed is False:
            denied += 1
    verdict = "충족" if denied >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(denied), TH,
               {"denied_24h": denied, "events_inspected": len(events)})


def collect_tls_ratio(item_id: str, maturity: str) -> CollectedResult:
    """3.3.1.1_1: Access app 중 HTTPS 강제 비율 ≥ 80% → 충족 / 50~80% → 부분충족"""
    MK, TH = "https_enforced_ratio", 0.8
    apps, err, _ = _cf_list("/access/apps")
    if err:
        return _err(item_id, maturity, MK, TH, err, {})
    apps = apps or []
    if not apps:
        return _ok(item_id, maturity, "미충족", MK, 0.0, TH, {"apps": 0})
    https = 0
    for app in apps:
        domain = str(app.get("domain") or "")
        # Cloudflare Access 는 사실상 모두 https — domain 이 https:// 로 시작하거나 호스트만 있을 때 둘 다 https 라 간주
        # 명시적으로 http:// 시작인 경우만 비강제로 본다.
        if domain and not domain.lower().startswith("http://"):
            https += 1
    ratio = https / len(apps)
    if ratio >= TH:
        verdict = "충족"
    elif ratio >= 0.5:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, ratio, TH,
               {"https_apps": https, "apps_total": len(apps)})


def collect_session_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.2.2.1_1: Access app 평균 session_duration ≤ 4h(=14400s) → 충족"""
    MK, TH = "avg_session_duration_seconds", 14400.0  # 4h
    apps, err, _ = _cf_list("/access/apps")
    if err:
        return _err(item_id, maturity, MK, TH, err, {})
    apps = apps or []
    if not apps:
        return _ok(item_id, maturity, "미충족", MK, 0.0, TH, {"apps": 0})
    durations = []
    for app in apps:
        d = app.get("session_duration") or ""
        # Cloudflare 표기: "30m", "8h", "24h", "1h30m" 등
        seconds = _parse_duration(str(d))
        if seconds is not None:
            durations.append(seconds)
    if not durations:
        return _ok(item_id, maturity, "미충족", MK, 0.0, TH,
                   {"apps": len(apps), "session_duration_parsed": 0})
    avg = sum(durations) / len(durations)
    verdict = "충족" if avg <= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(avg), TH,
               {"avg_session_duration_seconds": avg,
                "apps_with_duration": len(durations),
                "apps_total": len(apps)})


def collect_privilege_change_alerts(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.3_2: 최근 24h 관리자(admin) 로그인 이벤트 ≥ 1 → 충족 (권한 변경 감사)"""
    MK, TH = "admin_login_24h", 1.0
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    data, err = _cf_get(
        "/access/logs/access_requests",
        {"since": since, "limit": 1000},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err, {})
    events = (data or {}).get("result") or []
    if not isinstance(events, list):
        events = []
    admin_logins = 0
    for e in events:
        action = str(e.get("action") or "").lower()
        # admin 식별: app_uid 가 admin/dashboard 류이거나 email/identity 에 admin 포함
        email = str(e.get("user_email") or e.get("email") or "").lower()
        ident = str(e.get("identity") or "").lower()
        if action == "login" and ("admin" in email or "admin" in ident or e.get("admin") is True):
            admin_logins += 1
    verdict = "충족" if admin_logins >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(admin_logins), TH,
               {"admin_login_24h": admin_logins, "events_inspected": len(events)})


def _parse_duration(s: str) -> Optional[float]:
    """Cloudflare 표기 '30m' / '8h' / '1h30m' / '24h' → seconds."""
    s = (s or "").strip().lower()
    if not s:
        return None
    total = 0.0
    num = ""
    for ch in s:
        if ch.isdigit() or ch == ".":
            num += ch
        elif ch == "h":
            if num:
                total += float(num) * 3600
                num = ""
        elif ch == "m":
            if num:
                total += float(num) * 60
                num = ""
        elif ch == "s":
            if num:
                total += float(num)
                num = ""
        elif ch == "d":
            if num:
                total += float(num) * 86400
                num = ""
        else:
            # 무시
            pass
    if num:
        # 단위 없는 숫자는 초로 간주
        try:
            total += float(num)
        except Exception:
            pass
    return total if total > 0 else None


# === ASSESSMENT.PY 통합 가이드 (후속 통합 작업자용) ===
# ALL_TOOLS += ("cloudflare_access",)
# 새 카테고리: _ZTNA_TOOL_OF / _ZTNA_AUTO_TOOLS → ProfileSelect.ztna_type
# AssessmentRunRequest.cloudflare_creds: CloudflareCreds(api_token, account_id)
# _mask_creds: cloudflare_creds.api_token → "***"
# _run_collectors: cloudflare_access_collector.set_session_creds({...}) 호출
# _autodiscover: 본 모듈 import 추가 → docstring 첫 줄 X.X.X.X_N 로 자동 매핑됨
# _tool_health / _tool_configured: api_token + account_id 모두 비면 unavailable
