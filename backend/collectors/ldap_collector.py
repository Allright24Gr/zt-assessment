"""ldap_collector.py — 자체 LDAP / Active Directory 진단 함수 (Phase A: 15개)

keycloak/entra/okta_collector 와 동일한 추상을 가진 모듈. python-ldap3 사용.
인증: simple bind (BIND_DN + BIND_PASSWORD).

대상: 한국 공공·제조·금융권에서 운영하는 자체 IdP
  - Microsoft Active Directory (Windows Server)
  - OpenLDAP (RHEL / Ubuntu 표준 패키지)
  - FreeIPA (Red Hat IdM)

item_id 체계: {항목번호}.{성숙도번호}_{질문번호} — keycloak/entra/okta 와 동일.
dispatcher 자동매핑(_autodiscover) 에서 docstring 첫 줄로 자동 추출된다.

LDAP 표준은 변경 audit 로그를 강제하지 않으므로, role_change_events 같은 일부 항목은
'평가불가' + 안내 메시지를 반환한다 (정상 동작).
"""
from typing import Optional, Any, Tuple, List
from datetime import datetime, timezone
import os
import logging

CollectedResult = dict
logger = logging.getLogger(__name__)

# fallback 환경변수 — 사용자가 NewAssessment에서 자격을 직접 입력하지 않은 경우 사용
LDAP_URL           = os.environ.get("LDAP_URL", "")
LDAP_BIND_DN       = os.environ.get("LDAP_BIND_DN", "")
LDAP_BIND_PASSWORD = os.environ.get("LDAP_BIND_PASSWORD", "")
LDAP_BASE_DN       = os.environ.get("LDAP_BASE_DN", "")

# ldap3 는 운영 환경에 따라 미설치일 수 있으므로 lazy import.
# 모듈 로딩 자체는 실패하지 않도록 try/except.
try:
    import ldap3  # type: ignore
    from ldap3 import SUBTREE, BASE, LEVEL  # type: ignore
    _LDAP3_AVAILABLE = True
except Exception as _exc:  # pragma: no cover
    ldap3 = None  # type: ignore
    SUBTREE = "SUBTREE"
    BASE = "BASE"
    LEVEL = "LEVEL"
    _LDAP3_AVAILABLE = False
    _LDAP3_IMPORT_ERR = str(_exc)
else:
    _LDAP3_IMPORT_ERR = ""


# ─── session-scoped credential override ──────────────────────────────────────
# 사용자가 NewAssessment에서 입력한 LDAP 자격을 _run_collectors에서 주입한다.
_session_creds: Optional[dict] = None


def set_session_creds(creds: Optional[dict]) -> None:
    """세션 단위 LDAP 자격을 모듈 전역에 주입. None 이면 해제."""
    global _session_creds
    _session_creds = creds or None


def _ldap_url() -> str:
    if _session_creds and _session_creds.get("url"):
        return str(_session_creds["url"]).strip()
    return LDAP_URL.strip()


def _ldap_bind_dn() -> str:
    if _session_creds and _session_creds.get("bind_dn"):
        return str(_session_creds["bind_dn"]).strip()
    return LDAP_BIND_DN.strip()


def _ldap_bind_pass() -> str:
    if _session_creds and _session_creds.get("bind_password"):
        return str(_session_creds["bind_password"])
    return LDAP_BIND_PASSWORD


def _ldap_base_dn() -> str:
    if _session_creds and _session_creds.get("base_dn"):
        return str(_session_creds["base_dn"]).strip()
    return LDAP_BASE_DN.strip()


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
        "tool":         "ldap",
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


def _ldap_connect() -> Tuple[Any, Optional[str]]:
    """ldap3.Connection 을 반환. 실패 시 (None, error_msg).

    호출 측은 finally 에서 반환된 conn.unbind() 를 직접 처리해야 한다.
    """
    if not _LDAP3_AVAILABLE:
        return None, f"LDAP 미사용: ldap3 모듈 로드 실패 ({_LDAP3_IMPORT_ERR})"
    url = _ldap_url()
    bind_dn = _ldap_bind_dn()
    bind_pw = _ldap_bind_pass()
    if not url:
        return None, "LDAP 미연결: LDAP_URL 미설정"
    if not bind_dn or not bind_pw:
        return None, "LDAP 미연결: LDAP_BIND_DN/LDAP_BIND_PASSWORD 미설정"
    try:
        server = ldap3.Server(url, get_info=ldap3.ALL, connect_timeout=10)
        conn = ldap3.Connection(
            server,
            user=bind_dn,
            password=bind_pw,
            auto_bind=True,
            receive_timeout=20,
        )
        return conn, None
    except Exception as exc:
        return None, f"LDAP 연결 실패: {type(exc).__name__}: {exc}"


def _search(
    filter_str: str,
    attributes: Optional[List[str]] = None,
    scope: str = SUBTREE,
    base_override: Optional[str] = None,
    paged: bool = False,
    size_limit: int = 0,
) -> Tuple[List[Any], Optional[str], Any]:
    """LDAP 검색 헬퍼. (entries, error, raw_meta) 튜플.

    base_override: 검색 base 를 BASE_DN 외 다른 값(예: configurationNamingContext)으로
    바꾸고 싶을 때 사용.
    """
    conn, err = _ldap_connect()
    if err:
        return [], err, {}
    base = base_override or _ldap_base_dn()
    if not base and scope != BASE:
        try:
            conn.unbind()
        except Exception:
            pass
        return [], "LDAP 미연결: LDAP_BASE_DN 미설정", {}
    try:
        search_kwargs = dict(
            search_base=base or "",
            search_filter=filter_str,
            search_scope=scope,
            attributes=attributes or [],
            size_limit=size_limit,
        )
        if paged:
            search_kwargs["paged_size"] = 500
        ok = conn.search(**search_kwargs)
        entries = list(conn.entries) if ok else []
        return entries, None, {"result": conn.result, "base": base}
    except Exception as exc:
        return [], f"LDAP 검색 실패: {type(exc).__name__}: {exc}", {}
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def _root_dse() -> Tuple[Optional[dict], Optional[str]]:
    """RootDSE(base="" + scope=BASE) 조회 — 서버 메타데이터."""
    conn, err = _ldap_connect()
    if err:
        return None, err
    try:
        # ldap3 는 connection 생성 시 get_info=ALL 이면 server.info 에 RootDSE 캐시.
        info = getattr(conn.server, "info", None)
        if info is None:
            return None, "RootDSE 없음"
        data = {
            "supportedLDAPVersion": list(getattr(info, "supported_ldap_versions", []) or []),
            "naming_contexts": list(getattr(info, "naming_contexts", []) or []),
            "vendor_name": getattr(info, "vendor_name", "") or "",
            "vendor_version": getattr(info, "vendor_version", "") or "",
        }
        return data, None
    except Exception as exc:
        return None, f"RootDSE 조회 실패: {type(exc).__name__}: {exc}"
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def _attr_int(entry: Any, name: str, default: int = 0) -> int:
    try:
        v = getattr(entry, name).value
        if v is None or v == []:
            return default
        if isinstance(v, list):
            v = v[0]
        return int(v)
    except Exception:
        return default


def _attr_str(entry: Any, name: str, default: str = "") -> str:
    try:
        v = getattr(entry, name).value
        if v is None:
            return default
        if isinstance(v, list):
            v = v[0] if v else default
        return str(v)
    except Exception:
        return default


# ─────────────────────────── collectors (15) ───────────────────────────

def collect_user_role_ratio(item_id: str, maturity: str) -> CollectedResult:
    """1.1.1.2_1: 관리자 그룹 멤버 비율 분석. 일반 사용자 > 0 + 관리자 ≤ 10% → 충족"""
    MK, TH = "user_role_ratio", 0.95
    # 전체 user
    users, err, _ = _search(
        "(&(objectClass=user)(!(objectClass=computer)))",
        attributes=["distinguishedName", "memberOf"],
    )
    if err:
        # OpenLDAP/FreeIPA 호환: inetOrgPerson 으로 폴백
        users, err2, _ = _search(
            "(|(objectClass=inetOrgPerson)(objectClass=posixAccount))",
            attributes=["distinguishedName", "memberOf"],
        )
        if err2:
            return _err(item_id, maturity, MK, TH, err)
    total = len(users)
    if total == 0:
        return _err(item_id, maturity, MK, TH, "사용자 0명 (분모 불가)")
    admins = 0
    for e in users:
        groups_v = []
        try:
            mo = getattr(e, "memberOf").value
            if mo is None:
                mo = []
            if not isinstance(mo, list):
                mo = [mo]
            groups_v = [str(x).lower() for x in mo]
        except Exception:
            groups_v = []
        if any("admin" in g for g in groups_v):
            admins += 1
    regular = total - admins
    ratio = regular / total if total else 0.0
    if ratio >= TH:
        verdict = "충족"
    elif ratio >= 0.8:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, ratio, TH,
               {"total_users": total, "admin_users": admins, "regular_users": regular})


def collect_idp_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.1.1.3_1: LDAP 서버 자체가 IdP. RootDSE 응답 가능 시 충족(=1)"""
    MK, TH = "idp_server_ok", 1.0
    info, err = _root_dse()
    if err:
        return _err(item_id, maturity, MK, TH, err)
    return _ok(item_id, maturity, "충족", MK, 1.0, TH,
               {"naming_contexts": info.get("naming_contexts", []),
                "vendor_name": info.get("vendor_name", ""),
                "vendor_version": info.get("vendor_version", "")})


def collect_idp_registered(item_id: str, maturity: str) -> CollectedResult:
    """1.1.2.1_1: supportedLDAPVersion 존재 → 충족 (서버가 LDAP 규격 준수)"""
    MK, TH = "idp_protocol_registered", 1.0
    info, err = _root_dse()
    if err:
        return _err(item_id, maturity, MK, TH, err)
    versions = info.get("supportedLDAPVersion") or []
    if versions:
        return _ok(item_id, maturity, "충족", MK, 1.0, TH,
                   {"supportedLDAPVersion": versions})
    return _ok(item_id, maturity, "미충족", MK, 0.0, TH,
               {"supportedLDAPVersion": []})


def collect_active_idp_multi(item_id: str, maturity: str) -> CollectedResult:
    """1.1.2.2_1: forest trust(crossRef/trustedDomain) ≥ 2 → 충족 / 1 → 부분충족"""
    MK, TH = "active_idp_count", 2.0
    # AD: cn=Partitions,CN=Configuration,<base> 안의 crossRef
    base = _ldap_base_dn()
    cross_base = f"CN=Partitions,CN=Configuration,{base}" if base else ""
    cross, err1, _ = _search(
        "(objectClass=crossRef)",
        attributes=["nETBIOSName", "dnsRoot"],
        base_override=cross_base if cross_base else None,
    )
    trusted, err2, _ = _search(
        "(objectClass=trustedDomain)",
        attributes=["trustPartner"],
    )
    # 둘 다 실패하면 평가불가, 한쪽만 성공해도 카운트.
    if err1 and err2:
        return _err(item_id, maturity, MK, TH, err1 or err2)
    count = len(cross or []) + len(trusted or [])
    if count >= TH:
        verdict = "충족"
    elif count == 1:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"crossRef": len(cross or []), "trustedDomain": len(trusted or [])})


def collect_mfa_required(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.1_1: SMARTCARD_REQUIRED(0x40000) 또는 Fine-Grained PSO 존재 → 충족"""
    MK, TH = "mfa_enforced", 1.0
    # 1) Smartcard 강제 사용자 수
    smart_users, err, _ = _search(
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=262144))",
        attributes=["distinguishedName"],
    )
    smart_count = len(smart_users or [])
    # 2) Fine-Grained Password Policy(PSO) 개수 (AD 전용)
    base = _ldap_base_dn()
    pso_base = f"CN=Password Settings Container,CN=System,{base}" if base else ""
    psos, _err2, _ = _search(
        "(objectClass=msDS-PasswordSettings)",
        attributes=["cn"],
        base_override=pso_base if pso_base else None,
    )
    pso_count = len(psos or [])
    if err and pso_count == 0 and smart_count == 0:
        return _err(item_id, maturity, MK, TH, err)
    value = float(smart_count + pso_count)
    verdict = "충족" if value >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, value, TH,
               {"smartcard_required_users": smart_count, "password_settings_objects": pso_count})


def collect_conditional_auth(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.3_1: msDS-AuthNPolicy 또는 Authentication Silo ≥ 1 → 충족"""
    MK, TH = "auth_policy_count", 1.0
    base = _ldap_base_dn()
    pol_base = f"CN=AuthN Policy Configuration,CN=Services,CN=Configuration,{base}" if base else ""
    policies, err, _ = _search(
        "(|(objectClass=msDS-AuthNPolicy)(objectClass=msDS-AuthNPolicySilo))",
        attributes=["cn"],
        base_override=pol_base if pol_base else None,
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    count = len(policies or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"auth_policy_count": count})


def collect_session_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.2.2.1_1: domain 정책의 maxPwdAge/lockoutThreshold/lockoutDuration 설정 → 충족"""
    MK, TH = "session_policy_set", 1.0
    base = _ldap_base_dn()
    if not base:
        return _err(item_id, maturity, MK, TH, "LDAP_BASE_DN 미설정")
    entries, err, _ = _search(
        "(objectClass=domain)",
        attributes=["maxPwdAge", "lockoutThreshold", "lockoutDuration"],
        scope=BASE,
        base_override=base,
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    if not entries:
        return _err(item_id, maturity, MK, TH, "domain policy 미발견")
    e = entries[0]
    max_pwd_age = _attr_int(e, "maxPwdAge", 0)
    lockout_threshold = _attr_int(e, "lockoutThreshold", 0)
    lockout_duration = _attr_int(e, "lockoutDuration", 0)
    # 정책 항목 3개 중 0개=미충족, 1~2개=부분, 3개=충족
    set_count = sum(1 for x in (max_pwd_age, lockout_threshold, lockout_duration) if x)
    if set_count >= 3:
        verdict = "충족"
    elif set_count >= 1:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, float(set_count), TH,
               {"maxPwdAge": max_pwd_age, "lockoutThreshold": lockout_threshold,
                "lockoutDuration": lockout_duration})


def collect_stepup_auth(item_id: str, maturity: str) -> CollectedResult:
    """1.2.2.2_1: user-tier msDS-AuthNPolicy ≥ 1 → 충족 (단계별 인증)"""
    MK, TH = "stepup_policy_count", 1.0
    base = _ldap_base_dn()
    pol_base = f"CN=AuthN Policy Configuration,CN=Services,CN=Configuration,{base}" if base else ""
    policies, err, _ = _search(
        "(objectClass=msDS-AuthNPolicy)",
        attributes=["cn", "msDS-UserAllowedToAuthenticateTo"],
        base_override=pol_base if pol_base else None,
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    count = 0
    for e in policies or []:
        try:
            v = getattr(e, "msDS-UserAllowedToAuthenticateTo").value
            if v:
                count += 1
        except Exception:
            # 정책 자체가 존재하면 stepup 후보로 카운트 (보수적)
            count += 1
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"stepup_policy_count": count, "total_policies": len(policies or [])})


def collect_realm_count(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1.1_1: configurationNamingContext 의 도메인(domain) 객체 수"""
    MK, TH = "realm_count", 1.0
    base = _ldap_base_dn()
    if not base:
        return _err(item_id, maturity, MK, TH, "LDAP_BASE_DN 미설정")
    # naming_contexts 가 가장 신뢰 가능한 forest 도메인 목록
    info, err = _root_dse()
    if err:
        return _err(item_id, maturity, MK, TH, err)
    ncs = info.get("naming_contexts") or []
    # DC=… 로 시작하는 root 만 도메인으로 카운트 (Configuration/Schema 제외)
    domain_ncs = [n for n in ncs if str(n).upper().startswith("DC=")]
    count = len(domain_ncs)
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"realm_count": count, "naming_contexts": ncs})


def collect_icam_inventory(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1.2_1: 전체 사용자 수 ≥ 1 → 충족 (ICAM 인벤토리)"""
    MK, TH = "user_count", 1.0
    users, err, _ = _search(
        "(&(objectClass=user)(!(objectClass=computer)))",
        attributes=["distinguishedName"],
    )
    if err:
        # OpenLDAP 폴백
        users, err2, _ = _search(
            "(|(objectClass=inetOrgPerson)(objectClass=posixAccount))",
            attributes=["distinguishedName"],
        )
        if err2:
            return _err(item_id, maturity, MK, TH, err)
    count = len(users or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"user_count": count})


def collect_authz_clients(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.1_3: 보안 그룹(group) 수 ≥ 1 → 충족 (인가 단위)"""
    MK, TH = "group_count", 1.0
    groups, err, _ = _search(
        "(|(objectClass=group)(objectClass=groupOfNames)(objectClass=posixGroup))",
        attributes=["cn"],
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    count = len(groups or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"group_count": count})


def collect_rbac_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.2_1: built-in admin 그룹(Domain/Enterprise Admins) 활성 수 ≥ 1 → 충족"""
    MK, TH = "active_admin_groups", 1.0
    # AD 표준 admin 그룹 후보 — cn 매칭
    admin_filter = (
        "(|(cn=Domain Admins)(cn=Enterprise Admins)(cn=Schema Admins)"
        "(cn=Administrators)(cn=Account Operators))"
    )
    groups, err, _ = _search(admin_filter, attributes=["cn", "member"])
    if err:
        return _err(item_id, maturity, MK, TH, err)
    # 멤버가 1명 이상인 그룹만 활성으로 본다
    active = 0
    for g in groups or []:
        try:
            mb = getattr(g, "member").value
            if mb:
                if isinstance(mb, list):
                    if len(mb) > 0:
                        active += 1
                else:
                    active += 1
        except Exception:
            # member 속성 자체가 없으면 빈 그룹으로 간주, 카운트 안 함
            pass
    verdict = "충족" if active >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(active), TH,
               {"admin_groups_found": len(groups or []), "active_admin_groups": active})


def collect_password_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.2_1: domain minPwdLength ≥ 8 → 충족 / ≥ 6 → 부분충족 / 미만 → 미충족"""
    MK, TH = "password_min_length_ok", 8.0
    base = _ldap_base_dn()
    if not base:
        return _err(item_id, maturity, MK, TH, "LDAP_BASE_DN 미설정")
    entries, err, _ = _search(
        "(objectClass=domain)",
        attributes=["minPwdLength", "pwdProperties", "pwdHistoryLength"],
        scope=BASE,
        base_override=base,
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    if not entries:
        return _err(item_id, maturity, MK, TH, "domain policy 미발견")
    e = entries[0]
    min_len = _attr_int(e, "minPwdLength", 0)
    pwd_props = _attr_int(e, "pwdProperties", 0)
    pwd_hist = _attr_int(e, "pwdHistoryLength", 0)
    if min_len >= TH:
        verdict = "충족"
    elif min_len >= 6:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, float(min_len), TH,
               {"minPwdLength": min_len, "pwdProperties": pwd_props,
                "pwdHistoryLength": pwd_hist})


def collect_role_change_events(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.2_2: LDAP 표준엔 변경 audit 로그가 없음 → 평가불가 (SIEM 위임)"""
    MK, TH = "role_change_events", 1.0
    return _unavailable(
        item_id, maturity, MK, TH,
        "LDAP 표준은 변경 audit 로그를 제공하지 않습니다. Wazuh/Splunk(SIEM) 또는 "
        "Windows Security Event Log(4728/4732 등) 수집기로 대체 평가하세요.",
        {"note": "LDAP audit unsupported"},
    )


def collect_central_authz_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.2_1: msDS-AuthNPolicy ≥ 1 → 충족 (중앙 인가 정책)"""
    MK, TH = "central_authz_policy_count", 1.0
    base = _ldap_base_dn()
    pol_base = f"CN=AuthN Policy Configuration,CN=Services,CN=Configuration,{base}" if base else ""
    policies, err, _ = _search(
        "(objectClass=msDS-AuthNPolicy)",
        attributes=["cn"],
        base_override=pol_base if pol_base else None,
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    count = len(policies or [])
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"central_authz_policy_count": count})
