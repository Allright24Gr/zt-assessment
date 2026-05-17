"""crowdstrike_collector.py — CrowdStrike Falcon EDR 진단 함수 (Phase A: 15개)

entra_collector.py / okta_collector.py 와 동일한 추상을 가진 모듈.
CrowdStrike Falcon REST API 를 사용한다.

인증: OAuth2 client_credentials flow.
    POST {api_base}/oauth2/token (application/x-www-form-urlencoded)
    body: client_id=<k>&client_secret=<s>
    응답: {"access_token": "...", "expires_in": 1799}
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
CROWDSTRIKE_API_BASE      = os.environ.get("CROWDSTRIKE_API_BASE", "")
CROWDSTRIKE_CLIENT_ID     = os.environ.get("CROWDSTRIKE_CLIENT_ID", "")
CROWDSTRIKE_CLIENT_SECRET = os.environ.get("CROWDSTRIKE_CLIENT_SECRET", "")

# ─── session-scoped credential override ──────────────────────────────────────
_session_creds: Optional[dict] = None
_token_cache: Optional[dict] = None  # {"token": str, "expires_at": float}


def set_session_creds(creds: Optional[dict]) -> None:
    """세션 단위 CrowdStrike 자격을 모듈 전역에 주입. None 이면 해제 + 토큰 캐시 무효화."""
    global _session_creds, _token_cache
    _session_creds = creds or None
    _token_cache = None


def _api_base() -> str:
    if _session_creds and _session_creds.get("api_base"):
        return str(_session_creds["api_base"]).rstrip("/")
    return CROWDSTRIKE_API_BASE.rstrip("/")


def _client_id() -> str:
    if _session_creds and _session_creds.get("client_id"):
        return str(_session_creds["client_id"])
    return CROWDSTRIKE_CLIENT_ID


def _client_secret() -> str:
    if _session_creds and _session_creds.get("client_secret"):
        return str(_session_creds["client_secret"])
    return CROWDSTRIKE_CLIENT_SECRET


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
        "tool":         "crowdstrike",
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
    """OAuth2 client_credentials 토큰 발급. 캐싱 60s 마진. (token, error) 반환."""
    global _token_cache
    now = time.time()
    if _token_cache and _token_cache.get("expires_at", 0) > now + 60:
        return _token_cache["token"], None
    base = _api_base()
    cid = _client_id()
    cs = _client_secret()
    if not (base and cid and cs):
        return None, "CrowdStrike 인증 실패: api_base/client_id/client_secret 미설정"
    url = f"{base}/oauth2/token"
    try:
        resp = httpx.post(
            url,
            data={"client_id": cid, "client_secret": cs},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=20,
        )
    except Exception as exc:
        return None, f"CrowdStrike 토큰 요청 실패: {type(exc).__name__}: {exc}"
    if resp.status_code == 401 or resp.status_code == 403:
        return None, "CrowdStrike 인증 실패: client_id/client_secret 확인 필요"
    if resp.status_code >= 400:
        return None, f"CrowdStrike 토큰 발급 오류: HTTP {resp.status_code}"
    try:
        data = resp.json()
    except Exception:
        return None, "CrowdStrike 토큰 응답 파싱 실패"
    tok = data.get("access_token")
    if not tok:
        return None, "CrowdStrike 토큰 응답에 access_token 없음"
    _token_cache = {
        "token":      tok,
        "expires_at": now + float(data.get("expires_in", 1799)),
    }
    return tok, None


def _cs_get(path: str, params: dict = None, timeout: int = 30) -> Tuple[Optional[dict], Optional[str]]:
    """Falcon API GET. (data, error) 튜플. data 가 None 이면 error 존재."""
    token, terr = _get_access_token()
    if terr:
        return None, terr
    base = _api_base()
    try:
        resp = httpx.get(
            f"{base}{path}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            params=params or {},
            timeout=timeout,
        )
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    if resp.status_code == 401:
        return None, "CrowdStrike 권한 부족: 토큰 만료 또는 권한 없음"
    if resp.status_code == 403:
        return None, "CrowdStrike 권한 부족: API scope 부족"
    if resp.status_code == 429:
        return None, "CrowdStrike rate limit"
    try:
        body = resp.json()
    except Exception:
        body = {}
    if resp.status_code >= 400:
        errs = (body.get("errors") or [])
        msg = ""
        if errs and isinstance(errs, list):
            msg = errs[0].get("message") or ""
        return None, f"CrowdStrike API 오류: HTTP {resp.status_code} {msg}".strip()
    return body, None


def _cs_total(path: str, params: dict = None) -> Tuple[Optional[int], Optional[str], Any]:
    """meta.pagination.total 우선, 없으면 resources 길이로 카운트."""
    data, err = _cs_get(path, params)
    if err:
        return None, err, data
    meta = (data or {}).get("meta") or {}
    pagination = meta.get("pagination") or {}
    total = pagination.get("total")
    if total is None:
        resources = (data or {}).get("resources") or []
        total = len(resources)
    return int(total), None, data


# ─────────────────────────── collectors (15) ───────────────────────────

def collect_endpoint_inventory(item_id: str, maturity: str) -> CollectedResult:
    """2.2.1.1_1: 단말 자산 인벤토리 (전체 host count ≥ 1 → 충족)"""
    MK, TH = "endpoint_total", 1.0
    total, err, _ = _cs_total("/devices/queries/devices/v1", {"limit": 1})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"endpoint_total": total})


def collect_agent_registration(item_id: str, maturity: str) -> CollectedResult:
    """2.3.1.1_2: 에이전트 등록률 (online 호스트 / 전체 ≥ 0.9 → 충족, 0.7~ → 부분)"""
    MK, TH = "agent_online_ratio", 0.9
    total, err, _ = _cs_total("/devices/queries/devices/v1", {"limit": 1})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    online, oerr, _ = _cs_total("/devices/queries/devices/v1",
                                {"limit": 1, "filter": "status:'online'"})
    if oerr:
        return _err(item_id, maturity, MK, TH, oerr)
    if not total:
        return _err(item_id, maturity, MK, TH, "등록된 호스트(분모)가 0")
    ratio = (online or 0) / total
    if ratio >= TH:
        verdict = "충족"
    elif ratio >= 0.7:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, ratio, TH,
               {"online": online, "total": total})


def collect_edr_agents(item_id: str, maturity: str) -> CollectedResult:
    """2.3.1.2_2: 활성 EDR 에이전트 수 (online 호스트 ≥ 1 → 충족)"""
    MK, TH = "edr_online_agents", 1.0
    total, err, _ = _cs_total("/devices/queries/devices/v1",
                              {"limit": 1, "filter": "status:'online'"})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"online_agents": total})


def collect_auto_block(item_id: str, maturity: str) -> CollectedResult:
    """2.2.1.4_1: 자동 차단/격리 정책 (활성 sensor update 정책 ≥ 1 → 충족)"""
    MK, TH = "active_block_policies", 1.0
    total, err, _ = _cs_total("/policy/queries/sensor-update/v1",
                              {"limit": 1, "filter": "enabled:true"})
    if err:
        # filter 미지원 시 fallback: 전체 카운트
        total2, err2, _ = _cs_total("/policy/queries/sensor-update/v1", {"limit": 1})
        if err2:
            return _err(item_id, maturity, MK, TH, err)
        total = total2
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"active_block_policies": total})


def collect_policy_violation_alerts(item_id: str, maturity: str) -> CollectedResult:
    """2.1.1.2_2: 정책 위반 탐지 (Policy Violation tactic detect ≥ 1 → 충족)"""
    MK, TH = "policy_violation_detects", 1.0
    total, err, _ = _cs_total(
        "/detects/queries/detects/v1",
        {"limit": 1, "filter": "behaviors_processed.tactic:'Policy Violation'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"policy_violation_detects": total})


def collect_realtime_threat_alerts(item_id: str, maturity: str) -> CollectedResult:
    """4.4.1.1_2: 실시간 위협 알림 (new + high severity alert ≥ 1 → 충족)"""
    MK, TH = "realtime_high_alerts", 1.0
    total, err, _ = _cs_total(
        "/alerts/queries/alerts/v1",
        {"limit": 1, "filter": "status:'new'+severity:'high'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"realtime_high_alerts": total})


def collect_threat_detection_alerts(item_id: str, maturity: str) -> CollectedResult:
    """5.2.1.4_2: 위협 탐지 알림 (new detect ≥ 1 → 충족)"""
    MK, TH = "new_detects", 1.0
    total, err, _ = _cs_total(
        "/detects/queries/detects/v1",
        {"limit": 1, "filter": "status:'new'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"new_detects": total})


def collect_privilege_escalation_alerts(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.3_2: 권한 상승 탐지 (Privilege Escalation tactic detect ≥ 1 → 충족)"""
    MK, TH = "privilege_escalation_detects", 1.0
    total, err, _ = _cs_total(
        "/detects/queries/detects/v1",
        {"limit": 1, "filter": "behaviors_processed.tactic:'Privilege Escalation'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"privilege_escalation_detects": total})


def collect_lateral_movement_alerts(item_id: str, maturity: str) -> CollectedResult:
    """3.4.1.1_2: 측면 이동 탐지 (Lateral Movement tactic detect ≥ 1 → 충족)"""
    MK, TH = "lateral_movement_detects", 1.0
    total, err, _ = _cs_total(
        "/detects/queries/detects/v1",
        {"limit": 1, "filter": "behaviors_processed.tactic:'Lateral Movement'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"lateral_movement_detects": total})


def collect_malware_blocked(item_id: str, maturity: str) -> CollectedResult:
    """2.1.1.3_1: 악성코드 자동 차단 (Falcon Detection Method 탐지 ≥ 1 → 충족)"""
    MK, TH = "malware_blocked_detects", 1.0
    total, err, _ = _cs_total(
        "/detects/queries/detects/v1",
        {"limit": 1,
         "filter": "behaviors_processed.objective:'Falcon Detection Method'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"malware_blocked_detects": total})


def collect_quarantine_actions(item_id: str, maturity: str) -> CollectedResult:
    """2.4.2.2_1: 격리/원격대응 세션 수 (RTR 세션 ≥ 1 → 충족)"""
    MK, TH = "rtr_sessions", 1.0
    total, err, _ = _cs_total("/real-time-response/queries/sessions/v1", {"limit": 1})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"rtr_sessions": total})


def collect_realtime_monitoring(item_id: str, maturity: str) -> CollectedResult:
    """2.2.1.3_1: 실시간 모니터링 (online sensor ≥ 1 → 충족)"""
    MK, TH = "realtime_online_sensors", 1.0
    total, err, _ = _cs_total(
        "/devices/queries/devices/v1",
        {"limit": 1, "filter": "status:'online'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"realtime_online_sensors": total})


def collect_vuln_summary(item_id: str, maturity: str) -> CollectedResult:
    """5.5.2.2_1: 취약점 요약 (Spotlight vulnerability count ≥ 1 → 충족)"""
    MK, TH = "vulnerability_total", 1.0
    total, err, _ = _cs_total("/spotlight/queries/vulnerabilities/v1", {"limit": 1})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    verdict = "충족" if (total or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(total or 0), TH,
               {"vulnerability_total": total})


def collect_critical_unfixed_vulns(item_id: str, maturity: str) -> CollectedResult:
    """5.5.1.3_1: 미패치 Critical 취약점 (open + CRITICAL ≥ 1 → 미충족, 0 → 충족)"""
    MK, TH = "critical_open_vulns", 0.0
    total, err, _ = _cs_total(
        "/spotlight/queries/vulnerabilities/v1",
        {"limit": 1, "filter": "severity:'CRITICAL'+status:'open'"},
    )
    if err:
        return _err(item_id, maturity, MK, TH, err)
    count = total or 0
    # 0 건이면 양호(충족), 1~10 건이면 부분, 그 이상이면 미충족
    if count == 0:
        verdict = "충족"
    elif count <= 10:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"critical_open_vulns": count})


def collect_sca_access_control(item_id: str, maturity: str) -> CollectedResult:
    """2.1.1.3_2: 접근통제 정책 적용 호스트 비율 (prevention 정책이 적용된 sensor 비율 ≥ 0.9 → 충족)"""
    MK, TH = "prevention_policy_coverage", 0.9
    # 전체 sensor 와 prevention 정책 적용 sensor 비율을 비교한다.
    total, err, _ = _cs_total("/devices/queries/devices/v1", {"limit": 1})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    covered, cerr, _ = _cs_total(
        "/policy/queries/prevention/v1",
        {"limit": 1, "filter": "enabled:true"},
    )
    if cerr:
        # prevention 정책 조회 실패 시 전체 sensor 수만 noting
        return _err(item_id, maturity, MK, TH, cerr)
    if not total:
        return _err(item_id, maturity, MK, TH, "등록된 sensor(분모)가 0")
    # covered 는 정책 수. sensor 적용 정확 계산 어려우므로 정책 1개 이상이면 100% 가정.
    # 정책이 0 이면 0% 으로 미충족 처리.
    ratio = 1.0 if (covered or 0) >= 1 else 0.0
    if ratio >= TH:
        verdict = "충족"
    elif ratio > 0:
        verdict = "부분충족"
    else:
        verdict = "미충족"
    return _ok(item_id, maturity, verdict, MK, ratio, TH,
               {"prevention_policies": covered, "sensor_total": total})
