"""splunk_collector.py — Splunk Enterprise / Cloud 진단 함수 (Phase A: 15개)

wazuh_collector.py 와 동일한 추상을 가진 SIEM 진단 모듈.
인증: Splunk REST API admin (Basic Auth) — `https://<host>:8089/services/...`.
검색: `POST /services/search/jobs/export` (streaming/blocking) 를 사용해
SPL 결과 라인 수만 집계한다. self-signed 인증서가 흔하므로 verify=False.

item_id 체계는 wazuh 와 동일하며, dispatcher autodiscover 가 docstring 첫 줄로
매핑을 자동 추출한다.
"""
from typing import Optional, Any, Tuple
from datetime import datetime, timezone
import os
import json
import logging

import httpx

CollectedResult = dict
logger = logging.getLogger(__name__)

# fallback 환경변수 — 사용자가 NewAssessment에서 자격을 직접 입력하지 않은 경우 사용
SPLUNK_URL      = os.environ.get("SPLUNK_URL", "")
SPLUNK_USER     = os.environ.get("SPLUNK_USER", "")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "")
SPLUNK_TOKEN    = os.environ.get("SPLUNK_TOKEN", "")

# ─── session-scoped credential override ──────────────────────────────────────
_session_creds: Optional[dict] = None


def set_session_creds(creds: Optional[dict]) -> None:
    """세션 단위 Splunk 자격을 모듈 전역에 주입. None 이면 해제."""
    global _session_creds
    _session_creds = creds or None


def _splunk_url() -> str:
    if _session_creds and _session_creds.get("url"):
        return str(_session_creds["url"]).rstrip("/")
    return (SPLUNK_URL or "").rstrip("/")


def _splunk_user() -> str:
    if _session_creds and _session_creds.get("user"):
        return str(_session_creds["user"])
    return SPLUNK_USER


def _splunk_pass() -> str:
    if _session_creds and _session_creds.get("password"):
        return str(_session_creds["password"])
    return SPLUNK_PASSWORD


def _splunk_token() -> str:
    if _session_creds and _session_creds.get("token"):
        return str(_session_creds["token"])
    return SPLUNK_TOKEN


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
        "tool":         "splunk",
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


def _auth_headers() -> dict:
    token = _splunk_token()
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


def _basic_auth() -> Optional[tuple]:
    if _splunk_token():
        return None
    u, p = _splunk_user(), _splunk_pass()
    if u and p:
        return (u, p)
    return None


def _splunk_get(path: str, params: dict = None, timeout: int = 30) -> Tuple[Optional[Any], Optional[str]]:
    """Splunk REST GET. output_mode=json 자동 첨부. (data, error) 반환."""
    base = _splunk_url()
    if not base:
        return None, "Splunk 미연결: URL 미설정"
    if not (_basic_auth() or _auth_headers()):
        return None, "Splunk 미연결: 자격 미설정"
    q = dict(params or {})
    q.setdefault("output_mode", "json")
    try:
        resp = httpx.get(
            f"{base}{path}",
            headers=_auth_headers(),
            auth=_basic_auth(),
            params=q,
            verify=False,  # self-signed 흔함
            timeout=timeout,
        )
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    if resp.status_code == 401:
        return None, "Splunk 인증 실패: user/password 또는 token 확인"
    if resp.status_code == 403:
        return None, "Splunk 권한 부족: 자격이 해당 endpoint 접근 권한 부족"
    try:
        body = resp.json()
    except Exception:
        body = None
    if 400 <= resp.status_code:
        return None, f"Splunk API 오류: HTTP {resp.status_code}"
    return body, None


def _splunk_search_count(spl_query: str, earliest: str = "-30d", latest: str = "now",
                         timeout: int = 60, max_lines: int = 10000) -> Tuple[Optional[int], Optional[str], dict]:
    """SPL 을 동기 export 로 실행하고 결과 라인 수를 반환.

    POST /services/search/jobs/export 는 결과를 줄단위 JSON 으로 스트리밍한다.
    `| stats count` 가 포함된 SPL 이면 count 값을 그대로, 아니면 라인 수를 카운트.
    """
    base = _splunk_url()
    if not base:
        return None, "Splunk 미연결: URL 미설정", {}
    if not (_basic_auth() or _auth_headers()):
        return None, "Splunk 미연결: 자격 미설정", {}

    if not spl_query.lstrip().lower().startswith("search "):
        # `search ` 키워드 없으면 prefix 추가
        spl_query = f"search {spl_query}"

    data = {
        "search":       spl_query,
        "earliest_time": earliest,
        "latest_time":   latest,
        "output_mode":  "json",
    }
    try:
        resp = httpx.post(
            f"{base}/services/search/jobs/export",
            headers=_auth_headers(),
            auth=_basic_auth(),
            data=data,
            verify=False,
            timeout=timeout,
        )
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}", {}

    if resp.status_code == 401:
        return None, "Splunk 인증 실패", {}
    if resp.status_code == 403:
        return None, "Splunk 권한 부족", {}
    if 400 <= resp.status_code:
        return None, f"Splunk search 오류: HTTP {resp.status_code}", {}

    # 응답 본문은 줄단위 JSON. 마지막 결과/총 카운트만 본다.
    count = 0
    last_result: dict = {}
    text = resp.text or ""
    for idx, line in enumerate(text.splitlines()):
        if idx >= max_lines:
            break
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        # `result` 키가 있으면 단일 이벤트, `preview`/`lastrow` 등은 메타.
        if "result" in obj:
            count += 1
            last_result = obj.get("result") or {}
    # `| stats count` 처럼 단일 count 결과가 있으면 그 값을 채택.
    stat_count = None
    if isinstance(last_result, dict):
        c = last_result.get("count")
        if c is not None:
            try:
                stat_count = int(c)
            except (TypeError, ValueError):
                stat_count = None
    if stat_count is not None and count <= 1:
        return stat_count, None, {"mode": "stats_count", "value": stat_count}
    return count, None, {"mode": "event_count", "value": count}


# ─────────────────────────── collectors (15) ───────────────────────────

def collect_auth_failure_alerts(item_id: str, maturity: str) -> CollectedResult:
    """1.1.1.3_2: 인증 실패 알람 ≥ 1 → 충족"""
    MK, TH = "auth_failure_alerts", 1.0
    spl = 'search tag=authentication action=failure | stats count'
    cnt, err, raw = _splunk_search_count(spl)
    if err:
        return _err(item_id, maturity, MK, TH, err, raw)
    verdict = "충족" if (cnt or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(cnt or 0), TH,
               {"alerts": cnt, **(raw or {})})


def collect_active_response_auth(item_id: str, maturity: str) -> CollectedResult:
    """1.2.1.4_1: 적응형(adaptive) 대응 이력 ≥ 1 → 충족"""
    MK, TH = "active_response_count", 1.0
    spl = 'search index=_audit action=adaptive_response OR tag=adaptive_response | stats count'
    cnt, err, raw = _splunk_search_count(spl)
    if err:
        return _err(item_id, maturity, MK, TH, err, raw)
    verdict = "충족" if (cnt or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(cnt or 0), TH,
               {"adaptive_responses": cnt})


def collect_high_risk_alerts(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1.4_2: 최근 30일 high severity 알람 ≥ 1 → 충족"""
    MK, TH = "high_risk_alerts_30d", 1.0
    spl = 'search severity=high OR severity_label=high | stats count'
    cnt, err, raw = _splunk_search_count(spl, earliest="-30d")
    if err:
        return _err(item_id, maturity, MK, TH, err, raw)
    verdict = "충족" if (cnt or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(cnt or 0), TH,
               {"high_risk_alerts": cnt})


def collect_behavior_alerts(item_id: str, maturity: str) -> CollectedResult:
    """1.3.2.3_1: UBA/risk-based 행위 알람 ≥ 1 → 충족"""
    MK, TH = "behavior_alerts", 1.0
    spl = 'search (tag=ueba OR tag=risk OR source=*risk*) | stats count'
    cnt, err, raw = _splunk_search_count(spl)
    if err:
        return _err(item_id, maturity, MK, TH, err, raw)
    verdict = "충족" if (cnt or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(cnt or 0), TH,
               {"behavior_alerts": cnt})


def collect_activity_rules(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.1_1: 활성 saved alert search 수 ≥ 1 → 충족"""
    MK, TH = "saved_searches_active", 1.0
    data, err = _splunk_get("/services/saved/searches", {"count": 0})
    if err:
        return _err(item_id, maturity, MK, TH, err)
    entries = ((data or {}).get("entry") or []) if isinstance(data, dict) else []
    # alert 가 활성화된 것만 (alert.track=1 또는 is_scheduled=1)
    active = 0
    for e in entries:
        content = (e.get("content") or {}) if isinstance(e, dict) else {}
        if str(content.get("is_scheduled") or "").lower() in {"1", "true"}:
            active += 1
        elif str(content.get("alert.track") or "").lower() in {"1", "true"}:
            active += 1
    verdict = "충족" if active >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(active), TH,
               {"saved_searches_active": active, "saved_searches_total": len(entries)})


def collect_privilege_change_alerts(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.3_2: 권한 변경 알람 ≥ 1 → 충족"""
    MK, TH = "privilege_change_alerts", 1.0
    spl = 'search (tag=privilege_change OR tag=account_management action=modify) | stats count'
    cnt, err, raw = _splunk_search_count(spl)
    if err:
        return _err(item_id, maturity, MK, TH, err, raw)
    verdict = "충족" if (cnt or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(cnt or 0), TH,
               {"privilege_change_alerts": cnt})


def collect_policy_violation_alerts(item_id: str, maturity: str) -> CollectedResult:
    """2.1.1.2_2: 정책 위반 알람 ≥ 1 → 충족"""
    MK, TH = "policy_violation_alerts", 1.0
    spl = 'search (tag=policy_violation OR signature="*policy*violation*") | stats count'
    cnt, err, raw = _splunk_search_count(spl)
    if err:
        return _err(item_id, maturity, MK, TH, err, raw)
    verdict = "충족" if (cnt or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(cnt or 0), TH,
               {"policy_violation_alerts": cnt})


def collect_os_inventory(item_id: str, maturity: str) -> CollectedResult:
    """2.2.1.1_1: OS 호스트 인벤토리 수 ≥ 1 → 충족"""
    MK, TH = "os_host_count", 1.0
    # nix + windows 합산. host 필드 distinct count.
    spl = 'search (sourcetype=*nix* OR sourcetype=*windows* OR sourcetype=WinEventLog*) | stats dc(host) AS count'
    cnt, err, raw = _splunk_search_count(spl)
    if err:
        return _err(item_id, maturity, MK, TH, err, raw)
    verdict = "충족" if (cnt or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(cnt or 0), TH,
               {"os_host_count": cnt})


def collect_agent_registration(item_id: str, maturity: str) -> CollectedResult:
    """2.3.1.1_2: deployment client(universal forwarder) 등록 수 ≥ 1 → 충족"""
    MK, TH = "deployment_clients", 1.0
    data, err = _splunk_get("/services/deployment/server/clients", {"count": 0})
    if err:
        # fallback: forwarder 메트릭 검색
        cnt, serr, raw = _splunk_search_count(
            'search index=_internal sourcetype=splunkd group=tcpin_connections | stats dc(hostname) AS count'
        )
        if serr:
            return _err(item_id, maturity, MK, TH, err, {"raw": raw})
        verdict = "충족" if (cnt or 0) >= TH else "미충족"
        return _ok(item_id, maturity, verdict, MK, float(cnt or 0), TH,
                   {"source": "tcpin_metric", "clients": cnt})
    entries = ((data or {}).get("entry") or []) if isinstance(data, dict) else []
    count = len(entries)
    verdict = "충족" if count >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(count), TH,
               {"source": "deployment_server", "clients": count})


def collect_segment_policy_alerts(item_id: str, maturity: str) -> CollectedResult:
    """3.1.2.1_2: 네트워크 세그먼테이션 정책 위반 알람 ≥ 1 → 충족"""
    MK, TH = "segment_violation_alerts", 1.0
    spl = 'search (tag=network_segmentation OR signature="*segment*violation*") | stats count'
    cnt, err, raw = _splunk_search_count(spl)
    if err:
        return _err(item_id, maturity, MK, TH, err, raw)
    verdict = "충족" if (cnt or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(cnt or 0), TH,
               {"segment_violation_alerts": cnt})


def collect_lateral_movement_alerts(item_id: str, maturity: str) -> CollectedResult:
    """3.4.1.1_2: 측면 이동(lateral movement) 탐지 알람 ≥ 1 → 충족"""
    MK, TH = "lateral_movement_alerts", 1.0
    spl = 'search (tag=lateral_movement OR signature="*lateral*movement*") | stats count'
    cnt, err, raw = _splunk_search_count(spl)
    if err:
        return _err(item_id, maturity, MK, TH, err, raw)
    verdict = "충족" if (cnt or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(cnt or 0), TH,
               {"lateral_movement_alerts": cnt})


def collect_ids_alerts(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.3_2: IDS/IPS 알람 ≥ 1 → 충족"""
    MK, TH = "ids_alerts", 1.0
    spl = 'search (tag=ids OR tag=ips OR sourcetype=snort OR sourcetype=suricata) | stats count'
    cnt, err, raw = _splunk_search_count(spl)
    if err:
        return _err(item_id, maturity, MK, TH, err, raw)
    verdict = "충족" if (cnt or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(cnt or 0), TH,
               {"ids_alerts": cnt})


def collect_realtime_threat_alerts(item_id: str, maturity: str) -> CollectedResult:
    """4.4.1.1_2: 실시간 threat detection 알람 ≥ 1 → 충족"""
    MK, TH = "realtime_threat_alerts", 1.0
    spl = ('search (tag=threat OR tag=attack OR sourcetype=*threat*) '
           'earliest=-15m | stats count')
    cnt, err, raw = _splunk_search_count(spl, earliest="-15m")
    if err:
        return _err(item_id, maturity, MK, TH, err, raw)
    verdict = "충족" if (cnt or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(cnt or 0), TH,
               {"realtime_threat_alerts": cnt})


def collect_dlp_alerts(item_id: str, maturity: str) -> CollectedResult:
    """5.1.1.4_1: DLP 이벤트 ≥ 1 → 충족"""
    MK, TH = "dlp_alerts", 1.0
    spl = 'search (tag=dlp OR signature="*data*loss*") | stats count'
    cnt, err, raw = _splunk_search_count(spl)
    if err:
        return _err(item_id, maturity, MK, TH, err, raw)
    verdict = "충족" if (cnt or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(cnt or 0), TH,
               {"dlp_alerts": cnt})


def collect_threat_detection_alerts(item_id: str, maturity: str) -> CollectedResult:
    """5.2.1.4_2: 종합 threat detection 알람 ≥ 1 → 충족"""
    MK, TH = "threat_detection_alerts", 1.0
    spl = 'search (tag=threat OR tag=malware OR sourcetype=*threat*) | stats count'
    cnt, err, raw = _splunk_search_count(spl)
    if err:
        return _err(item_id, maturity, MK, TH, err, raw)
    verdict = "충족" if (cnt or 0) >= TH else "미충족"
    return _ok(item_id, maturity, verdict, MK, float(cnt or 0), TH,
               {"threat_detection_alerts": cnt})
