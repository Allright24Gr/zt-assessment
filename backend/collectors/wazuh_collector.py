import os
import time
import requests
import urllib3
from datetime import datetime, timezone, timedelta
from typing import Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CollectedResult = dict

WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://localhost:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh")
WAZUH_API_PASS = os.environ.get("WAZUH_API_PASS", "wazuh")
WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASS = os.environ.get("WAZUH_INDEXER_PASS", "admin")

_token_cache: dict = {"token": None, "expires_at": 0.0}
_indexer_session: Optional[requests.Session] = None


# ─── helpers ─────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_dt(s: str) -> Optional[datetime]:
    if not s or s == "N/A":
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _get_wazuh_token() -> str:
    global _token_cache
    if _token_cache["token"] and time.time() < _token_cache["expires_at"] - 30:
        return _token_cache["token"]
    resp = requests.post(
        f"{WAZUH_API_URL}/security/user/authenticate",
        auth=(WAZUH_API_USER, WAZUH_API_PASS),
        verify=False,
        timeout=10,
    )
    resp.raise_for_status()
    token = resp.json()["data"]["token"]
    _token_cache["token"] = token
    _token_cache["expires_at"] = time.time() + 900
    return token


def _get_indexer_session() -> requests.Session:
    global _indexer_session
    if _indexer_session is None:
        session = requests.Session()
        session.auth = (WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS)
        session.verify = False
        _indexer_session = session
    return _indexer_session


def _indexer_count(index_pattern: str, query_dsl: dict) -> int:
    session = _get_indexer_session()
    body = dict(query_dsl)
    body["size"] = 0
    body["track_total_hits"] = True
    resp = session.post(
        f"{WAZUH_INDEXER_URL}/{index_pattern}/_search",
        json=body,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["hits"]["total"]["value"]


def _indexer_search(index_pattern: str, query_dsl: dict) -> dict:
    session = _get_indexer_session()
    resp = session.post(
        f"{WAZUH_INDEXER_URL}/{index_pattern}/_search",
        json=query_dsl,
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def _wazuh_get(path: str, params: dict = None) -> dict:
    token = _get_wazuh_token()
    resp = requests.get(
        f"{WAZUH_API_URL}{path}",
        headers={"Authorization": f"Bearer {token}"},
        params=params,
        verify=False,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def _get_active_agents() -> list:
    agents, offset, limit = [], 0, 500
    while True:
        data = _wazuh_get("/agents", params={"status": "active", "limit": limit, "offset": offset})
        items = data.get("data", {}).get("affected_items", [])
        agents.extend(items)
        if len(agents) >= data.get("data", {}).get("total_affected_items", 0):
            break
        offset += limit
    return agents


def _get_all_agents() -> list:
    agents, offset, limit = [], 0, 500
    while True:
        data = _wazuh_get("/agents", params={"limit": limit, "offset": offset})
        items = data.get("data", {}).get("affected_items", [])
        agents.extend(items)
        if len(agents) >= data.get("data", {}).get("total_affected_items", 0):
            break
        offset += limit
    return agents


def _err(item_id: str, maturity: str, metric_key: str, threshold: float,
         error: str, raw: dict = None) -> CollectedResult:
    return {
        "item_id": item_id, "maturity": maturity, "tool": "wazuh",
        "result": "평가불가", "metric_key": metric_key, "metric_value": 0.0,
        "threshold": threshold, "raw_json": raw or {}, "collected_at": _now_iso(),
        "error": error,
    }


def _ok(item_id: str, maturity: str, result: str, metric_key: str,
        metric_value: float, threshold: float, raw: dict) -> CollectedResult:
    return {
        "item_id": item_id, "maturity": maturity, "tool": "wazuh",
        "result": result, "metric_key": metric_key, "metric_value": metric_value,
        "threshold": threshold, "raw_json": raw, "collected_at": _now_iso(),
        "error": None,
    }


# ─── 1. collect_auth_failure_alerts ──────────────────────────────────────────

def collect_auth_failure_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "auth_failure_alert_count", 1.0, {}
    rule_enabled: Optional[bool] = None
    try:
        r = _wazuh_get("/rules", {"search": "authentication_failure", "status": "enabled", "limit": 1})
        raw["rules"] = r
        rule_enabled = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        raw["rules_error"] = str(e)

    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"must": [
                {"terms": {"rule.groups": ["authentication_failure", "authentication_failed"]}},
                {"range": {"@timestamp": {"gte": "now-86400s"}}}
            ]}},
        })
        raw["indexer"] = ir
        count = float(ir["hits"]["total"]["value"])
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)

    if rule_enabled is True and count >= 1:
        res = "충족"
    elif rule_enabled is True and count == 0:
        res = "부분충족"
    elif rule_enabled is None:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


# ─── 2. collect_active_response_auth ─────────────────────────────────────────

def collect_active_response_auth(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "auth_autoresponse_count", 1.0, {}
    rule_count = 0
    try:
        r = _wazuh_get("/rules", {"search": "authentication_failure", "status": "enabled"})
        raw["rules"] = r
        rule_count = r.get("data", {}).get("total_affected_items", 0)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    ar_count = 0
    ar_err = None
    try:
        ar = _wazuh_get("/active-response")
        raw["active_response"] = ar
        ar_count = len(ar.get("data", {}).get("affected_items", []))
    except Exception as e:
        raw["ar_error"] = str(e)
        ar_err = str(e)

    if ar_err:
        res = "부분충족" if rule_count >= 1 else "미충족"
        return {**_ok(item_id, maturity, res, mk, 0.0, thr, raw), "error": ar_err}

    if rule_count >= 1 and ar_count >= 1:
        res = "충족"
    elif rule_count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, float(ar_count), thr, raw)


# ─── 3. collect_agent_sca_ratio ──────────────────────────────────────────────

def collect_agent_sca_ratio(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "sca_collection_ratio", 0.8, {}
    try:
        agents = _get_active_agents()
        raw["agent_count"] = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    active_count = len(agents)
    if active_count == 0:
        return _ok(item_id, maturity, "미충족", mk, 0.0, thr, raw)

    sca_ok = 0
    for a in agents:
        try:
            r = _wazuh_get(f"/sca/{a['id']}", {"limit": 1})
            if r.get("data", {}).get("affected_items"):
                sca_ok += 1
        except Exception:
            pass

    ratio = sca_ok / active_count
    raw["sca_ok_count"] = sca_ok
    res = "충족" if ratio >= 0.8 else "부분충족"
    return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, raw)


# ─── 4. collect_sca_average ──────────────────────────────────────────────────

def collect_sca_average(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "sca_avg_score", 70.0, {}
    try:
        agents = _get_active_agents()
        raw["agent_count"] = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    if not agents:
        return _err(item_id, maturity, mk, thr, "에이전트 0개")

    scores = []
    for a in agents:
        try:
            r = _wazuh_get(f"/sca/{a['id']}")
            for item in r.get("data", {}).get("affected_items", []):
                if "score" in item:
                    scores.append(item["score"])
        except Exception:
            pass

    if not scores:
        return _err(item_id, maturity, mk, thr, "SCA 결과 0개")

    avg = sum(scores) / len(scores)
    raw["avg_score"] = avg
    if avg >= 70:
        res = "충족"
    elif avg >= 50:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, round(avg, 2), thr, raw)


# ─── 5. collect_high_risk_alerts ─────────────────────────────────────────────

def collect_high_risk_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "high_risk_alert_count", 0.0, {}
    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 10, "track_total_hits": True,
            "query": {"bool": {"must": [
                {"range": {"rule.level": {"gte": 10}}},
                {"range": {"@timestamp": {"gte": "now-3600s"}}}
            ]}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        })
        raw["indexer"] = ir
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    count = float(ir["hits"]["total"]["value"])
    hits = ir.get("hits", {}).get("hits", [])
    delay_sec = None
    if hits:
        ts = _parse_dt(hits[0].get("_source", {}).get("@timestamp", ""))
        if ts:
            delay_sec = (datetime.now(timezone.utc) - ts).total_seconds()

    if count >= 1 and delay_sec is not None and delay_sec <= 60:
        res = "충족"
    elif count >= 1:
        res = "부분충족"
    else:
        raw["note"] = "no_alerts_in_1h"
        res = "부분충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


# ─── 6. collect_behavior_alerts ──────────────────────────────────────────────

def collect_behavior_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "behavior_alert_count", 1.0, {}
    rule_enabled: Optional[bool] = None
    try:
        r = _wazuh_get("/rules", {"search": "authentication", "status": "enabled", "limit": 1})
        raw["rules"] = r
        rule_enabled = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        raw["rules_error"] = str(e)

    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"must": [
                {"bool": {"should": [
                    {"term": {"rule.groups": "authentication"}},
                    {"term": {"rule.groups": "anomaly"}}
                ]}},
                {"range": {"@timestamp": {"gte": "now-86400s"}}}
            ]}},
        })
        raw["indexer"] = ir
        count = float(ir["hits"]["total"]["value"])
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)

    if rule_enabled is True and count >= 1:
        res = "충족"
    elif rule_enabled is True:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


# ─── 7. collect_activity_rules ───────────────────────────────────────────────

def collect_activity_rules(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "activity_rule_count", 1.0, {}
    try:
        agents = _get_active_agents()
        raw["agent_count"] = len(agents)
        active_count = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    try:
        r = _wazuh_get("/rules", {"search": "syslog", "status": "enabled"})
        raw["rules"] = r
        rule_count = r.get("data", {}).get("total_affected_items", 0)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)

    if active_count >= 1 and rule_count >= 1:
        res = "충족"
    elif active_count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, float(rule_count), thr, raw)


# ─── 8. collect_privilege_change_alerts ──────────────────────────────────────

def collect_privilege_change_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "privilege_change_alert_count", 1.0, {}
    rule_enabled: Optional[bool] = None
    try:
        r = _wazuh_get("/rules", {"search": "policy_changed", "status": "enabled", "limit": 1})
        raw["rules"] = r
        rule_enabled = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        raw["rules_error"] = str(e)

    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"must": [
                {"bool": {"should": [
                    {"term": {"rule.groups": "policy_changed"}},
                    {"term": {"rule.groups": "privilege_escalation"}}
                ]}},
                {"range": {"@timestamp": {"gte": "now-2592000s"}}}
            ]}},
        })
        raw["indexer"] = ir
        count = float(ir["hits"]["total"]["value"])
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)

    if rule_enabled is True and count >= 1:
        res = "충족"
    elif rule_enabled is True:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


# ─── 9. collect_sca_compliance ───────────────────────────────────────────────

def collect_sca_compliance(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "sca_active_ratio", 0.9, {}
    try:
        agents = _get_active_agents()
        raw["agent_count"] = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    denom = len(agents)
    if denom == 0:
        return _ok(item_id, maturity, "미충족", mk, 0.0, thr, raw)

    numer = 0
    for a in agents:
        try:
            r = _wazuh_get(f"/sca/{a['id']}", {"limit": 1})
            if r.get("data", {}).get("affected_items"):
                numer += 1
        except Exception:
            pass

    ratio = numer / denom
    raw["sca_count"] = numer
    if ratio >= 0.9:
        res = "충족"
    elif ratio >= 0.5:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, raw)


# ─── 10. collect_policy_violation_alerts ─────────────────────────────────────

def collect_policy_violation_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "policy_violation_count", 1.0, {}
    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"term": {"rule.groups": "policy_violation"}},
        })
        raw["indexer"] = ir
        alert_count = float(ir["hits"]["total"]["value"])
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    ar_count = 0
    try:
        ar = _wazuh_get("/active-response")
        raw["active_response"] = ar
        ar_count = len(ar.get("data", {}).get("affected_items", []))
    except Exception as e:
        raw["ar_error"] = str(e)

    if alert_count >= 1 and ar_count >= 1:
        res = "충족"
    elif alert_count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, alert_count, thr, raw)


# ─── 11. collect_sca_auto_remediation ────────────────────────────────────────

def collect_sca_auto_remediation(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "sca_autofix_count", 1.0, {}
    try:
        agents = _get_active_agents()
        raw["agent_count"] = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    scores = []
    for a in agents:
        try:
            r = _wazuh_get(f"/sca/{a['id']}")
            for item in r.get("data", {}).get("affected_items", []):
                if "score" in item:
                    scores.append(item["score"])
        except Exception:
            pass

    sca_avg = sum(scores) / len(scores) if scores else 0.0
    raw["sca_avg"] = sca_avg

    ar_count = 0
    try:
        ar = _wazuh_get("/active-response")
        raw["active_response"] = ar
        ar_count = len(ar.get("data", {}).get("affected_items", []))
    except Exception as e:
        raw["ar_error"] = str(e)

    if sca_avg >= 70 and ar_count >= 1:
        res = "충족"
    elif sca_avg >= 70:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, float(ar_count), thr, raw)


# ─── 12. collect_os_inventory ────────────────────────────────────────────────

def collect_os_inventory(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "os_inventory_ratio", 0.9, {}
    try:
        agents = _get_active_agents()
        raw["agent_count"] = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    denom = len(agents)
    if denom == 0:
        return _err(item_id, maturity, mk, thr, "활성 에이전트 0개")

    numer = 0
    for a in agents:
        try:
            r = _wazuh_get(f"/syscollector/{a['id']}/os")
            if r.get("data", {}).get("affected_items"):
                numer += 1
        except Exception:
            pass

    ratio = numer / denom
    raw["os_count"] = numer
    if ratio >= 0.9:
        res = "충족"
    elif ratio >= 0.5:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, raw)


# ─── 13. collect_sca_access_control ──────────────────────────────────────────

def collect_sca_access_control(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "sca_pass_ratio", 0.8, {}
    try:
        agents = _get_active_agents()
        raw["agent_count"] = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    sca_data = []
    for a in agents:
        try:
            r = _wazuh_get(f"/sca/{a['id']}")
            for item in r.get("data", {}).get("affected_items", []):
                sca_data.append(item)
        except Exception:
            pass

    denom = len(sca_data)
    if denom == 0:
        return _err(item_id, maturity, mk, thr, "SCA 결과 없음")

    numer = sum(1 for s in sca_data if s.get("score", 0) >= 70)
    ratio = numer / denom
    raw["sca_total"] = denom
    if ratio >= 0.8:
        res = "충족"
    elif ratio >= 0.5:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, raw)


# ─── 14. collect_auto_block ──────────────────────────────────────────────────

def collect_auto_block(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "auto_block_count", 1.0, {}
    try:
        ar = _wazuh_get("/active-response")
        raw["active_response"] = ar
        ar_count = len(ar.get("data", {}).get("affected_items", []))
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    disconnected = 0
    try:
        r = _wazuh_get("/agents", {"status": "disconnected", "limit": 1})
        raw["disconnected"] = r
        disconnected = r.get("data", {}).get("total_affected_items", 0)
    except Exception as e:
        raw["agents_error"] = str(e)

    if ar_count >= 1 and disconnected >= 1:
        res = "충족"
    elif ar_count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, float(ar_count), thr, raw)


# ─── 15. collect_agent_registration ──────────────────────────────────────────

def collect_agent_registration(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "agent_registration_ratio", 1.0, {}
    try:
        agents = _get_all_agents()
        raw["agent_count"] = len(agents)
        agent_count = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    res = "충족" if agent_count >= 1 else "미충족"
    return _ok(item_id, maturity, res, mk, float(agent_count), thr, raw)


# ─── 16. collect_agent_keepalive ─────────────────────────────────────────────

def collect_agent_keepalive(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "keepalive_ratio", 0.9, {}
    now = datetime.now(timezone.utc)
    try:
        agents = _get_all_agents()
        raw["agent_count"] = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    denom = len(agents)
    if denom == 0:
        return _err(item_id, maturity, mk, thr, "에이전트 0개")

    cutoff = now - timedelta(hours=24)
    numer = sum(1 for a in agents if (ka := _parse_dt(a.get("lastKeepAlive", ""))) and ka >= cutoff)
    ratio = numer / denom
    raw["recent_count"] = numer
    if ratio >= 0.9:
        res = "충족"
    elif ratio >= 0.5:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, raw)


# ─── 17. collect_unauthorized_device_alerts ──────────────────────────────────

def collect_unauthorized_device_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "unauthorized_device_count", 1.0, {}
    rule_enabled: Optional[bool] = None
    try:
        r = _wazuh_get("/rules", {"search": "unauthorized", "status": "enabled", "limit": 1})
        raw["rules"] = r
        rule_enabled = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        raw["rules_error"] = str(e)

    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"should": [
                {"term": {"rule.groups": "unauthorized_device"}},
                {"term": {"rule.groups": "new_agent"}}
            ]}},
        })
        raw["indexer"] = ir
        count = float(ir["hits"]["total"]["value"])
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)

    if rule_enabled is True and count >= 1:
        res = "충족"
    elif rule_enabled is True:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


# ─── 18. collect_vulnerability_summary ───────────────────────────────────────

def collect_vulnerability_summary(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "vuln_scan_agent_count", 1.0, {}
    try:
        active_agents = _get_active_agents()
        raw["active_agent_count"] = len(active_agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    agent_ids = [a.get("id") for a in active_agents if a.get("id")]
    if not agent_ids:
        return _ok(item_id, maturity, "미충족", mk, 0.0, thr, raw)

    try:
        ir = _indexer_search("wazuh-states-vulnerabilities-*", {
            "size": 0, "track_total_hits": True,
            "query": {"terms": {"agent.id": agent_ids}},
            "aggs": {
                "by_agent": {"terms": {"field": "agent.id", "size": 1000}},
                "by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}},
            },
        })
        raw["indexer"] = ir
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)

    aggs = ir.get("aggregations", {})
    scan_agent_count = len(aggs.get("by_agent", {}).get("buckets", []))
    raw["scan_agent_count"] = scan_agent_count

    if scan_agent_count >= 1:
        res = "충족"
    elif active_agents:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, float(scan_agent_count), thr, raw)


# ─── 19. collect_realtime_monitoring ─────────────────────────────────────────

def collect_realtime_monitoring(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "realtime_alert_count", 1.0, {}
    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 5, "track_total_hits": True,
            "query": {"range": {"@timestamp": {"gte": "now-3600s"}}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        })
        raw["indexer"] = ir
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    count = float(ir["hits"]["total"]["value"])
    hits = ir.get("hits", {}).get("hits", [])
    delay_sec = None
    if hits:
        ts = _parse_dt(hits[0].get("_source", {}).get("@timestamp", ""))
        if ts:
            delay_sec = (datetime.now(timezone.utc) - ts).total_seconds()

    if count >= 1 and delay_sec is not None and delay_sec <= 60:
        res = "충족"
    elif count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


# ─── 20. collect_os_distribution ─────────────────────────────────────────────

def collect_os_distribution(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "agent_os_count", 1.0, {}
    try:
        agents = _get_all_agents()
        raw["agent_count"] = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    agent_count = len(agents)
    os_dist: dict = {"linux": 0, "windows": 0, "darwin": 0}
    for a in agents:
        platform = (a.get("os") or {}).get("platform", "").lower()
        for key in ("linux", "windows", "darwin"):
            if key in platform:
                os_dist[key] += 1
                break

    raw["os_dist"] = os_dist
    populated = sum(1 for v in os_dist.values() if v > 0)

    if agent_count >= 1 and populated >= 2:
        res = "충족"
    elif agent_count >= 1 and populated >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, float(agent_count), thr, raw)


# ─── 21. collect_sca_policy_ratio ────────────────────────────────────────────

def collect_sca_policy_ratio(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "sca_policy_ratio", 0.8, {}
    try:
        agents = _get_active_agents()
        raw["agent_count"] = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    denom = len(agents)
    if denom == 0:
        return _err(item_id, maturity, mk, thr, "활성 에이전트 0개")

    numer = 0
    for a in agents:
        try:
            r = _wazuh_get(f"/sca/{a['id']}", {"limit": 1})
            if r.get("data", {}).get("affected_items"):
                numer += 1
        except Exception:
            pass

    ratio = numer / denom
    raw["sca_count"] = numer
    res = "충족" if ratio >= 0.8 else "부분충족"
    return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, raw)


# ─── 22. collect_continuous_monitoring ───────────────────────────────────────

def collect_continuous_monitoring(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "continuous_monitor_ratio", 0.9, {}
    now = datetime.now(timezone.utc)
    try:
        agents = _get_all_agents()
        raw["agent_count"] = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    denom = len(agents)
    if denom == 0:
        return _err(item_id, maturity, mk, thr, "에이전트 0개")

    cutoff = now - timedelta(hours=1)
    numer = sum(1 for a in agents if (ka := _parse_dt(a.get("lastKeepAlive", ""))) and ka >= cutoff)
    ratio = numer / denom
    raw["recent_count"] = numer
    if ratio >= 0.9:
        res = "충족"
    elif ratio >= 0.5:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, raw)


# ─── 23. collect_auto_threat_response ────────────────────────────────────────

def collect_auto_threat_response(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "auto_threat_response_count", 1.0, {}
    now = datetime.now(timezone.utc)
    try:
        ar = _wazuh_get("/active-response")
        raw["active_response"] = ar
        ar_items = ar.get("data", {}).get("affected_items", [])
        ar_count = len(ar_items)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    cutoff = now - timedelta(days=30)
    recent_exec = sum(
        1 for item in ar_items
        if (t := _parse_dt(item.get("last_execution", ""))) and t >= cutoff
    )
    raw["ar_count"] = ar_count
    raw["recent_exec"] = recent_exec

    if ar_count >= 1 and recent_exec >= 1:
        res = "충족"
    elif ar_count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, float(ar_count), thr, raw)


# ─── 24. collect_edr_agents ──────────────────────────────────────────────────

def collect_edr_agents(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "edr_agent_count", 1.0, {}
    try:
        agents = _get_active_agents()
        raw["agent_count"] = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    edr_count = sum(1 for a in agents if a.get("version"))
    raw["edr_count"] = edr_count
    res = "충족" if edr_count >= 1 else "미충족"
    return _ok(item_id, maturity, res, mk, float(edr_count), thr, raw)


# ─── 25. collect_threat_detection_alerts ─────────────────────────────────────

def collect_threat_detection_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "threat_detection_count", 1.0, {}
    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"must": [
                {"bool": {"should": [
                    {"term": {"rule.groups": "malware"}},
                    {"term": {"rule.groups": "rootcheck"}},
                    {"term": {"rule.groups": "virus"}},
                ]}},
                {"range": {"@timestamp": {"gte": "now-86400s"}}}
            ]}},
        })
        raw["indexer"] = ir
        alert_count = float(ir["hits"]["total"]["value"])
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    ar_count = 0
    try:
        ar = _wazuh_get("/active-response")
        raw["active_response"] = ar
        ar_count = len(ar.get("data", {}).get("affected_items", []))
    except Exception as e:
        raw["ar_error"] = str(e)

    if alert_count >= 1 and ar_count >= 1:
        res = "충족"
    elif alert_count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, alert_count, thr, raw)


# ─── 26. collect_vuln_asset_list ─────────────────────────────────────────────

def collect_vuln_asset_list(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "vuln_asset_count", 1.0, {}
    try:
        active_agents = _get_active_agents()
        raw["active_agent_count"] = len(active_agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    agent_ids = [a.get("id") for a in active_agents if a.get("id")]
    if not agent_ids:
        return _ok(item_id, maturity, "미충족", mk, 0.0, thr, raw)

    try:
        ir = _indexer_search("wazuh-states-vulnerabilities-*", {
            "size": 0, "track_total_hits": True,
            "query": {"terms": {"agent.id": agent_ids}},
            "aggs": {
                "by_agent": {"terms": {"field": "agent.id", "size": 1000}},
                "critical": {"filter": {"term": {"vulnerability.severity": "critical"}}},
                "high": {"filter": {"term": {"vulnerability.severity": "high"}}},
            },
        })
        raw["indexer"] = ir
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)

    aggs = ir.get("aggregations", {})
    scan_count = len(aggs.get("by_agent", {}).get("buckets", []))
    raw["scan_count"] = scan_count
    raw["critical_count"] = aggs.get("critical", {}).get("doc_count", 0)
    raw["high_count"] = aggs.get("high", {}).get("doc_count", 0)

    res = "충족" if scan_count >= 1 else "미충족"
    return _ok(item_id, maturity, res, mk, float(scan_count), thr, raw)


# ─── 27. collect_vuln_scan_ratio ─────────────────────────────────────────────

def collect_vuln_scan_ratio(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "vuln_scan_ratio", 0.9, {}
    try:
        active_agents = _get_active_agents()
        raw["active_agent_count"] = len(active_agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    denom = len(active_agents)
    if denom == 0:
        return _err(item_id, maturity, mk, thr, "활성 에이전트 0개")

    agent_ids = [a.get("id") for a in active_agents if a.get("id")]
    try:
        ir = _indexer_search("wazuh-states-vulnerabilities-*", {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"must": [
                {"terms": {"agent.id": agent_ids}},
                {"range": {"@timestamp": {"gte": "now-86400s"}}}
            ]}},
            "aggs": {"by_agent": {"terms": {"field": "agent.id", "size": 1000}}},
        })
        raw["indexer"] = ir
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)

    numer = len(ir.get("aggregations", {}).get("by_agent", {}).get("buckets", []))
    ratio = numer / denom
    raw["scan_agent_count"] = numer
    if ratio >= 0.9:
        res = "충족"
    elif ratio >= 0.5:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, raw)


# ─── 28. collect_critical_unfixed_vulns ──────────────────────────────────────

def collect_critical_unfixed_vulns(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "critical_unfixed_count", 0.0, {}
    try:
        active_agents = _get_active_agents()
        raw["active_agent_count"] = len(active_agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    agent_ids = [a.get("id") for a in active_agents if a.get("id")]
    if not agent_ids:
        return _err(item_id, maturity, mk, thr, "활성 에이전트 0개")

    try:
        ir = _indexer_search("wazuh-states-vulnerabilities-*", {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"must": [
                {"terms": {"agent.id": agent_ids}},
                {"term": {"vulnerability.severity": "critical"}},
                {"term": {"vulnerability.status": "VULNERABLE"}},
            ]}},
        })
        raw["indexer"] = ir
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)

    unfixed = float(ir["hits"]["total"]["value"])
    raw["unfixed_count"] = unfixed
    if unfixed == 0:
        res = "충족"
    elif unfixed <= 5:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, unfixed, thr, raw)


# ─── 29. collect_segment_policy_alerts ───────────────────────────────────────

def collect_segment_policy_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "segment_policy_alert_count", 1.0, {}
    rule_enabled: Optional[bool] = None
    try:
        r = _wazuh_get("/rules", {"search": "network_policy", "status": "enabled", "limit": 1})
        raw["rules"] = r
        rule_enabled = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        raw["rules_error"] = str(e)

    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"term": {"rule.groups": "network_policy"}},
        })
        raw["indexer"] = ir
        count = float(ir["hits"]["total"]["value"])
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)

    if rule_enabled is True and count >= 1:
        res = "충족"
    elif rule_enabled is True:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


# ─── 30. collect_lateral_movement_alerts ─────────────────────────────────────

def collect_lateral_movement_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "lateral_movement_count", 1.0, {}
    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"should": [
                {"term": {"rule.groups": "lateral_movement"}},
                {"term": {"rule.groups": "network_scan"}},
            ]}},
        })
        raw["indexer"] = ir
        alert_count = float(ir["hits"]["total"]["value"])
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    ar_count = 0
    try:
        ar = _wazuh_get("/active-response")
        raw["active_response"] = ar
        ar_count = len(ar.get("data", {}).get("affected_items", []))
    except Exception as e:
        raw["ar_error"] = str(e)

    if ar_count >= 1 and alert_count >= 1:
        res = "충족"
    elif ar_count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, alert_count, thr, raw)


# ─── 31. collect_ids_alerts ──────────────────────────────────────────────────

def collect_ids_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "ids_alert_count", 1.0, {}
    rule_enabled: Optional[bool] = None
    try:
        r = _wazuh_get("/rules", {"search": "ids", "status": "enabled", "limit": 1})
        raw["rules"] = r
        rule_enabled = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        raw["rules_error"] = str(e)

    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"must": [
                {"bool": {"should": [
                    {"term": {"rule.groups": "ids"}},
                    {"term": {"rule.groups": "intrusion_detection"}},
                ]}},
                {"range": {"@timestamp": {"gte": "now-86400s"}}}
            ]}},
        })
        raw["indexer"] = ir
        count = float(ir["hits"]["total"]["value"])
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)

    if rule_enabled is True and count >= 1:
        res = "충족"
    elif rule_enabled is True:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


# ─── 32. collect_attack_response ─────────────────────────────────────────────

def collect_attack_response(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "attack_response_count", 1.0, {}
    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"term": {"rule.groups": "attack"}},
        })
        raw["indexer"] = ir
        alert_count = float(ir["hits"]["total"]["value"])
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    ar_count = 0
    try:
        ar = _wazuh_get("/active-response")
        raw["active_response"] = ar
        ar_count = len(ar.get("data", {}).get("affected_items", []))
    except Exception as e:
        raw["ar_error"] = str(e)

    if alert_count >= 1 and ar_count >= 1:
        res = "충족"
    elif alert_count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, alert_count, thr, raw)


# ─── 33. collect_realtime_threat_alerts ──────────────────────────────────────

def collect_realtime_threat_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "realtime_threat_count", 1.0, {}
    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 5, "track_total_hits": True,
            "query": {"bool": {"must": [
                {"range": {"rule.level": {"gte": 7}}},
                {"range": {"@timestamp": {"gte": "now-3600s"}}},
            ]}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        })
        raw["indexer"] = ir
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    count = float(ir["hits"]["total"]["value"])
    hits = ir.get("hits", {}).get("hits", [])
    delay_sec = None
    if hits:
        ts = _parse_dt(hits[0].get("_source", {}).get("@timestamp", ""))
        if ts:
            delay_sec = (datetime.now(timezone.utc) - ts).total_seconds()

    if count >= 1 and delay_sec is not None and delay_sec <= 60:
        res = "충족"
    elif count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


# ─── 34. collect_tls_cleartext_alerts ────────────────────────────────────────

def collect_tls_cleartext_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "cleartext_alert_count", 0.0, {}
    rule_enabled: Optional[bool] = None
    try:
        r = _wazuh_get("/rules", {"search": "cleartext", "status": "enabled", "limit": 1})
        raw["rules"] = r
        rule_enabled = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    count = 0.0
    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"should": [
                {"term": {"rule.groups": "cleartext"}},
                {"term": {"rule.groups": "unencrypted"}},
            ]}},
        })
        raw["indexer"] = ir
        count = float(ir["hits"]["total"]["value"])
    except Exception as e:
        raw["indexer_error"] = str(e)

    res = "충족" if rule_enabled else "미충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


# ─── 35. collect_backup_history ──────────────────────────────────────────────

def collect_backup_history(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "backup_history_count", 1.0, {}
    now = datetime.now(timezone.utc)
    try:
        agents = _get_all_agents()
        raw["agent_count"] = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    cutoff = now - timedelta(hours=24)
    recent_count = sum(
        1 for a in agents
        if (ka := _parse_dt(a.get("lastKeepAlive", ""))) and ka >= cutoff
    )
    raw["recent_count"] = recent_count
    res = "충족" if recent_count >= 1 else "미충족"
    return _ok(item_id, maturity, res, mk, float(recent_count), thr, raw)


# ─── 36. collect_agent_uptime ─────────────────────────────────────────────────

def collect_agent_uptime(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "agent_uptime_ratio", 0.99, {}
    try:
        agents = _get_all_agents()
        raw["agent_count"] = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    denom = len(agents)
    if denom == 0:
        return _err(item_id, maturity, mk, thr, "에이전트 0개")

    numer = sum(1 for a in agents if a.get("status") == "active")
    ratio = numer / denom
    raw["active_count"] = numer
    if ratio >= 0.99:
        res = "충족"
    elif ratio >= 0.95:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, raw)


# ─── 37. collect_policy_change_alerts ────────────────────────────────────────

def collect_policy_change_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "policy_change_alert_count", 1.0, {}
    rule_enabled: Optional[bool] = None
    try:
        r = _wazuh_get("/rules", {"search": "policy_changed", "status": "enabled", "limit": 1})
        raw["rules"] = r
        rule_enabled = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        raw["rules_error"] = str(e)

    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"term": {"rule.groups": "policy_changed"}},
        })
        raw["indexer"] = ir
        count = float(ir["hits"]["total"]["value"])
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)

    if count >= 1:
        res = "충족"
    elif rule_enabled:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


# ─── 38. collect_privilege_escalation_alerts ─────────────────────────────────

def collect_privilege_escalation_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "privilege_alert_count", 1.0, {}
    rule_enabled: Optional[bool] = None
    try:
        r = _wazuh_get("/rules", {"search": "privilege_escalation", "status": "enabled", "limit": 1})
        raw["rules"] = r
        rule_enabled = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        raw["rules_error"] = str(e)

    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"should": [
                {"term": {"rule.groups": "privilege_escalation"}},
                {"term": {"rule.groups": "admin_access"}},
            ]}},
        })
        raw["indexer"] = ir
        count = float(ir["hits"]["total"]["value"])
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)

    if rule_enabled is True and count >= 1:
        res = "충족"
    elif rule_enabled is True:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


# ─── 39. collect_abnormal_privilege_alerts ───────────────────────────────────

def collect_abnormal_privilege_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "abnormal_privilege_count", 1.0, {}
    rule_enabled: Optional[bool] = None
    try:
        r = _wazuh_get("/rules", {"search": "privilege_escalation", "status": "enabled", "limit": 1})
        raw["rules"] = r
        rule_enabled = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        raw["rules_error"] = str(e)

    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"must": [
                {"term": {"rule.groups": "privilege_escalation"}},
                {"range": {"rule.level": {"gte": 7}}},
            ]}},
        })
        raw["indexer"] = ir
        count = float(ir["hits"]["total"]["value"])
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)

    if rule_enabled is True and count >= 1:
        res = "충족"
    elif rule_enabled is True:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


# ─── 40. collect_fim_status ──────────────────────────────────────────────────

def collect_fim_status(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "fim_active_count", 1.0, {}
    try:
        agents = _get_active_agents()
        raw["agent_count"] = len(agents)
        active_count = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    fim_count = 0
    for a in agents:
        try:
            r = _wazuh_get(f"/syscheck/{a['id']}", {"limit": 1})
            if r.get("data", {}).get("affected_items"):
                fim_count += 1
        except Exception:
            pass

    raw["fim_count"] = fim_count
    if fim_count >= 1:
        res = "충족"
    elif active_count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, float(fim_count), thr, raw)


# ─── 41. collect_fim_collection_ratio ────────────────────────────────────────

def collect_fim_collection_ratio(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "fim_collection_ratio", 0.8, {}
    try:
        agents = _get_active_agents()
        raw["agent_count"] = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    denom = len(agents)
    if denom == 0:
        return _err(item_id, maturity, mk, thr, "활성 에이전트 0개")

    numer = 0
    for a in agents:
        try:
            r = _wazuh_get(f"/syscheck/{a['id']}", {"limit": 1})
            if r.get("data", {}).get("affected_items"):
                numer += 1
        except Exception:
            pass

    ratio = numer / denom
    raw["fim_count"] = numer
    res = "충족" if ratio >= 0.8 else "부분충족"
    return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, raw)


# ─── 42. collect_dlp_alerts ──────────────────────────────────────────────────

def collect_dlp_alerts(item_id: str, maturity: str) -> CollectedResult:
    mk, thr, raw = "dlp_alert_count", 1.0, {}
    rule_enabled: Optional[bool] = None
    try:
        r = _wazuh_get("/rules", {"search": "data_loss", "status": "enabled", "limit": 1})
        raw["rules"] = r
        rule_enabled = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        raw["rules_error"] = str(e)

    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"bool": {"should": [
                {"term": {"rule.groups": "data_loss"}},
                {"term": {"rule.groups": "exfiltration"}},
            ]}},
        })
        raw["indexer"] = ir
        count = float(ir["hits"]["total"]["value"])
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)

    if rule_enabled is True and count >= 1:
        res = "충족"
    elif rule_enabled is True:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


# ─── Unit Tests ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import unittest
    from unittest.mock import MagicMock, patch

    def _mock_token_resp(token="test-token"):
        m = MagicMock()
        m.json.return_value = {"data": {"token": token}}
        m.raise_for_status = MagicMock()
        return m

    def _mock_rules_resp(total=1):
        m = MagicMock()
        m.json.return_value = {"data": {"total_affected_items": total, "affected_items": []}}
        m.raise_for_status = MagicMock()
        return m

    def _mock_agents_resp(agents):
        m = MagicMock()
        m.json.return_value = {"data": {"total_affected_items": len(agents), "affected_items": agents}}
        m.raise_for_status = MagicMock()
        return m

    def _mock_ar_resp(count=1):
        items = [{"command": "firewall-drop", "last_execution": "2026-05-01T00:00:00+00:00"}] * count
        m = MagicMock()
        m.json.return_value = {"data": {"total_affected_items": count, "affected_items": items}}
        m.raise_for_status = MagicMock()
        return m

    def _mock_sca_resp(scores=None):
        items = [{"policy_id": "cis_debian", "score": s, "pass": 80, "fail": 20} for s in (scores or [])]
        m = MagicMock()
        m.json.return_value = {"data": {"total_affected_items": len(items), "affected_items": items}}
        m.raise_for_status = MagicMock()
        return m

    def _mock_idx_resp(total=5, hits=None, aggs=None):
        m = MagicMock()
        m.json.return_value = {
            "hits": {"total": {"value": total}, "hits": hits or []},
            "aggregations": aggs or {},
        }
        m.raise_for_status = MagicMock()
        return m

    class TestTokenCache(unittest.TestCase):
        def setUp(self):
            _token_cache["token"] = None
            _token_cache["expires_at"] = 0.0

        @patch("requests.post")
        def test_token_fetched_on_first_call(self, mock_post):
            mock_post.return_value = _mock_token_resp("abc")
            tok = _get_wazuh_token()
            self.assertEqual(tok, "abc")
            mock_post.assert_called_once()

        @patch("requests.post")
        def test_token_cached(self, mock_post):
            mock_post.return_value = _mock_token_resp("abc")
            _get_wazuh_token()
            _get_wazuh_token()
            mock_post.assert_called_once()

        @patch("requests.post")
        def test_token_refreshed_when_expired(self, mock_post):
            mock_post.return_value = _mock_token_resp("abc")
            _token_cache["token"] = "old"
            _token_cache["expires_at"] = time.time() - 10
            tok = _get_wazuh_token()
            self.assertEqual(tok, "abc")

    class TestCollectAuthFailureAlerts(unittest.TestCase):
        def _run(self, rule_total, idx_total):
            with patch("__main__._wazuh_get") as mg, \
                 patch("__main__._indexer_search") as mi:
                mg.return_value = {"data": {"total_affected_items": rule_total, "affected_items": []}}
                mi.return_value = {"hits": {"total": {"value": idx_total}, "hits": []}}
                return collect_auth_failure_alerts("1.1.1_향상", "향상")

        def test_충족(self):
            r = self._run(1, 5)
            self.assertEqual(r["result"], "충족")
            self.assertEqual(r["metric_value"], 5.0)

        def test_부분충족_rule_ok_no_alerts(self):
            r = self._run(1, 0)
            self.assertEqual(r["result"], "부분충족")

        def test_미충족_no_rule(self):
            r = self._run(0, 0)
            self.assertEqual(r["result"], "미충족")

        def test_평가불가_indexer_failure(self):
            with patch("__main__._wazuh_get") as mg, \
                 patch("__main__._indexer_search") as mi:
                mg.return_value = {"data": {"total_affected_items": 1, "affected_items": []}}
                mi.side_effect = Exception("connection refused")
                r = collect_auth_failure_alerts("1.1.1_향상", "향상")
            self.assertEqual(r["result"], "평가불가")
            self.assertIsNotNone(r["error"])

    class TestCollectActiveResponseAuth(unittest.TestCase):
        def _run(self, rule_total, ar_count):
            with patch("__main__._wazuh_get") as mg:
                call_count = [0]
                def side(path, params=None):
                    call_count[0] += 1
                    if "/rules" in path:
                        return {"data": {"total_affected_items": rule_total, "affected_items": []}}
                    if "/active-response" in path:
                        items = [{"command": "block"}] * ar_count
                        return {"data": {"total_affected_items": ar_count, "affected_items": items}}
                    return {}
                mg.side_effect = side
                return collect_active_response_auth("1.2.1_최적화", "최적화")

        def test_충족(self):
            r = self._run(2, 3)
            self.assertEqual(r["result"], "충족")

        def test_부분충족_no_ar(self):
            r = self._run(2, 0)
            self.assertEqual(r["result"], "부분충족")

        def test_미충족_no_rule(self):
            r = self._run(0, 0)
            self.assertEqual(r["result"], "미충족")

    class TestCollectScaAverage(unittest.TestCase):
        def test_충족(self):
            with patch("__main__._get_active_agents") as mga, \
                 patch("__main__._wazuh_get") as mg:
                mga.return_value = [{"id": "001"}]
                mg.return_value = {"data": {"affected_items": [{"score": 80}, {"score": 90}]}}
                r = collect_sca_average("1.3.1_초기", "초기")
            self.assertEqual(r["result"], "충족")
            self.assertAlmostEqual(r["metric_value"], 85.0)

        def test_부분충족(self):
            with patch("__main__._get_active_agents") as mga, \
                 patch("__main__._wazuh_get") as mg:
                mga.return_value = [{"id": "001"}]
                mg.return_value = {"data": {"affected_items": [{"score": 55}]}}
                r = collect_sca_average("1.3.1_초기", "초기")
            self.assertEqual(r["result"], "부분충족")

        def test_평가불가_no_agents(self):
            with patch("__main__._get_active_agents") as mga:
                mga.return_value = []
                r = collect_sca_average("1.3.1_초기", "초기")
            self.assertEqual(r["result"], "평가불가")

    class TestCollectHighRiskAlerts(unittest.TestCase):
        def test_충족_recent_alert(self):
            ts = datetime.now(timezone.utc).isoformat()
            with patch("__main__._indexer_search") as mi:
                mi.return_value = {
                    "hits": {"total": {"value": 3}, "hits": [{"_source": {"@timestamp": ts}}]}
                }
                r = collect_high_risk_alerts("1.3.1_최적화", "최적화")
            self.assertEqual(r["result"], "충족")

        def test_부분충족_old_alert(self):
            ts = "2020-01-01T00:00:00+00:00"
            with patch("__main__._indexer_search") as mi:
                mi.return_value = {
                    "hits": {"total": {"value": 3}, "hits": [{"_source": {"@timestamp": ts}}]}
                }
                r = collect_high_risk_alerts("1.3.1_최적화", "최적화")
            self.assertEqual(r["result"], "부분충족")

        def test_부분충족_no_alerts(self):
            with patch("__main__._indexer_search") as mi:
                mi.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
                r = collect_high_risk_alerts("1.3.1_최적화", "최적화")
            self.assertEqual(r["result"], "부분충족")
            self.assertEqual(r["raw_json"].get("note"), "no_alerts_in_1h")

    class TestCollectAgentRegistration(unittest.TestCase):
        def test_충족(self):
            with patch("__main__._get_all_agents") as mga:
                mga.return_value = [{"id": "001", "name": "host1", "status": "active"}]
                r = collect_agent_registration("2.3.1_기존", "기존")
            self.assertEqual(r["result"], "충족")
            self.assertEqual(r["metric_value"], 1.0)

        def test_미충족(self):
            with patch("__main__._get_all_agents") as mga:
                mga.return_value = []
                r = collect_agent_registration("2.3.1_기존", "기존")
            self.assertEqual(r["result"], "미충족")

    class TestCollectAgentKeepalive(unittest.TestCase):
        def test_충족(self):
            now_s = datetime.now(timezone.utc).isoformat()
            agents = [{"id": str(i), "lastKeepAlive": now_s} for i in range(10)]
            with patch("__main__._get_all_agents") as mga:
                mga.return_value = agents
                r = collect_agent_keepalive("2.3.1_초기", "초기")
            self.assertEqual(r["result"], "충족")

        def test_미충족(self):
            old_s = "2020-01-01T00:00:00+00:00"
            agents = [{"id": str(i), "lastKeepAlive": old_s} for i in range(10)]
            with patch("__main__._get_all_agents") as mga:
                mga.return_value = agents
                r = collect_agent_keepalive("2.3.1_초기", "초기")
            self.assertEqual(r["result"], "미충족")

    class TestCollectVulnerabilitySummary(unittest.TestCase):
        def test_충족(self):
            with patch("__main__._get_active_agents") as mga, \
                 patch("__main__._indexer_search") as mi:
                mga.return_value = [{"id": "001"}]
                mi.return_value = {
                    "hits": {"total": {"value": 10}, "hits": []},
                    "aggregations": {
                        "by_agent": {"buckets": [{"key": "001", "doc_count": 10}]},
                        "by_severity": {"buckets": []},
                    },
                }
                r = collect_vulnerability_summary("2.3.1_향상", "향상")
            self.assertEqual(r["result"], "충족")
            self.assertEqual(r["metric_value"], 1.0)

    class TestCollectCriticalUnfixedVulns(unittest.TestCase):
        def test_충족_no_vulns(self):
            with patch("__main__._get_active_agents") as mga, \
                 patch("__main__._indexer_search") as mi:
                mga.return_value = [{"id": "001"}]
                mi.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
                r = collect_critical_unfixed_vulns("2.4.2_최적화", "최적화")
            self.assertEqual(r["result"], "충족")

        def test_부분충족(self):
            with patch("__main__._get_active_agents") as mga, \
                 patch("__main__._indexer_search") as mi:
                mga.return_value = [{"id": "001"}]
                mi.return_value = {"hits": {"total": {"value": 3}, "hits": []}}
                r = collect_critical_unfixed_vulns("2.4.2_최적화", "최적화")
            self.assertEqual(r["result"], "부분충족")

        def test_미충족(self):
            with patch("__main__._get_active_agents") as mga, \
                 patch("__main__._indexer_search") as mi:
                mga.return_value = [{"id": "001"}]
                mi.return_value = {"hits": {"total": {"value": 10}, "hits": []}}
                r = collect_critical_unfixed_vulns("2.4.2_최적화", "최적화")
            self.assertEqual(r["result"], "미충족")

    class TestCollectEdrAgents(unittest.TestCase):
        def test_충족(self):
            with patch("__main__._get_active_agents") as mga:
                mga.return_value = [{"id": "001", "version": "4.8.0", "status": "active"}]
                r = collect_edr_agents("2.4.1_기존", "기존")
            self.assertEqual(r["result"], "충족")

        def test_미충족(self):
            with patch("__main__._get_active_agents") as mga:
                mga.return_value = [{"id": "001", "status": "active"}]
                r = collect_edr_agents("2.4.1_기존", "기존")
            self.assertEqual(r["result"], "미충족")

    class TestCollectTlsCleartextAlerts(unittest.TestCase):
        def test_충족_rule_exists(self):
            with patch("__main__._wazuh_get") as mg, \
                 patch("__main__._indexer_search") as mi:
                mg.return_value = {"data": {"total_affected_items": 1, "affected_items": []}}
                mi.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
                r = collect_tls_cleartext_alerts("3.3.1_초기", "초기")
            self.assertEqual(r["result"], "충족")

        def test_미충족_no_rule(self):
            with patch("__main__._wazuh_get") as mg, \
                 patch("__main__._indexer_search") as mi:
                mg.return_value = {"data": {"total_affected_items": 0, "affected_items": []}}
                mi.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
                r = collect_tls_cleartext_alerts("3.3.1_초기", "초기")
            self.assertEqual(r["result"], "미충족")

    class TestCollectAgentUptime(unittest.TestCase):
        def test_충족_all_active(self):
            agents = [{"id": str(i), "status": "active"} for i in range(100)]
            with patch("__main__._get_all_agents") as mga:
                mga.return_value = agents
                r = collect_agent_uptime("3.5.1_향상", "향상")
            self.assertEqual(r["result"], "충족")

        def test_미충족_low_ratio(self):
            agents = (
                [{"id": str(i), "status": "active"} for i in range(90)] +
                [{"id": str(i + 90), "status": "disconnected"} for i in range(10)]
            )
            with patch("__main__._get_all_agents") as mga:
                mga.return_value = agents
                r = collect_agent_uptime("3.5.1_향상", "향상")
            self.assertEqual(r["result"], "미충족")

    class TestCollectFimStatus(unittest.TestCase):
        def test_충족(self):
            with patch("__main__._get_active_agents") as mga, \
                 patch("__main__._wazuh_get") as mg:
                mga.return_value = [{"id": "001"}]
                mg.return_value = {"data": {"affected_items": [{"path": "/etc/passwd", "md5": "abc"}]}}
                r = collect_fim_status("6.1.1_초기", "초기")
            self.assertEqual(r["result"], "충족")

        def test_부분충족_no_fim_data(self):
            with patch("__main__._get_active_agents") as mga, \
                 patch("__main__._wazuh_get") as mg:
                mga.return_value = [{"id": "001"}]
                mg.return_value = {"data": {"affected_items": []}}
                r = collect_fim_status("6.1.1_초기", "초기")
            self.assertEqual(r["result"], "부분충족")

    class TestIndexerSession(unittest.TestCase):
        def test_singleton(self):
            global _indexer_session
            _indexer_session = None
            s1 = _get_indexer_session()
            s2 = _get_indexer_session()
            self.assertIs(s1, s2)
            _indexer_session = None

    unittest.main(verbosity=2)
