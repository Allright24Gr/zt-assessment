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


# ─── New functions (43~122) ───────────────────────────────────────────────────

def collect_auto_reauth(item_id: str, maturity: str) -> CollectedResult:
    """1.2.2.4_1: 탐지 룰 AND 세션 종료 자동화 → 충족 / 탐지만 → 부분충족"""
    mk, thr, raw = "auto_reauth_count", 1.0, {}
    rule_ok = False
    try:
        r = _wazuh_get("/rules", {"search": "authentication_failure", "status": "enabled", "limit": 1})
        raw["rules"] = r
        rule_ok = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        raw["rules_error"] = str(e)
    ar_count = 0
    try:
        ar = _wazuh_get("/active-response")
        raw["active_response"] = ar
        ar_count = len(ar.get("data", {}).get("affected_items", []))
    except Exception as e:
        raw["ar_error"] = str(e)
    if rule_ok and ar_count >= 1:
        res = "충족"
    elif rule_ok:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, float(ar_count), thr, raw)


def collect_icam_automation(item_id: str, maturity: str) -> CollectedResult:
    """1.3.1.3_2: AR ≥ 1 AND 비율 ≥ 80% → 충족 / 미달 → 부분충족"""
    mk, thr, raw = "ar_count", 1.0, {}
    try:
        ar = _wazuh_get("/active-response")
        raw["active_response"] = ar
        ar_count = len(ar.get("data", {}).get("affected_items", []))
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))
    agents = _get_active_agents()
    agent_count = len(agents)
    ratio = ar_count / agent_count if agent_count > 0 else 0.0
    raw["ratio"] = ratio
    if ar_count >= 1 and ratio >= 0.8:
        res = "충족"
    elif ar_count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, float(ar_count), thr, raw)


def collect_dynamic_access_policy(item_id: str, maturity: str) -> CollectedResult:
    """1.4.1.4_1: 자동화 구성 → 충족 / 수동만 → 부분충족"""
    mk, thr, raw = "dynamic_ar_count", 1.0, {}
    try:
        ar = _wazuh_get("/active-response")
        raw["active_response"] = ar
        ar_count = len(ar.get("data", {}).get("affected_items", []))
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))
    res = "충족" if ar_count >= 1 else "부분충족"
    return _ok(item_id, maturity, res, mk, float(ar_count), thr, raw)


def collect_dynamic_privilege_change(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.4_1: 권한상승 알림 ≥ 1 → 충족 / 구성됐으나 0 → 부분충족"""
    mk, thr = "dynamic_priv_count", 1.0
    try:
        count = float(_indexer_count("wazuh-alerts-*", {
            "query": {"bool": {"must": [
                {"term": {"rule.groups": "privilege_escalation"}},
                {"range": {"@timestamp": {"gte": "now-2592000s"}}}
            ]}}
        }))
        res = "충족" if count >= thr else "부분충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"count": int(count)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_realtime_least_privilege(item_id: str, maturity: str) -> CollectedResult:
    """1.4.2.4_2: 워크플로우 구성 AND 이벤트 ≥ 1 → 충족 / 구성만 → 부분충족"""
    mk, thr, raw = "realtime_priv_workflow", 1.0, {}
    ar_count = 0
    try:
        ar = _wazuh_get("/active-response")
        raw["ar"] = ar
        ar_count = len(ar.get("data", {}).get("affected_items", []))
    except Exception as e:
        raw["ar_error"] = str(e)
    try:
        count = float(_indexer_count("wazuh-alerts-*", {
            "query": {"bool": {"must": [
                {"term": {"rule.groups": "privilege_escalation"}},
                {"range": {"@timestamp": {"gte": "now-3600s"}}}
            ]}}
        }))
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)
    if ar_count >= 1 and count >= 1:
        res = "충족"
    elif ar_count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


def collect_device_security_check(item_id: str, maturity: str) -> CollectedResult:
    """2.2.1.3_1: SCA ≥ 70점 비율 ≥ 80% → 충족 / 50~80% → 부분충족"""
    mk, thr, raw = "sca_pass_ratio_80", 0.8, {}
    try:
        agents = _get_active_agents()
        raw["agent_count"] = len(agents)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))
    sca_data = []
    for a in agents:
        try:
            r = _wazuh_get(f"/sca/{a['id']}")
            sca_data.extend(r.get("data", {}).get("affected_items", []))
        except Exception:
            pass
    if not sca_data:
        return _err(item_id, maturity, mk, thr, "SCA 결과 없음")
    pass_count = sum(1 for s in sca_data if s.get("score", 0) >= 70)
    ratio = pass_count / len(sca_data)
    if ratio >= 0.8:
        res = "충족"
    elif ratio >= 0.5:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, {"pass_count": pass_count, "total": len(sca_data)})


def collect_device_security_integration(item_id: str, maturity: str) -> CollectedResult:
    """2.2.1.4_2: 연동 워크플로우 AND 실행 이력 ≥ 1 → 충족 / 구성만 → 부분충족"""
    mk, thr, raw = "integration_workflow_count", 1.0, {}
    try:
        agents = _get_active_agents()
        raw["agent_count"] = len(agents)
        ar = _wazuh_get("/active-response")
        raw["ar"] = ar
        ar_count = len(ar.get("data", {}).get("affected_items", []))
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))
    if ar_count >= 1 and len(agents) >= 1:
        res = "충족"
    elif ar_count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, float(ar_count), thr, raw)


def collect_endpoint_central_policy(item_id: str, maturity: str) -> CollectedResult:
    """2.3.2.3_1: AR 있는 에이전트 비율 ≥ 90% → 충족 / 미달 → 부분충족"""
    mk, thr, raw = "central_policy_ratio", 0.9, {}
    try:
        agents = _get_active_agents()
        raw["agent_count"] = len(agents)
        ar = _wazuh_get("/active-response")
        raw["ar"] = ar
        ar_count = len(ar.get("data", {}).get("affected_items", []))
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))
    denom = len(agents)
    if denom == 0:
        return _err(item_id, maturity, mk, thr, "활성 에이전트 0개")
    ratio = min(ar_count / denom, 1.0)
    if ratio >= 0.9:
        res = "충족"
    elif ratio >= 0.5:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, raw)


def collect_vuln_integrated(item_id: str, maturity: str) -> CollectedResult:
    """2.4.2.3_2: 통합 운영 → 충족 / 독립 운영 → 부분충족"""
    mk, thr, raw = "vuln_integrated_count", 1.0, {}
    try:
        agents = _get_active_agents()
        ar = _wazuh_get("/active-response")
        ar_count = len(ar.get("data", {}).get("affected_items", []))
        agent_ids = [a.get("id") for a in agents if a.get("id")]
        vuln_count = 0
        if agent_ids:
            vuln_count = _indexer_count("wazuh-states-vulnerabilities-*", {
                "query": {"terms": {"agent.id": agent_ids}}
            })
        raw.update({"ar_count": ar_count, "vuln_count": vuln_count})
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))
    if ar_count >= 1 and vuln_count >= 1:
        res = "충족"
    elif vuln_count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, float(ar_count), thr, raw)


def _indexer_alert_count(groups: list, window: str = "now-86400s") -> float:
    """Helper: indexer alert count by rule.groups within time window."""
    should = [{"term": {"rule.groups": g}} for g in groups]
    query = {
        "query": {"bool": {"must": [
            {"bool": {"should": should, "minimum_should_match": 1}},
            {"range": {"@timestamp": {"gte": window}}}
        ]}}
    }
    return float(_indexer_count("wazuh-alerts-*", query))


def _rule_and_alert(item_id, maturity, mk, thr, rule_search, groups, window="now-86400s"):
    """Helper: rule-exists AND alert-count pattern."""
    raw = {}
    rule_ok = False
    try:
        r = _wazuh_get("/rules", {"search": rule_search, "status": "enabled", "limit": 1})
        raw["rules"] = r
        rule_ok = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        raw["rules_error"] = str(e)
    try:
        count = _indexer_alert_count(groups, window)
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)
    if rule_ok and count >= thr:
        res = "충족"
    elif rule_ok:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, count, thr, raw)


def _alert_only(item_id, maturity, mk, thr, groups, window="now-86400s"):
    """Helper: indexer alert-only pattern."""
    try:
        count = _indexer_alert_count(groups, window)
        res = "충족" if count >= thr else "미충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"count": int(count)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_segment_traffic_monitor(item_id: str, maturity: str) -> CollectedResult:
    """3.1.1.2_2: 룰 AND 알림 → 충족 / 룰만 → 부분충족"""
    return _rule_and_alert(item_id, maturity, "segment_traffic_count", 1.0, "network_scan", ["network_scan"])


def collect_macro_segment_custom_policy(item_id: str, maturity: str) -> CollectedResult:
    """3.1.1.3_1: 차등 정책 알림 → 충족 / 단일만 → 부분충족"""
    return _alert_only(item_id, maturity, "custom_segment_count", 1.0, ["network_policy"])


def collect_macro_segment_response(item_id: str, maturity: str) -> CollectedResult:
    """3.1.1.3_2: AR 활성 AND 실행 이력 ≥ 1 → 충족 / 룰만 → 부분충족"""
    mk, thr, raw = "macro_ar_count", 1.0, {}
    try:
        ar = _wazuh_get("/active-response")
        raw["ar"] = ar
        ar_items = ar.get("data", {}).get("affected_items", [])
        ar_count = len(ar_items)
        recent = sum(1 for a in ar_items if a.get("last_execution"))
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))
    if ar_count >= 1 and recent >= 1:
        res = "충족"
    elif ar_count >= 1:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, float(ar_count), thr, raw)


def collect_micro_segment_block(item_id: str, maturity: str) -> CollectedResult:
    """3.1.2.2_2: 차단 룰 AND 실행 이력 ≥ 1 → 충족 / 룰만 → 부분충족"""
    mk, thr, raw = "micro_block_count", 1.0, {}
    rule_ok = False
    try:
        r = _wazuh_get("/rules", {"search": "network_policy", "status": "enabled", "limit": 1})
        rule_ok = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        raw["rules_error"] = str(e)
    try:
        ar = _wazuh_get("/active-response")
        ar_count = len(ar.get("data", {}).get("affected_items", []))
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e), raw)
    if rule_ok and ar_count >= 1:
        res = "충족"
    elif rule_ok:
        res = "부분충족"
    else:
        res = "미충족"
    return _ok(item_id, maturity, res, mk, float(ar_count), thr, raw)


def collect_micro_segment_monitor(item_id: str, maturity: str) -> CollectedResult:
    """3.1.2.2_3: 모니터링 룰 활성화 → 충족 / 미활성 → 미충족"""
    mk, thr = "micro_monitor_count", 1.0
    try:
        r = _wazuh_get("/rules", {"search": "network", "status": "enabled", "limit": 1})
        count = float(r.get("data", {}).get("total_affected_items", 0))
        res = "충족" if count >= thr else "미충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"rule_count": int(count)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_micro_segment_policy_ratio(item_id: str, maturity: str) -> CollectedResult:
    """3.1.2.3_1: 정책 적용 비율 ≥ 90% → 충족 / 50~90% → 부분충족"""
    mk, thr, raw = "micro_policy_ratio", 0.9, {}
    try:
        agents = _get_active_agents()
        ar = _wazuh_get("/active-response")
        ar_count = len(ar.get("data", {}).get("affected_items", []))
        denom = len(agents)
        if denom == 0:
            return _err(item_id, maturity, mk, thr, "에이전트 0개")
        ratio = min(ar_count / denom, 1.0)
        if ratio >= 0.9:
            res = "충족"
        elif ratio >= 0.5:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, {"ar": ar_count, "agents": denom})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_static_network_rules(item_id: str, maturity: str) -> CollectedResult:
    """3.2.1.1_2: 룰 ≥ 1 → 충족"""
    mk, thr = "static_rule_count", 1.0
    try:
        r = _wazuh_get("/rules", {"status": "enabled", "limit": 1})
        count = float(r.get("data", {}).get("total_affected_items", 0))
        res = "충족" if count >= thr else "미충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"rule_count": int(count)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_app_profile_traffic(item_id: str, maturity: str) -> CollectedResult:
    """3.2.1.2_2: 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "app_profile_alert_count", 1.0, ["application_profile"])


def collect_dynamic_network_rules(item_id: str, maturity: str) -> CollectedResult:
    """3.2.1.3_2: 동적 룰 ≥ 1 → 충족"""
    mk, thr = "dynamic_rule_count", 1.0
    try:
        r = _wazuh_get("/rules", {"search": "network", "status": "enabled"})
        count = float(r.get("data", {}).get("total_affected_items", 0))
        res = "충족" if count >= thr else "미충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"rule_count": int(count)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_network_auto_response(item_id: str, maturity: str) -> CollectedResult:
    """3.2.1.4_1: 실행 ≥ 1 → 충족 / 룰만 → 부분충족"""
    mk, thr, raw = "network_ar_count", 1.0, {}
    try:
        ar = _wazuh_get("/active-response")
        ar_items = ar.get("data", {}).get("affected_items", [])
        ar_count = len(ar_items)
        recent = sum(1 for a in ar_items if a.get("last_execution"))
        if ar_count >= 1 and recent >= 1:
            res = "충족"
        elif ar_count >= 1:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, float(ar_count), thr, {"ar_count": ar_count})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_app_profile_change_detect(item_id: str, maturity: str) -> CollectedResult:
    """3.2.1.4_2: 탐지 알림 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "profile_change_count", 1.0, ["application_profile"])


def collect_tls_coverage(item_id: str, maturity: str) -> CollectedResult:
    """3.3.1.2_1: 비율 ≥ 80% → 충족 / 50~80% → 부분충족"""
    mk, thr = "tls_coverage_ratio", 0.8
    try:
        total = float(_indexer_count("wazuh-alerts-*", {"query": {"match_all": {}}}))
        tls = float(_indexer_count("wazuh-alerts-*", {
            "query": {"bool": {"should": [
                {"term": {"rule.groups": "tls"}}, {"term": {"rule.groups": "ssl"}}
            ]}}
        }))
        ratio = tls / total if total > 0 else 0.0
        if ratio >= 0.8:
            res = "충족"
        elif ratio >= 0.5:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, {"tls_alerts": int(tls), "total": int(total)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_tls_policy_rule(item_id: str, maturity: str) -> CollectedResult:
    """3.3.1.2_2: TLS 정책 룰 활성화 → 충족 / 미활성 → 미충족"""
    mk, thr = "tls_rule_count", 1.0
    try:
        r = _wazuh_get("/rules", {"search": "tls", "status": "enabled", "limit": 1})
        count = float(r.get("data", {}).get("total_affected_items", 0))
        res = "충족" if count >= thr else "미충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"tls_rule_count": int(count)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_auto_data_flow_map(item_id: str, maturity: str) -> CollectedResult:
    """3.4.1.2_2: 자동 매핑 알림 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "auto_flow_map_count", 1.0, ["network_flow"])


def collect_abnormal_data_movement(item_id: str, maturity: str) -> CollectedResult:
    """3.4.1.3_1: 룰 AND 알림 → 충족 / 룰만 → 부분충족"""
    return _rule_and_alert(item_id, maturity, "abnormal_data_count", 1.0, "data_exfiltration", ["data_exfiltration"])


def collect_correlation_threat_detect(item_id: str, maturity: str) -> CollectedResult:
    """3.4.1.3_2: 상관 분석 알림 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "correlation_alert_count", 1.0, ["correlation"])


def collect_network_continuity(item_id: str, maturity: str) -> CollectedResult:
    """3.5.1.4_1: 활성 비율 ≥ 99.9% AND 알림 수집 → 충족 / 미달 → 부분충족"""
    mk, thr, raw = "network_continuity_ratio", 0.999, {}
    try:
        agents = _get_all_agents()
        denom = len(agents)
        if denom == 0:
            return _err(item_id, maturity, mk, thr, "에이전트 0개")
        numer = sum(1 for a in agents if a.get("status") == "active")
        ratio = numer / denom
        alert_count = float(_indexer_count("wazuh-alerts-*", {
            "query": {"range": {"@timestamp": {"gte": "now-3600s"}}}
        }))
        if ratio >= 0.999 and alert_count >= 1:
            res = "충족"
        elif ratio >= 0.99:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, {"active": numer, "total": denom})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_auto_recovery(item_id: str, maturity: str) -> CollectedResult:
    """3.5.1.4_2: 장애 감지 AND 자동 복구 이력 ≥ 1 → 충족 / 감지만 → 부분충족"""
    mk, thr, raw = "auto_recovery_count", 1.0, {}
    try:
        count = float(_indexer_count("wazuh-alerts-*", {
            "query": {"bool": {"should": [
                {"term": {"rule.groups": "agent_disconnected"}},
                {"term": {"rule.groups": "ossec"}},
            ]}}
        }))
        raw["detect_count"] = int(count)
        ar = _wazuh_get("/active-response")
        ar_count = len(ar.get("data", {}).get("affected_items", []))
        if count >= 1 and ar_count >= 1:
            res = "충족"
        elif count >= 1:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"detect_count": int(count), "ar_count": ar_count})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_realtime_access_event(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.4_1: 이벤트 ≥ 1 → 충족 / 구성만 → 부분충족"""
    return _alert_only(item_id, maturity, "access_event_count", 1.0, ["access_control"], "now-3600s")


def collect_command_trust_reeval(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.4_3: 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "command_alert_count", 1.0, ["command_execution"])


def collect_risk_based_access_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.1.1.4_4: 위험 분석 기반 룰 운영 → 충족 / 계획만 → 부분충족"""
    mk, thr, raw = "risk_policy_count", 1.0, {}
    rule_ok = False
    try:
        r = _wazuh_get("/rules", {"search": "access", "status": "enabled", "limit": 1})
        rule_ok = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        raw["rules_error"] = str(e)
    try:
        count = float(_indexer_count("wazuh-alerts-*", {
            "query": {"bool": {"must": [
                {"range": {"rule.level": {"gte": 7}}},
                {"range": {"@timestamp": {"gte": "now-86400s"}}}
            ]}}
        }))
        if rule_ok and count >= 1:
            res = "충족"
        elif rule_ok:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"rule_ok": rule_ok, "count": int(count)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_pam_basic(item_id: str, maturity: str) -> CollectedResult:
    """4.2.1.1_1: 특권 계정 목록 존재(에이전트 ≥ 1) → 충족"""
    mk, thr = "privileged_agent_count", 1.0
    try:
        agents = _get_active_agents()
        count = float(len(agents))
        res = "충족" if count >= thr else "미충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"agent_count": int(count)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_pam_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.2.1.1_2: PAM 정책 룰 존재 → 충족"""
    mk, thr = "pam_rule_count", 1.0
    try:
        r = _wazuh_get("/rules", {"search": "privilege", "status": "enabled"})
        count = float(r.get("data", {}).get("total_affected_items", 0))
        res = "충족" if count >= thr else "미충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"pam_rule_count": int(count)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_pam_monitor(item_id: str, maturity: str) -> CollectedResult:
    """4.2.1.2_1: 룰 AND 알림 → 충족 / 룰만 → 부분충족"""
    return _rule_and_alert(item_id, maturity, "pam_monitor_count", 1.0, "privilege_access", ["privilege_access"])


def collect_abnormal_auth_monitor(item_id: str, maturity: str) -> CollectedResult:
    """4.2.2.3_3: 룰 AND 알림 → 충족 / 룰만 → 부분충족"""
    return _rule_and_alert(item_id, maturity, "abnormal_auth_count", 1.0, "authentication_failure",
                           ["authentication_failure", "authentication_failed"], "now-3600s")


def collect_inter_segment_control(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.2_2: 룰 AND 알림 → 충족 / 룰만 → 부분충족"""
    return _rule_and_alert(item_id, maturity, "inter_segment_count", 1.0, "lateral_movement", ["lateral_movement"])


def collect_workload_segment_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.3_1: 워크로드별 차등 정책 알림 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "workload_policy_count", 1.0, ["network_policy"])


def collect_realtime_segment_inspect(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.3_3: 알림 수집 → 충족 / 미수집 → 미충족"""
    try:
        count = float(_indexer_count("wazuh-alerts-*", {
            "query": {"bool": {"must": [
                {"range": {"rule.level": {"gte": 7}}},
                {"range": {"@timestamp": {"gte": "now-3600s"}}}
            ]}}
        }))
        res = "충족" if count >= 1.0 else "미충족"
        return _ok(item_id, maturity, res, "realtime_segment_count", count, 1.0, {"count": int(count)})
    except Exception as exc:
        return _err(item_id, maturity, "realtime_segment_count", 1.0, str(exc))


def collect_group_move_analysis(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.3_4: 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "group_move_count", 1.0, ["lateral_movement"])


def collect_realtime_group_move_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.3.1.3_6: 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "realtime_policy_count", 1.0, ["policy_changed"], "now-3600s")


def collect_system_policy_basic(item_id: str, maturity: str) -> CollectedResult:
    """4.4.1.1_1: 에이전트 ≥ 1 AND SCA 활성 → 충족 / 에이전트만 → 부분충족"""
    mk, thr, raw = "system_sca_count", 1.0, {}
    try:
        agents = _get_active_agents()
        agent_count = len(agents)
        sca_count = 0
        for a in agents[:5]:
            try:
                r = _wazuh_get(f"/sca/{a['id']}", {"limit": 1})
                if r.get("data", {}).get("affected_items"):
                    sca_count += 1
            except Exception:
                pass
        if agent_count >= 1 and sca_count >= 1:
            res = "충족"
        elif agent_count >= 1:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, float(sca_count), thr, {"agents": agent_count, "sca": sca_count})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_auto_policy_apply(item_id: str, maturity: str) -> CollectedResult:
    """4.4.1.2_2: 비율 ≥ 80% → 충족 / 50~80% → 부분충족"""
    mk, thr = "auto_policy_ratio", 0.8
    try:
        agents = _get_active_agents()
        denom = len(agents)
        if denom == 0:
            return _err(item_id, maturity, mk, thr, "에이전트 0개")
        ar = _wazuh_get("/active-response")
        ar_count = len(ar.get("data", {}).get("affected_items", []))
        ratio = min(ar_count / denom, 1.0)
        if ratio >= 0.8:
            res = "충족"
        elif ratio >= 0.5:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, {"ar": ar_count, "agents": denom})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_dynamic_policy_change(item_id: str, maturity: str) -> CollectedResult:
    """4.4.1.3_2: 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "dynamic_policy_count", 1.0, ["policy_changed"])


def collect_autonomous_policy(item_id: str, maturity: str) -> CollectedResult:
    """4.4.1.4_1: 자율 적용 이벤트 ≥ 1 → 충족 / 구성만 → 부분충족"""
    mk, thr = "autonomous_policy_event", 1.0
    try:
        count = float(_indexer_count("wazuh-alerts-*", {
            "query": {"bool": {"must": [
                {"term": {"rule.groups": "policy_changed"}},
                {"range": {"@timestamp": {"gte": "now-3600s"}}}
            ]}}
        }))
        res = "충족" if count >= thr else "부분충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"count": int(count)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_consistent_policy_ratio(item_id: str, maturity: str) -> CollectedResult:
    """4.4.1.4_2: 비율 ≥ 90% → 충족 / 50~90% → 부분충족"""
    mk, thr = "consistent_policy_ratio", 0.9
    try:
        agents = _get_active_agents()
        denom = len(agents)
        if denom == 0:
            return _err(item_id, maturity, mk, thr, "에이전트 0개")
        sca_ok = 0
        for a in agents:
            try:
                r = _wazuh_get(f"/sca/{a['id']}", {"limit": 1})
                if r.get("data", {}).get("affected_items"):
                    sca_ok += 1
            except Exception:
                pass
        ratio = sca_ok / denom
        if ratio >= 0.9:
            res = "충족"
        elif ratio >= 0.5:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, {"sca_ok": sca_ok, "agents": denom})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_workload_anomaly(item_id: str, maturity: str) -> CollectedResult:
    """5.1.1.4_1: 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "workload_anomaly_count", 1.0, ["anomaly_detection"])


def collect_abnormal_access_block(item_id: str, maturity: str) -> CollectedResult:
    """5.1.1.4_3: 룰 AND 알림 → 충족 / 룰만 → 부분충족"""
    return _rule_and_alert(item_id, maturity, "abnormal_access_block_count", 1.0, "access", ["access_control"])


def collect_app_security_monitor(item_id: str, maturity: str) -> CollectedResult:
    """5.2.1.2_1: 알림 AND 룰 활성 → 충족 / 룰만 → 부분충족"""
    return _rule_and_alert(item_id, maturity, "app_monitor_count", 1.0, "web", ["web", "application"])


def collect_system_change_review(item_id: str, maturity: str) -> CollectedResult:
    """5.2.1.2_2: 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "config_change_count", 1.0, ["configuration_changed", "syslog"])


def collect_system_realtime_threat(item_id: str, maturity: str) -> CollectedResult:
    """5.2.1.4_1: 알림 AND 처리지연 ≤ 60s → 충족 / 수집만 → 부분충족"""
    mk, thr, raw = "system_threat_count", 1.0, {}
    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 5, "track_total_hits": True,
            "query": {"bool": {"must": [
                {"range": {"rule.level": {"gte": 7}}},
                {"range": {"@timestamp": {"gte": "now-3600s"}}}
            ]}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        })
        raw["indexer"] = ir
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
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_remote_device_sca(item_id: str, maturity: str) -> CollectedResult:
    """5.3.1.2_1: SCA 평균 ≥ 70 → 충족 / 50~70 → 부분충족"""
    mk, thr, raw = "remote_sca_avg", 70.0, {}
    try:
        agents = _get_active_agents()
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
            return _err(item_id, maturity, mk, thr, "SCA 결과 없음")
        avg = sum(scores) / len(scores)
        if avg >= 70:
            res = "충족"
        elif avg >= 50:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, round(avg, 2), thr, {"avg": round(avg, 2), "count": len(scores)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_remote_realtime_monitor(item_id: str, maturity: str) -> CollectedResult:
    """5.3.1.3_1: 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "remote_monitor_count", 1.0, ["remote_access"], "now-3600s")


def collect_deploy_pipeline_monitor(item_id: str, maturity: str) -> CollectedResult:
    """5.4.1.2_1: 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "deploy_monitor_count", 1.0, ["deployment"])


def collect_deploy_continuous_monitor(item_id: str, maturity: str) -> CollectedResult:
    """5.4.1.3_1: 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "deploy_continuous_count", 1.0, ["deployment"])


def collect_deploy_anomaly_detect(item_id: str, maturity: str) -> CollectedResult:
    """5.4.1.3_3: 탐지 알림 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "deploy_anomaly_count", 1.0, ["deployment", "anomaly"])


def collect_app_inventory_auto(item_id: str, maturity: str) -> CollectedResult:
    """5.4.2.2_1: 수집 비율 ≥ 80% → 충족 / 미달 → 부분충족"""
    mk, thr, raw = "app_inventory_ratio", 0.8, {}
    try:
        agents = _get_active_agents()
        denom = len(agents)
        if denom == 0:
            return _err(item_id, maturity, mk, thr, "에이전트 0개")
        numer = 0
        for a in agents:
            try:
                r = _wazuh_get(f"/syscollector/{a['id']}/packages", {"limit": 1})
                if r.get("data", {}).get("affected_items"):
                    numer += 1
            except Exception:
                pass
        ratio = numer / denom
        if ratio >= 0.8:
            res = "충족"
        elif ratio >= 0.5:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, round(ratio, 4), thr, {"ok": numer, "total": denom})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_runtime_analysis_auto(item_id: str, maturity: str) -> CollectedResult:
    """5.5.1.4_2: 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "runtime_analysis_count", 1.0, ["runtime_anomaly"])


def collect_data_risk_monitor(item_id: str, maturity: str) -> CollectedResult:
    """6.1.1.3_1: 룰 AND 알림 → 충족 / 룰만 → 부분충족"""
    return _rule_and_alert(item_id, maturity, "data_risk_count", 1.0, "data_access", ["data_access"])


def collect_sensitive_data_protect(item_id: str, maturity: str) -> CollectedResult:
    """6.1.1.3_2: 알림 AND 보호 정책 ≥ 1 → 충족 / 알림만 → 부분충족"""
    mk, thr, raw = "sensitive_protect_count", 1.0, {}
    try:
        count = float(_indexer_count("wazuh-alerts-*", {
            "query": {"term": {"rule.groups": "data_access"}}
        }))
        ar = _wazuh_get("/active-response")
        ar_count = len(ar.get("data", {}).get("affected_items", []))
        if count >= 1 and ar_count >= 1:
            res = "충족"
        elif count >= 1:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"alert_count": int(count), "ar_count": ar_count})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_data_usage_pattern(item_id: str, maturity: str) -> CollectedResult:
    """6.1.1.3_3: 분석 룰 AND 알림 → 충족 / 룰만 → 부분충족"""
    return _rule_and_alert(item_id, maturity, "data_pattern_count", 1.0, "data_access", ["data_access"])


def collect_data_catalog_integrated(item_id: str, maturity: str) -> CollectedResult:
    """6.1.1.4_2: 통합 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "catalog_integrated_count", 1.0, ["data_catalog"])


def collect_data_governance_audit(item_id: str, maturity: str) -> CollectedResult:
    """6.1.2.2_1: 감사 룰 AND 알림 → 충족 / 룰만 → 부분충족"""
    return _rule_and_alert(item_id, maturity, "governance_audit_count", 1.0, "audit", ["audit"])


def collect_data_governance_auto(item_id: str, maturity: str) -> CollectedResult:
    """6.1.2.3_1: 자동화 알림 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "governance_auto_count", 1.0, ["data_governance"])


def collect_data_policy_realtime(item_id: str, maturity: str) -> CollectedResult:
    """6.1.2.3_2: 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "policy_realtime_count", 1.0, ["policy_violation"], "now-3600s")


def collect_data_governance_integrated(item_id: str, maturity: str) -> CollectedResult:
    """6.1.2.4_1: 통합 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "governance_integrated_count", 1.0, ["data_governance"])


def collect_data_access_auto_adjust(item_id: str, maturity: str) -> CollectedResult:
    """6.2.1.4_1: 알림 AND 자동 조정 이벤트 → 충족 / 알림만 → 부분충족"""
    mk, thr, raw = "access_auto_adjust_count", 1.0, {}
    try:
        count = float(_indexer_count("wazuh-alerts-*", {
            "query": {"term": {"rule.groups": "data_access"}}
        }))
        ar = _wazuh_get("/active-response")
        ar_count = len(ar.get("data", {}).get("affected_items", []))
        if count >= 1 and ar_count >= 1:
            res = "충족"
        elif count >= 1:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"data_alerts": int(count), "ar_count": ar_count})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_data_encryption_basic(item_id: str, maturity: str) -> CollectedResult:
    """6.3.1.2_1: 활성 에이전트 ≥ 1 → 충족"""
    mk, thr = "encryption_agent_count", 1.0
    try:
        agents = _get_active_agents()
        count = float(len(agents))
        res = "충족" if count >= thr else "미충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"agent_count": int(count)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_data_encryption_integrated(item_id: str, maturity: str) -> CollectedResult:
    """6.3.1.3_1: 통합 운영 → 충족 / 부분 → 부분충족"""
    return _alert_only(item_id, maturity, "encryption_integrated_count", 1.0, ["encryption"])


def collect_data_masking_realtime(item_id: str, maturity: str) -> CollectedResult:
    """6.3.1.4_2: 마스킹 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "masking_alert_count", 1.0, ["data_masking"])


def collect_data_label_monitor(item_id: str, maturity: str) -> CollectedResult:
    """6.4.1.2_2: 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "label_monitor_count", 1.0, ["data_label"])


def collect_auto_label_classify(item_id: str, maturity: str) -> CollectedResult:
    """6.4.1.3_1: 자동 분류 알림 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "auto_label_count", 1.0, ["data_classification"])


def collect_label_security_integration(item_id: str, maturity: str) -> CollectedResult:
    """6.4.1.3_2: 연계 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "label_integration_count", 1.0, ["data_label", "security"])


def collect_dlp_policy_central(item_id: str, maturity: str) -> CollectedResult:
    """6.5.1.2_2: DLP 룰 ≥ 1 → 충족"""
    mk, thr = "dlp_rule_count", 1.0
    try:
        r = _wazuh_get("/rules", {"search": "data_loss", "status": "enabled"})
        count = float(r.get("data", {}).get("total_affected_items", 0))
        res = "충족" if count >= thr else "미충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"dlp_rule_count": int(count)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_dlp_monitor_mode(item_id: str, maturity: str) -> CollectedResult:
    """6.5.1.2_3: 모니터링 알림 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "dlp_monitor_count", 1.0, ["data_loss"], "now-86400s")


def collect_dlp_realtime(item_id: str, maturity: str) -> CollectedResult:
    """6.5.1.3_1: 알림 AND 처리지연 ≤ 60s → 충족 / 수집만 → 부분충족"""
    mk, thr, raw = "dlp_realtime_count", 1.0, {}
    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 5, "track_total_hits": True,
            "query": {"bool": {"must": [
                {"bool": {"should": [
                    {"term": {"rule.groups": "data_loss"}},
                    {"term": {"rule.groups": "exfiltration"}},
                ]}},
                {"range": {"@timestamp": {"gte": "now-3600s"}}}
            ]}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        })
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
        return _ok(item_id, maturity, res, mk, count, thr, {"count": int(count), "delay_sec": delay_sec})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_dlp_prevent_mode(item_id: str, maturity: str) -> CollectedResult:
    """6.5.1.3_2: 차단 룰 AND 실행 이력 ≥ 1 → 충족 / 룰만 → 부분충족"""
    mk, thr, raw = "dlp_prevent_count", 1.0, {}
    rule_ok = False
    try:
        r = _wazuh_get("/rules", {"search": "data_loss", "status": "enabled", "limit": 1})
        rule_ok = r.get("data", {}).get("total_affected_items", 0) >= 1
    except Exception as e:
        raw["rules_error"] = str(e)
    try:
        ar = _wazuh_get("/active-response")
        ar_items = ar.get("data", {}).get("affected_items", [])
        ar_count = len(ar_items)
        if rule_ok and ar_count >= 1:
            res = "충족"
        elif rule_ok:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, float(ar_count), thr, {"rule_ok": rule_ok, "ar_count": ar_count})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_dlp_auto_optimize(item_id: str, maturity: str) -> CollectedResult:
    """6.5.1.4_2: 자동 최적화 알림 → 충족 / 미수집 → 미충족"""
    mk, thr = "dlp_optimize_count", 1.0
    try:
        count = float(_indexer_count("wazuh-alerts-*", {
            "query": {"bool": {"should": [
                {"term": {"rule.groups": "data_loss"}},
                {"term": {"rule.groups": "policy_changed"}},
            ]}}
        }))
        res = "충족" if count >= thr else "미충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"count": int(count)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_data_activity_monitor(item_id: str, maturity: str) -> CollectedResult:
    """6.5.2.2_1: FIM 에이전트 ≥ 1 AND 감시 디렉토리 ≥ 1 → 충족 / 에이전트만 → 부분충족"""
    mk, thr, raw = "fim_dir_count", 1.0, {}
    try:
        agents = _get_active_agents()
        agent_count = len(agents)
        fim_count = 0
        dir_count = 0
        for a in agents[:5]:
            try:
                r = _wazuh_get(f"/syscheck/{a['id']}", {"limit": 1})
                items = r.get("data", {}).get("affected_items", [])
                if items:
                    fim_count += 1
                    dir_count += len(items)
            except Exception:
                pass
        if fim_count >= 1 and dir_count >= 1:
            res = "충족"
        elif agent_count >= 1:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, float(dir_count), thr, {"fim_agents": fim_count, "dirs": dir_count})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_data_anomaly_detect(item_id: str, maturity: str) -> CollectedResult:
    """6.5.2.2_2: 알림 수집 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "data_anomaly_count", 1.0, ["data_access", "anomaly"])


def collect_data_realtime_anomaly(item_id: str, maturity: str) -> CollectedResult:
    """6.5.2.3_1: 알림 AND 처리지연 ≤ 60s → 충족 / 수집만 → 부분충족"""
    mk, thr, raw = "data_realtime_count", 1.0, {}
    try:
        ir = _indexer_search("wazuh-alerts-*", {
            "size": 5, "track_total_hits": True,
            "query": {"bool": {"must": [
                {"term": {"rule.groups": "data_access"}},
                {"range": {"@timestamp": {"gte": "now-3600s"}}}
            ]}},
            "sort": [{"@timestamp": {"order": "desc"}}],
        })
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
        return _ok(item_id, maturity, res, mk, count, thr, {"count": int(count)})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


def collect_data_security_integration(item_id: str, maturity: str) -> CollectedResult:
    """6.5.2.3_2: 연계 알림 → 충족 / 미수집 → 미충족"""
    return _alert_only(item_id, maturity, "data_integration_count", 1.0, ["data_access", "security"])


def collect_data_context_access(item_id: str, maturity: str) -> CollectedResult:
    """6.5.2.4_1: 모니터링 AND 최소 접근제어 정책 ≥ 1 → 충족 / 모니터링만 → 부분충족"""
    mk, thr, raw = "context_access_count", 1.0, {}
    try:
        count = float(_indexer_count("wazuh-alerts-*", {
            "query": {"term": {"rule.groups": "data_access"}}
        }))
        ar = _wazuh_get("/active-response")
        ar_count = len(ar.get("data", {}).get("affected_items", []))
        if count >= 1 and ar_count >= 1:
            res = "충족"
        elif count >= 1:
            res = "부분충족"
        else:
            res = "미충족"
        return _ok(item_id, maturity, res, mk, count, thr, {"alert_count": int(count), "ar_count": ar_count})
    except Exception as exc:
        return _err(item_id, maturity, mk, thr, str(exc))


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
