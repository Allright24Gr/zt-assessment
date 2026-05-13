from datetime import datetime, timezone
import os
import httpx


CollectedResult = dict

NMAP_WRAPPER_URL = os.environ.get("NMAP_WRAPPER_URL", "http://nmap-wrapper:5000")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ok(item_id: str, maturity: str, result: str, metric_key: str,
        metric_value: float, threshold: float, raw: dict) -> CollectedResult:
    return {
        "item_id": item_id, "maturity": maturity, "tool": "nmap",
        "result": result, "metric_key": metric_key, "metric_value": metric_value,
        "threshold": threshold, "raw_json": raw, "collected_at": _now_iso(),
        "error": None,
    }


def _err(item_id: str, maturity: str, metric_key: str, threshold: float,
         error: str, raw: dict = None) -> CollectedResult:
    return {
        "item_id": item_id, "maturity": maturity, "tool": "nmap",
        "result": "평가불가", "metric_key": metric_key, "metric_value": 0.0,
        "threshold": threshold, "raw_json": raw or {}, "collected_at": _now_iso(),
        "error": error,
    }


def collect_open_ports(
    item_id: str,
    maturity: str,
    target_ip: str,
    ports: str = "1-1024",
) -> CollectedResult:
    mk, thr = "open_port_count", 5.0
    try:
        resp = httpx.post(
            f"{NMAP_WRAPPER_URL}/scan/ports",
            json={"item_id": item_id, "target_ip": target_ip, "ports": ports},
            timeout=90,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    if data.get("error"):
        return _err(item_id, maturity, mk, thr, data["error"], data.get("raw_json", {}))

    count = float(data.get("metric_value", 0))
    if count == 0:
        result = "충족"
    elif count <= thr:
        result = "부분충족"
    else:
        result = "미충족"

    return _ok(item_id, maturity, result, mk, count, thr, data.get("raw_json", {}))


def collect_tls_status(
    item_id: str,
    maturity: str,
    target_ip: str,
) -> CollectedResult:
    mk, thr = "tls_covered_ratio", 1.0
    try:
        resp = httpx.post(
            f"{NMAP_WRAPPER_URL}/scan/tls",
            json={"item_id": item_id, "target_ip": target_ip},
            timeout=90,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    if data.get("error"):
        return _err(item_id, maturity, mk, thr, data["error"], data.get("raw_json", {}))

    ratio = float(data.get("metric_value", 0))
    if ratio >= 1.0:
        result = "충족"
    elif ratio >= 0.5:
        result = "부분충족"
    else:
        result = "미충족"

    return _ok(item_id, maturity, result, mk, ratio, thr, data.get("raw_json", {}))


def collect_subnet_topology(
    item_id: str,
    maturity: str,
    network_range: str,
) -> CollectedResult:
    mk, thr = "subnet_count", 2.0
    try:
        resp = httpx.post(
            f"{NMAP_WRAPPER_URL}/scan/subnets",
            json={"item_id": item_id, "network_range": network_range},
            timeout=90,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    if data.get("error"):
        return _err(item_id, maturity, mk, thr, data["error"], data.get("raw_json", {}))

    count = float(data.get("metric_value", 0))
    if count >= thr:
        result = "충족"
    elif count == 1:
        result = "부분충족"
    else:
        result = "미충족"

    return _ok(item_id, maturity, result, mk, count, thr, data.get("raw_json", {}))
