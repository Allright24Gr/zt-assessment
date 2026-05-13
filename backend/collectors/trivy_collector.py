from datetime import datetime, timezone
import os
import httpx


CollectedResult = dict

TRIVY_WRAPPER_URL = os.environ.get("TRIVY_WRAPPER_URL", "http://trivy-wrapper:5001")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ok(item_id: str, maturity: str, result: str, metric_key: str,
        metric_value: float, threshold: float, raw: dict) -> CollectedResult:
    return {
        "item_id": item_id, "maturity": maturity, "tool": "trivy",
        "result": result, "metric_key": metric_key, "metric_value": metric_value,
        "threshold": threshold, "raw_json": raw, "collected_at": _now_iso(),
        "error": None,
    }


def _err(item_id: str, maturity: str, metric_key: str, threshold: float,
         error: str, raw: dict = None) -> CollectedResult:
    return {
        "item_id": item_id, "maturity": maturity, "tool": "trivy",
        "result": "평가불가", "metric_key": metric_key, "metric_value": 0.0,
        "threshold": threshold, "raw_json": raw or {}, "collected_at": _now_iso(),
        "error": error,
    }


def collect_image_vulnerabilities(
    item_id: str,
    maturity: str,
    image_name: str,
) -> CollectedResult:
    mk, thr = "critical_high_vuln_count", 0.0
    try:
        resp = httpx.post(
            f"{TRIVY_WRAPPER_URL}/scan/image",
            json={"item_id": item_id, "image_name": image_name},
            timeout=150,
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
    elif count <= 5:
        result = "부분충족"
    else:
        result = "미충족"

    return _ok(item_id, maturity, result, mk, count, thr, data.get("raw_json", {}))


def collect_filesystem_scan(
    item_id: str,
    maturity: str,
    scan_path: str,
) -> CollectedResult:
    mk, thr = "fs_vuln_count", 10.0
    try:
        resp = httpx.post(
            f"{TRIVY_WRAPPER_URL}/scan/fs",
            json={"item_id": item_id, "path": scan_path},
            timeout=150,
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


def collect_sbom(
    item_id: str,
    maturity: str,
    image_name: str,
) -> CollectedResult:
    mk, thr = "sbom_component_count", 1.0
    try:
        resp = httpx.post(
            f"{TRIVY_WRAPPER_URL}/scan/sbom",
            json={"item_id": item_id, "image_name": image_name},
            timeout=330,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        return _err(item_id, maturity, mk, thr, str(e))

    if data.get("error"):
        return _err(item_id, maturity, mk, thr, data["error"], data.get("raw_json", {}))

    count = float(data.get("metric_value", 0))
    result = "충족" if count >= thr else "미충족"

    return _ok(item_id, maturity, result, mk, count, thr, data.get("raw_json", {}))
