"""
nmap_collector.py — Nmap 래퍼 기반 수집 모듈 (14개 함수)
엔드포인트: POST /scan/ports, /scan/subnets, /scan/tls
"""
from datetime import datetime, timezone
import os
import httpx

CollectedResult = dict

NMAP_WRAPPER_URL = os.getenv("NMAP_WRAPPER_URL", "http://localhost:8001")
NMAP_TARGET = os.getenv("NMAP_TARGET", "127.0.0.1")


# ─── Helpers ─────────────────────────────────────────────────────────────────

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


def _scan_ports(payload: dict, timeout: int = 90) -> tuple[dict, str | None]:
    try:
        resp = httpx.post(f"{NMAP_WRAPPER_URL}/scan/ports", json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("error"):
            return data, data["error"]
        return data, None
    except Exception as e:
        return {}, str(e)


def _scan_subnets(payload: dict, timeout: int = 90) -> tuple[dict, str | None]:
    try:
        resp = httpx.post(f"{NMAP_WRAPPER_URL}/scan/subnets", json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("error"):
            return data, data["error"]
        return data, None
    except Exception as e:
        return {}, str(e)


def _scan_tls(payload: dict, timeout: int = 90) -> tuple[dict, str | None]:
    try:
        resp = httpx.post(f"{NMAP_WRAPPER_URL}/scan/tls", json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("error"):
            return data, data["error"]
        return data, None
    except Exception as e:
        return {}, str(e)


# ─── 14 Collector Functions ───────────────────────────────────────────────────

def collect_host_discovery() -> CollectedResult:
    """2.1.1.1_1 — 호스트 발견: 식별된 호스트 수 >= 1"""
    item_id, maturity = "2.1.1.1_1", "기존"
    mk, thr = "identified_host_count", 1.0
    data, error = _scan_ports({"target_ip": NMAP_TARGET, "ports": "1-1024"})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("host_count", data.get("metric_value", 0)))
    result = "충족" if count >= thr else "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_port_service_map() -> CollectedResult:
    """2.4.2.2_1 — 포트/서비스 맵: 스캔 수행 여부 (1=수행)"""
    item_id, maturity = "2.4.2.2_1", "초기"
    mk, thr = "scan_performed", 1.0
    data, error = _scan_ports({"target_ip": NMAP_TARGET, "ports": "1-65535"})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    performed = 1.0 if data.get("ports") is not None or data.get("metric_value") is not None else 0.0
    result = "충족" if performed >= thr else "미충족"
    return _ok(item_id, maturity, result, mk, performed, thr, data)


def collect_subnet_topology() -> CollectedResult:
    """3.1.1.1_1 — 서브넷 토폴로지: 서브넷 수 >= 2"""
    item_id, maturity = "3.1.1.1_1", "기존"
    mk, thr = "subnet_count", 2.0
    data, error = _scan_subnets({"network_range": NMAP_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("subnet_count", data.get("metric_value", 0)))
    if count >= thr:
        result = "충족"
    elif count == 1:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_subnet_traffic_map() -> CollectedResult:
    """3.1.1.1_2 — 서브넷 간 트래픽 맵: 서브넷 수 >= 2"""
    item_id, maturity = "3.1.1.1_2", "초기"
    mk, thr = "subnet_count", 2.0
    data, error = _scan_subnets({"network_range": NMAP_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("subnet_count", data.get("metric_value", 0)))
    if count >= thr:
        result = "충족"
    elif count == 1:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_micro_segment_ports() -> CollectedResult:
    """3.1.2.1_1 — 마이크로세그먼트 포트 프로파일: 고유 포트 프로파일 수 >= 2"""
    item_id, maturity = "3.1.2.1_1", "기존"
    mk, thr = "unique_port_profile_count", 2.0
    data, error = _scan_ports({"target_ip": NMAP_TARGET, "ports": "1-1024"})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("unique_port_profile_count", data.get("metric_value", 0)))
    if count >= thr:
        result = "충족"
    elif count == 1:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_tls_ratio() -> CollectedResult:
    """3.3.1.1_1 — TLS 적용률: tls_ratio >= 0.5"""
    item_id, maturity = "3.3.1.1_1", "기존"
    mk, thr = "tls_ratio", 0.5
    data, error = _scan_tls({"target_ip": NMAP_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    ratio = float(data.get("tls_ratio", data.get("metric_value", 0)))
    if ratio >= 1.0:
        result = "충족"
    elif ratio >= thr:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, ratio, thr, data)


def collect_tls_services() -> CollectedResult:
    """3.3.1.1_2 — TLS 적용 서비스 수: tls_service_count >= 1"""
    item_id, maturity = "3.3.1.1_2", "초기"
    mk, thr = "tls_service_count", 1.0
    data, error = _scan_tls({"target_ip": NMAP_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("tls_service_count", data.get("metric_value", 0)))
    result = "충족" if count >= thr else "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_tls_advanced() -> CollectedResult:
    """3.3.1.3_2 — TLS 1.3 적용률: tls13_ratio >= 0.8"""
    item_id, maturity = "3.3.1.3_2", "초기"
    mk, thr = "tls13_ratio", 0.8
    data, error = _scan_tls({"target_ip": NMAP_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    ratio = float(data.get("tls13_ratio", data.get("metric_value", 0)))
    if ratio >= thr:
        result = "충족"
    elif ratio >= 0.5:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, ratio, thr, data)


def collect_app_traffic_map() -> CollectedResult:
    """3.4.1.2_1 — 앱 트래픽 맵: service_map_count >= 1"""
    item_id, maturity = "3.4.1.2_1", "초기"
    mk, thr = "service_map_count", 1.0
    data, error = _scan_ports({"target_ip": NMAP_TARGET, "ports": "1-65535"})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("service_map_count", data.get("metric_value", 0)))
    result = "충족" if count >= thr else "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_network_redundancy() -> CollectedResult:
    """3.5.1.2_3 — 네트워크 이중화: redundant_subnet_count >= 2"""
    item_id, maturity = "3.5.1.2_3", "최적화"
    mk, thr = "redundant_subnet_count", 2.0
    data, error = _scan_subnets({"network_range": NMAP_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("redundant_subnet_count", data.get("metric_value", 0)))
    if count >= thr:
        result = "충족"
    elif count == 1:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_subnet_segmentation() -> CollectedResult:
    """4.3.1.1_1 — 서브넷 세분화: subnet_count >= 2"""
    item_id, maturity = "4.3.1.1_1", "기존"
    mk, thr = "subnet_count", 2.0
    data, error = _scan_subnets({"network_range": NMAP_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("subnet_count", data.get("metric_value", 0)))
    if count >= thr:
        result = "충족"
    elif count == 1:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_perimeter_model() -> CollectedResult:
    """4.3.1.1_2 — 경계 모델 포트 제한: open_port_count >= 1 (최소 포트 개방 확인)"""
    item_id, maturity = "4.3.1.1_2", "초기"
    mk, thr = "open_port_count", 1.0
    data, error = _scan_ports({"target_ip": NMAP_TARGET, "ports": "1-65535"})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("open_port_count", data.get("metric_value", 0)))
    if count == 0:
        result = "미충족"
    elif count <= 10:
        result = "충족"
    else:
        result = "부분충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_system_subnet_separation() -> CollectedResult:
    """4.3.1.2_1 — 시스템-서브넷 분리: subnet_count >= 2"""
    item_id, maturity = "4.3.1.2_1", "기존"
    mk, thr = "subnet_count", 2.0
    data, error = _scan_subnets({"network_range": NMAP_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("subnet_count", data.get("metric_value", 0)))
    if count >= thr:
        result = "충족"
    elif count == 1:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_vpn_ports() -> CollectedResult:
    """5.3.1.1_1 — VPN 포트 확인: vpn_port_count >= 1 (포트 1194/500/4500/1723)"""
    item_id, maturity = "5.3.1.1_1", "기존"
    mk, thr = "vpn_port_count", 1.0
    data, error = _scan_ports({"target_ip": NMAP_TARGET, "ports": "500,1194,1723,4500"})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    ports_open = data.get("ports", [])
    vpn_ports = {500, 1194, 1723, 4500}
    if isinstance(ports_open, list):
        count = float(len([p for p in ports_open if int(p) in vpn_ports]))
    else:
        count = float(data.get("vpn_port_count", data.get("metric_value", 0)))
    result = "충족" if count >= thr else "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)
