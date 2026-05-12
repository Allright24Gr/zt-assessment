from flask import Flask, request, jsonify
from datetime import datetime, timezone
import subprocess
import xml.etree.ElementTree as ET
import statistics

app = Flask(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _base_result(metric_key: str, tool: str = "nmap") -> dict:
    return {
        "item_id": "",
        "tool": tool,
        "metric_key": metric_key,
        "metric_value": 0,
        "threshold": 0,
        "raw_json": {},
        "collected_at": _now(),
        "error": None,
    }


def _run_nmap(args: list, timeout: int = 60) -> tuple[dict, str | None]:
    """nmap을 실행하고 XML 결과를 파싱한다."""
    try:
        cmd = ["nmap", "-oX", "-"] + args
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            return {}, proc.stderr.strip()
        root = ET.fromstring(proc.stdout)
        return {"xml_output": proc.stdout, "hosts": _parse_hosts(root)}, None
    except subprocess.TimeoutExpired:
        return {}, f"nmap 실행 타임아웃 ({timeout}초)"
    except Exception as exc:
        return {}, str(exc)


def _parse_hosts(root: ET.Element) -> list:
    hosts = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        address = addr_el.get("addr", "") if addr_el is not None else ""
        status_el = host.find("status")
        status = status_el.get("state", "unknown") if status_el is not None else "unknown"
        ports = []
        for port in host.findall(".//port"):
            state_el = port.find("state")
            service_el = port.find("service")
            ports.append({
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "state": state_el.get("state") if state_el is not None else "unknown",
                "service": service_el.get("name") if service_el is not None else "",
                "version": service_el.get("version", "") if service_el is not None else "",
            })
        scripts = []
        for script in host.findall(".//script"):
            scripts.append({"id": script.get("id"), "output": script.get("output")})
        hosts.append({"address": address, "status": status, "ports": ports, "scripts": scripts})
    return hosts


@app.post("/scan/ports")
def scan_ports():
    """포트 스캔: 열려 있는 포트 목록을 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    target_ip = body.get("target_ip", "")
    ports = body.get("ports", "1-1024")

    result = _base_result("open_port_count")
    result["item_id"] = body.get("item_id", "")

    if not target_ip:
        result["error"] = "target_ip 파라미터가 필요합니다."
        return jsonify(result), 400

    raw, err = _run_nmap(["-p", str(ports), "--open", target_ip])
    if err:
        result["error"] = err
        return jsonify(result), 500

    open_ports = [
        p for h in raw.get("hosts", []) for p in h["ports"]
        if p["state"] == "open"
    ]
    result["metric_value"] = len(open_ports)
    result["raw_json"] = raw
    return jsonify(result)


@app.post("/scan/tls")
def scan_tls():
    """TLS 적용 여부 스캔: ssl-cert 스크립트로 포트별 TLS 상태를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    target_ip = body.get("target_ip", "")

    result = _base_result("tls_covered_ratio")
    result["item_id"] = body.get("item_id", "")

    if not target_ip:
        result["error"] = "target_ip 파라미터가 필요합니다."
        return jsonify(result), 400

    raw, err = _run_nmap(["-p", "443,8443,8080,80", "--script", "ssl-cert", target_ip])
    if err:
        result["error"] = err
        return jsonify(result), 500

    total_ports, tls_ports = 0, 0
    for host in raw.get("hosts", []):
        for port in host["ports"]:
            if port["state"] == "open":
                total_ports += 1
        for script in host["scripts"]:
            if script["id"] == "ssl-cert":
                tls_ports += 1

    ratio = (tls_ports / total_ports) if total_ports > 0 else 0.0
    result["metric_value"] = round(ratio, 4)
    result["threshold"] = 1.0
    result["raw_json"] = raw
    return jsonify(result)


@app.post("/scan/subnets")
def scan_subnets():
    """서브넷 탐지: 네트워크 범위 내 고유 서브넷(/24) 수를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    network_range = body.get("network_range", "")

    result = _base_result("subnet_count")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 2

    if not network_range:
        result["error"] = "network_range 파라미터가 필요합니다."
        return jsonify(result), 400

    raw, err = _run_nmap(["-sn", network_range])
    if err:
        result["error"] = err
        return jsonify(result), 500

    hosts = raw.get("hosts", [])
    active_hosts = [h for h in hosts if h.get("status") == "up"]
    subnets: set[str] = set()
    for h in active_hosts:
        parts = h.get("address", "").split(".")
        if len(parts) == 4:
            subnets.add(".".join(parts[:3]))

    result["metric_value"] = len(subnets)
    result["raw_json"] = {
        **raw,
        "active_host_count": len(active_hosts),
        "subnets": list(subnets),
    }
    return jsonify(result)


@app.post("/scan/hosts")
def scan_hosts():
    """활성 호스트 비율: 등록 자산 대비 탐지된 호스트 비율을 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    network_range = body.get("network_range", "")
    registered_asset_count = body.get("registered_asset_count", 0)

    result = _base_result("host_discovery_ratio")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 0.8

    if not network_range:
        result["error"] = "network_range 파라미터가 필요합니다."
        return jsonify(result), 400

    if not registered_asset_count:
        result["error"] = "자산 수 미설정"
        return jsonify(result), 400

    raw, err = _run_nmap(["-sn", network_range])
    if err:
        result["error"] = err
        return jsonify(result), 500

    up_hosts = [h for h in raw.get("hosts", []) if h.get("status") == "up"]
    ratio = round(len(up_hosts) / registered_asset_count, 4) if registered_asset_count > 0 else 0.0
    result["metric_value"] = ratio
    result["raw_json"] = {
        **raw,
        "up_host_count": len(up_hosts),
        "registered_asset_count": registered_asset_count,
    }
    return jsonify(result)


@app.post("/scan/port-distribution")
def scan_port_distribution():
    """호스트별 포트 분포: 포트 수 분산값을 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    network_range = body.get("network_range", "")

    result = _base_result("port_distribution_variance")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 0

    if not network_range:
        result["error"] = "network_range 파라미터가 필요합니다."
        return jsonify(result), 400

    raw, err = _run_nmap(["-p", "1-1024", network_range])
    if err:
        result["error"] = err
        return jsonify(result), 500

    host_port_map: dict[str, int] = {}
    for h in raw.get("hosts", []):
        open_count = sum(1 for p in h["ports"] if p["state"] == "open")
        host_port_map[h["address"]] = open_count

    port_counts = list(host_port_map.values())
    variance = round(statistics.variance(port_counts), 4) if len(port_counts) >= 2 else 0.0
    result["metric_value"] = variance
    result["raw_json"] = {**raw, "host_port_map": host_port_map}
    return jsonify(result)


@app.post("/scan/tls-version")
def scan_tls_version():
    """TLS 버전 검사: TLS 1.3 비율과 약한 암호 수를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    target_ip = body.get("target_ip", "")

    result = _base_result("tls13_ratio")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 0.8

    if not target_ip:
        result["error"] = "target_ip 파라미터가 필요합니다."
        return jsonify(result), 400

    raw, err = _run_nmap(["-p", "443,8443", "--script", "ssl-enum-ciphers", target_ip])
    if err:
        result["error"] = err
        return jsonify(result), 500

    tls13_count = 0
    total_services = 0
    weak_cipher_count = 0
    weak_patterns = {"RC4", "3DES", "NULL", "DES", "EXPORT"}

    for host in raw.get("hosts", []):
        for script in host.get("scripts", []):
            if script.get("id") == "ssl-enum-ciphers":
                total_services += 1
                output = script.get("output", "")
                if "TLSv1.3" in output:
                    tls13_count += 1
                if any(p in output for p in weak_patterns):
                    weak_cipher_count += 1

    ratio = round(tls13_count / total_services, 4) if total_services > 0 else 0.0
    result["metric_value"] = ratio
    result["raw_json"] = {
        **raw,
        "tls13_count": tls13_count,
        "total_services": total_services,
        "weak_cipher_count": weak_cipher_count,
    }
    return jsonify(result)


@app.post("/scan/services")
def scan_services():
    """서비스 매핑: 식별된 서비스 수를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    target_ip = body.get("target_ip", "")

    result = _base_result("service_mapping_count")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 1

    if not target_ip:
        result["error"] = "target_ip 파라미터가 필요합니다."
        return jsonify(result), 400

    raw, err = _run_nmap(["-sV", target_ip])
    if err:
        result["error"] = err
        return jsonify(result), 500

    service_set: set[str] = set()
    for h in raw.get("hosts", []):
        for p in h["ports"]:
            if p["state"] == "open" and p.get("service"):
                service_set.add(p["service"])

    result["metric_value"] = len(service_set)
    result["raw_json"] = {**raw, "services": list(service_set)}
    return jsonify(result)


@app.post("/scan/redundancy")
def scan_redundancy():
    """이중화 경로: 동일 서비스 포트가 열린 호스트 수를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    network_range = body.get("network_range", "")
    service_port = str(body.get("service_port", "80"))

    result = _base_result("redundancy_path_count")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 2

    if not network_range:
        result["error"] = "network_range 파라미터가 필요합니다."
        return jsonify(result), 400

    raw, err = _run_nmap(["-p", service_port, network_range])
    if err:
        result["error"] = err
        return jsonify(result), 500

    redundant_hosts = [
        h["address"] for h in raw.get("hosts", [])
        if any(p["state"] == "open" and p["port"] == service_port for p in h["ports"])
    ]
    result["metric_value"] = len(redundant_hosts)
    result["raw_json"] = {**raw, "redundant_hosts": redundant_hosts}
    return jsonify(result)


@app.post("/scan/vpn")
def scan_vpn():
    """VPN 포트 탐지: VPN 관련 포트 수를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    target_ip = body.get("target_ip", "")

    result = _base_result("vpn_port_count")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 1

    if not target_ip:
        result["error"] = "target_ip 파라미터가 필요합니다."
        return jsonify(result), 400

    raw, err = _run_nmap(["-p", "1194,500,4500,1723,443", target_ip])
    if err:
        result["error"] = err
        return jsonify(result), 500

    vpn_ports = {"1194", "500", "4500", "1723"}
    vpn_open = [
        p for h in raw.get("hosts", []) for p in h["ports"]
        if p["state"] == "open" and p["port"] in vpn_ports
    ]
    result["metric_value"] = len(vpn_open)
    result["raw_json"] = {**raw, "vpn_open_ports": [p["port"] for p in vpn_open]}
    return jsonify(result)


@app.post("/scan/vulnerable-services")
def scan_vulnerable_services():
    """취약 서비스 탐지: 알려진 취약 버전 서비스 수를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    target_ip = body.get("target_ip", "")

    result = _base_result("vulnerable_service_count")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 0

    if not target_ip:
        result["error"] = "target_ip 파라미터가 필요합니다."
        return jsonify(result), 400

    VULNERABLE_PATTERNS: dict[str, list[str]] = {
        "openssh": ["6.", "5.", "4.", "3.", "2."],
        "apache": ["1.", "2.0", "2.2"],
        "nginx": ["0.", "1.0", "1.2", "1.4", "1.6", "1.8"],
        "ftp": ["vsftpd 2.3.4", "proftpd 1.3.3"],
        "telnet": [],
        "rsh": [],
        "rlogin": [],
    }

    raw, err = _run_nmap(["-sV", target_ip])
    if err:
        result["error"] = err
        return jsonify(result), 500

    vulnerable = []
    for h in raw.get("hosts", []):
        for p in h["ports"]:
            if p["state"] != "open":
                continue
            svc = p.get("service", "").lower()
            ver = p.get("version", "").lower()
            for vuln_svc, vuln_versions in VULNERABLE_PATTERNS.items():
                if vuln_svc in svc:
                    if not vuln_versions or any(v in ver for v in vuln_versions):
                        vulnerable.append({"port": p["port"], "service": svc, "version": ver})
                        break

    result["metric_value"] = len(vulnerable)
    result["raw_json"] = {**raw, "vulnerable_services": vulnerable}
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
