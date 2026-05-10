from flask import Flask, request, jsonify
from datetime import datetime, timezone
import subprocess
import json
import xml.etree.ElementTree as ET

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


def _run_nmap(args: list) -> tuple[dict, str | None]:
    """nmap을 실행하고 XML 결과를 파싱한다."""
    try:
        cmd = ["nmap", "-oX", "-"] + args
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            return {}, proc.stderr.strip()
        root = ET.fromstring(proc.stdout)
        return {"xml_output": proc.stdout, "hosts": _parse_hosts(root)}, None
    except subprocess.TimeoutExpired:
        return {}, "nmap 실행 타임아웃 (120초)"
    except Exception as exc:
        return {}, str(exc)


def _parse_hosts(root: ET.Element) -> list:
    hosts = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        address = addr_el.get("addr", "") if addr_el is not None else ""
        ports = []
        for port in host.findall(".//port"):
            state_el = port.find("state")
            service_el = port.find("service")
            ports.append({
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "state": state_el.get("state") if state_el is not None else "unknown",
                "service": service_el.get("name") if service_el is not None else "",
            })
        scripts = []
        for script in host.findall(".//script"):
            scripts.append({"id": script.get("id"), "output": script.get("output")})
        hosts.append({"address": address, "ports": ports, "scripts": scripts})
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
    """서브넷 탐지: 네트워크 범위 내 활성 호스트와 서브넷 수를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    network_range = body.get("network_range", "")

    result = _base_result("active_host_count")
    result["item_id"] = body.get("item_id", "")

    if not network_range:
        result["error"] = "network_range 파라미터가 필요합니다."
        return jsonify(result), 400

    raw, err = _run_nmap(["-sn", network_range])
    if err:
        result["error"] = err
        return jsonify(result), 500

    host_count = len(raw.get("hosts", []))
    result["metric_value"] = host_count
    result["raw_json"] = raw
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
