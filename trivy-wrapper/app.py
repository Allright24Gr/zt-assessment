from flask import Flask, request, jsonify
from datetime import datetime, timezone
import subprocess
import json

app = Flask(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _base_result(metric_key: str, tool: str = "trivy") -> dict:
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


def _run_trivy(args: list) -> tuple[dict, str | None]:
    """trivy를 실행하고 JSON 결과를 파싱한다."""
    try:
        cmd = ["trivy", "--quiet", "--format", "json"] + args
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode not in (0, 1):  # trivy returns 1 when vulns found
            return {}, proc.stderr.strip() or f"trivy 종료 코드: {proc.returncode}"
        parsed = json.loads(proc.stdout) if proc.stdout.strip() else {}
        return parsed, None
    except subprocess.TimeoutExpired:
        return {}, "trivy 실행 타임아웃 (300초)"
    except json.JSONDecodeError as exc:
        return {}, f"JSON 파싱 오류: {exc}"
    except Exception as exc:
        return {}, str(exc)


def _count_by_severity(raw: dict) -> dict[str, int]:
    """취약점 결과에서 심각도별 건수를 집계한다."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for result in raw.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = vuln.get("Severity", "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1
    return counts


@app.post("/scan/image")
def scan_image():
    """컨테이너 이미지 취약점 스캔: Critical/High 취약점 수를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    image_name = body.get("image_name", "")

    result = _base_result("critical_high_vuln_count")
    result["item_id"] = body.get("item_id", "")

    if not image_name:
        result["error"] = "image_name 파라미터가 필요합니다."
        return jsonify(result), 400

    raw, err = _run_trivy(["image", image_name])
    if err:
        result["error"] = err
        return jsonify(result), 500

    counts = _count_by_severity(raw)
    critical_high = counts["CRITICAL"] + counts["HIGH"]
    result["metric_value"] = critical_high
    result["threshold"] = 0
    result["raw_json"] = {"severity_counts": counts, "trivy_output": raw}
    return jsonify(result)


@app.post("/scan/fs")
def scan_fs():
    """파일시스템 취약점 스캔: 심각도별 취약점 수를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    scan_path = body.get("path", "")

    result = _base_result("fs_vuln_count")
    result["item_id"] = body.get("item_id", "")

    if not scan_path:
        result["error"] = "path 파라미터가 필요합니다."
        return jsonify(result), 400

    raw, err = _run_trivy(["fs", scan_path])
    if err:
        result["error"] = err
        return jsonify(result), 500

    counts = _count_by_severity(raw)
    total = sum(counts.values())
    result["metric_value"] = total
    result["raw_json"] = {"severity_counts": counts, "trivy_output": raw}
    return jsonify(result)


@app.post("/scan/sbom")
def scan_sbom():
    """SBOM 생성: 컴포넌트 수와 라이선스 정보를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    image_name = body.get("image_name", "")

    result = _base_result("sbom_component_count")
    result["item_id"] = body.get("item_id", "")

    if not image_name:
        result["error"] = "image_name 파라미터가 필요합니다."
        return jsonify(result), 400

    try:
        cmd = ["trivy", "--quiet", "--format", "spdx-json", "image", image_name]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode not in (0, 1):
            result["error"] = proc.stderr.strip() or f"trivy 종료 코드: {proc.returncode}"
            return jsonify(result), 500

        sbom_data = json.loads(proc.stdout) if proc.stdout.strip() else {}
        packages = sbom_data.get("packages", [])
        licenses = list({
            lic
            for pkg in packages
            for lic in pkg.get("licenseConcluded", "").split(" AND ")
            if lic and lic != "NOASSERTION"
        })

        result["metric_value"] = len(packages)
        result["threshold"] = 1
        result["raw_json"] = {
            "component_count": len(packages),
            "licenses": licenses,
            "sbom": sbom_data,
        }
    except subprocess.TimeoutExpired:
        result["error"] = "trivy SBOM 생성 타임아웃 (300초)"
        return jsonify(result), 500
    except json.JSONDecodeError as exc:
        result["error"] = f"SBOM JSON 파싱 오류: {exc}"
        return jsonify(result), 500

    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
