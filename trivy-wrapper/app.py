from flask import Flask, request, jsonify
from datetime import datetime, timezone
import subprocess
import json
import os

app = Flask(__name__)

_TRIVY_ENV = {**os.environ, "TRIVY_NO_PROGRESS": "true"}


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


def _run_trivy(args: list, timeout: int = 120) -> tuple[dict, str | None]:
    """trivy를 실행하고 JSON 결과를 파싱한다."""
    try:
        cmd = ["trivy", "--quiet", "--format", "json"] + args
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=_TRIVY_ENV)
        if proc.returncode not in (0, 1):  # trivy returns 1 when vulns found
            return {}, proc.stderr.strip() or f"trivy 종료 코드: {proc.returncode}"
        parsed = json.loads(proc.stdout) if proc.stdout.strip() else {}
        return parsed, None
    except subprocess.TimeoutExpired:
        return {}, f"trivy 실행 타임아웃 ({timeout}초)"
    except json.JSONDecodeError as exc:
        return {}, f"JSON 파싱 오류: {exc}"
    except Exception as exc:
        return {}, str(exc)


def _run_trivy_sbom(image_name: str, timeout: int = 300) -> tuple[dict, str | None]:
    """trivy spdx-json 포맷으로 SBOM을 생성한다."""
    try:
        cmd = ["trivy", "--quiet", "--format", "spdx-json", "image", image_name]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=_TRIVY_ENV)
        if proc.returncode not in (0, 1):
            return {}, proc.stderr.strip() or f"trivy 종료 코드: {proc.returncode}"
        parsed = json.loads(proc.stdout) if proc.stdout.strip() else {}
        return parsed, None
    except subprocess.TimeoutExpired:
        return {}, f"trivy SBOM 생성 타임아웃 ({timeout}초)"
    except json.JSONDecodeError as exc:
        return {}, f"SBOM JSON 파싱 오류: {exc}"
    except Exception as exc:
        return {}, str(exc)


def _count_by_severity(raw: dict) -> dict[str, int]:
    """취약점 결과에서 심각도별 건수를 집계한다."""
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
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

    raw, err = _run_trivy(["image", image_name], timeout=120)
    if err:
        result["error"] = err
        return jsonify(result), 500

    counts = _count_by_severity(raw)
    result["metric_value"] = counts["CRITICAL"] + counts["HIGH"]
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

    raw, err = _run_trivy(["fs", scan_path], timeout=120)
    if err:
        result["error"] = err
        return jsonify(result), 500

    counts = _count_by_severity(raw)
    result["metric_value"] = sum(counts.values())
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

    sbom_data, err = _run_trivy_sbom(image_name, timeout=300)
    if err:
        result["error"] = err
        return jsonify(result), 500

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
    return jsonify(result)


@app.post("/scan/cicd")
def scan_cicd():
    """CI/CD 자동 스캔: 이미지 배열에 대한 스캔 완료 비율을 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    image_names = body.get("image_names", [])

    result = _base_result("cicd_scan_ratio")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 0.9

    if not image_names:
        result["error"] = "image_names 파라미터가 필요합니다."
        return jsonify(result), 400

    scanned = 0
    image_results: dict = {}
    for img in image_names:
        raw, err = _run_trivy(["image", img], timeout=120)
        if err:
            image_results[img] = {"error": err}
        else:
            image_results[img] = {"severity_counts": _count_by_severity(raw)}
            scanned += 1

    ratio = round(scanned / len(image_names), 4) if image_names else 0.0
    result["metric_value"] = ratio
    result["raw_json"] = {"image_results": image_results, "scanned": scanned, "total": len(image_names)}
    return jsonify(result)


@app.post("/scan/integrity")
def scan_integrity():
    """코드 무결성: 이미지 스캔 수행 여부와 수정 가능한 CRITICAL 취약점 수를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    image_name = body.get("image_name", "")

    result = _base_result("integrity_check_count")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 1

    if not image_name:
        result["error"] = "image_name 파라미터가 필요합니다."
        return jsonify(result), 400

    raw, err = _run_trivy(["image", image_name], timeout=120)
    if err:
        result["error"] = err
        return jsonify(result), 500

    fixable_critical = sum(
        1 for r in raw.get("Results", [])
        for v in (r.get("Vulnerabilities") or [])
        if v.get("Severity", "").upper() == "CRITICAL" and v.get("FixedVersion")
    )
    result["metric_value"] = 1
    result["raw_json"] = {"fixable_critical_count": fixable_critical, "trivy_output": raw}
    return jsonify(result)


@app.post("/scan/compliance")
def scan_compliance():
    """정책 준수 검증: 수정 가능한 CRITICAL 취약점 수를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    image_name = body.get("image_name", "")

    result = _base_result("fixable_critical_count")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 0

    if not image_name:
        result["error"] = "image_name 파라미터가 필요합니다."
        return jsonify(result), 400

    raw, err = _run_trivy(["image", image_name], timeout=120)
    if err:
        result["error"] = err
        return jsonify(result), 500

    fixable_critical = sum(
        1 for r in raw.get("Results", [])
        for v in (r.get("Vulnerabilities") or [])
        if v.get("Severity", "").upper() == "CRITICAL" and v.get("FixedVersion")
    )
    result["metric_value"] = fixable_critical
    result["raw_json"] = {"severity_counts": _count_by_severity(raw), "trivy_output": raw}
    return jsonify(result)


@app.post("/scan/coverage")
def scan_coverage():
    """전 구성 요소 스캔: targets 배열에 대한 스캔 완료 비율을 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    targets = body.get("targets", [])

    result = _base_result("component_scan_ratio")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 0.9

    if not targets:
        result["error"] = "targets 파라미터가 필요합니다."
        return jsonify(result), 400

    scanned = 0
    target_results: dict = {}
    for target in targets:
        is_path = target.startswith("/") or target.startswith(".")
        subcmd = ["fs", target] if is_path else ["image", target]
        raw, err = _run_trivy(subcmd, timeout=120)
        if err:
            target_results[target] = {"error": err}
        else:
            target_results[target] = {"success": True}
            scanned += 1

    ratio = round(scanned / len(targets), 4) if targets else 0.0
    result["metric_value"] = ratio
    result["raw_json"] = {"target_results": target_results, "scanned": scanned, "total": len(targets)}
    return jsonify(result)


@app.post("/scan/third-party")
def scan_third_party():
    """서드파티 라이브러리: 파일시스템 스캔의 CRITICAL 취약점 수를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    scan_path = body.get("path", "")

    result = _base_result("third_party_critical_count")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 0

    if not scan_path:
        result["error"] = "path 파라미터가 필요합니다."
        return jsonify(result), 400

    raw, err = _run_trivy(["fs", scan_path], timeout=120)
    if err:
        result["error"] = err
        return jsonify(result), 500

    counts = _count_by_severity(raw)
    vuln_libs = [
        {"pkg": v.get("PkgName", ""), "fixed": v.get("FixedVersion", "")}
        for r in raw.get("Results", [])
        for v in (r.get("Vulnerabilities") or [])
        if v.get("Severity", "").upper() == "CRITICAL"
    ]
    result["metric_value"] = counts["CRITICAL"]
    result["raw_json"] = {"severity_counts": counts, "vulnerable_libraries": vuln_libs}
    return jsonify(result)


@app.post("/scan/sbom-full")
def scan_sbom_full():
    """전 주기 SBOM: 여러 이미지에 대한 SBOM 생성 성공 수를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    image_names = body.get("image_names", [])

    result = _base_result("full_sbom_count")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 1

    if not image_names:
        result["error"] = "image_names 파라미터가 필요합니다."
        return jsonify(result), 400

    success_count = 0
    sbom_results: dict = {}
    for img in image_names:
        sbom_data, err = _run_trivy_sbom(img, timeout=300)
        if err:
            sbom_results[img] = {"error": err}
        else:
            sbom_results[img] = {"component_count": len(sbom_data.get("packages", []))}
            success_count += 1

    result["metric_value"] = success_count
    result["raw_json"] = {"sbom_results": sbom_results}
    return jsonify(result)


@app.post("/scan/risk")
def scan_risk():
    """소프트웨어 위험 평가: 스캔 수행 여부를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    image_name = body.get("image_name", "")

    result = _base_result("risk_scan_count")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 1

    if not image_name:
        result["error"] = "image_name 파라미터가 필요합니다."
        return jsonify(result), 400

    raw, err = _run_trivy(["image", image_name], timeout=120)
    if err:
        result["error"] = err
        return jsonify(result), 500

    result["metric_value"] = 1
    result["raw_json"] = {"severity_counts": _count_by_severity(raw)}
    return jsonify(result)


@app.post("/scan/supply-chain")
def scan_supply_chain():
    """공급망 SBOM 기반 스캔: SBOM 생성 후 취약점 스캔 수행 여부를 반환한다."""
    body = request.get_json(force=True, silent=True) or {}
    image_name = body.get("image_name", "")

    result = _base_result("supply_chain_scan_count")
    result["item_id"] = body.get("item_id", "")
    result["threshold"] = 1

    if not image_name:
        result["error"] = "image_name 파라미터가 필요합니다."
        return jsonify(result), 400

    sbom_data, _ = _run_trivy_sbom(image_name, timeout=300)
    sbom_component_count = len(sbom_data.get("packages", []))

    raw, err = _run_trivy(["image", image_name], timeout=120)
    if err:
        result["error"] = err
        return jsonify(result), 500

    counts = _count_by_severity(raw)
    result["metric_value"] = 1
    result["raw_json"] = {
        "sbom_component_count": sbom_component_count,
        "vuln_count": sum(counts.values()),
        "severity_counts": counts,
    }
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
