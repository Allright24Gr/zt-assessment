"""
trivy_collector.py — Trivy 래퍼 기반 수집 모듈 (11개 함수)
엔드포인트: POST /scan/image, /scan/fs, /scan/sbom
"""
from datetime import datetime, timezone
import os
import httpx

CollectedResult = dict

TRIVY_WRAPPER_URL = os.getenv("TRIVY_WRAPPER_URL", "http://localhost:8002")
TRIVY_TARGET = os.getenv("TRIVY_TARGET", ".")


# ─── Helpers ─────────────────────────────────────────────────────────────────

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


def _scan_image(payload: dict, timeout: int = 150) -> tuple[dict, str | None]:
    try:
        resp = httpx.post(f"{TRIVY_WRAPPER_URL}/scan/image", json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("error"):
            return data, data["error"]
        return data, None
    except Exception as e:
        return {}, str(e)


def _scan_fs(payload: dict, timeout: int = 150) -> tuple[dict, str | None]:
    try:
        resp = httpx.post(f"{TRIVY_WRAPPER_URL}/scan/fs", json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("error"):
            return data, data["error"]
        return data, None
    except Exception as e:
        return {}, str(e)


def _scan_sbom(payload: dict, timeout: int = 330) -> tuple[dict, str | None]:
    try:
        resp = httpx.post(f"{TRIVY_WRAPPER_URL}/scan/sbom", json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        if data.get("error"):
            return data, data["error"]
        return data, None
    except Exception as e:
        return {}, str(e)


# ─── 11 Collector Functions ───────────────────────────────────────────────────

def collect_image_scan() -> CollectedResult:
    """6.1.1.1_1 — 이미지 취약점 스캔: critical_high_vuln_count == 0"""
    item_id, maturity = "6.1.1.1_1", "기존"
    mk, thr = "critical_high_vuln_count", 0.0
    data, error = _scan_image({"image_name": TRIVY_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("critical_high_vuln_count", data.get("metric_value", 0)))
    if count == 0:
        result = "충족"
    elif count <= 5:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_cicd_scan_ratio() -> CollectedResult:
    """6.1.1.2_1 — CI/CD 파이프라인 스캔 비율: scan_ratio >= 0.8"""
    item_id, maturity = "6.1.1.2_1", "초기"
    mk, thr = "scan_ratio", 0.8
    data, error = _scan_image({"image_name": TRIVY_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    ratio = float(data.get("scan_ratio", data.get("metric_value", 1.0)))
    if ratio >= thr:
        result = "충족"
    elif ratio >= 0.5:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, ratio, thr, data)


def collect_integrity_check() -> CollectedResult:
    """6.1.1.3_1 — 무결성 검증: integrity_check_passed >= 1"""
    item_id, maturity = "6.1.1.3_1", "향상"
    mk, thr = "integrity_check_passed", 1.0
    data, error = _scan_image({"image_name": TRIVY_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    passed = float(data.get("integrity_check_passed", data.get("metric_value", 0)))
    result = "충족" if passed >= thr else "미충족"
    return _ok(item_id, maturity, result, mk, passed, thr, data)


def collect_policy_compliance_scan() -> CollectedResult:
    """6.2.1.1_1 — 정책 컴플라이언스 스캔: compliance_pass_ratio >= 0.8"""
    item_id, maturity = "6.2.1.1_1", "기존"
    mk, thr = "compliance_pass_ratio", 0.8
    data, error = _scan_fs({"path": TRIVY_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    ratio = float(data.get("compliance_pass_ratio", data.get("metric_value", 0)))
    if ratio >= thr:
        result = "충족"
    elif ratio >= 0.5:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, ratio, thr, data)


def collect_full_component_scan() -> CollectedResult:
    """6.2.1.2_1 — 전체 컴포넌트 스캔: component_count >= 1"""
    item_id, maturity = "6.2.1.2_1", "초기"
    mk, thr = "component_count", 1.0
    data, error = _scan_fs({"path": TRIVY_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("component_count", data.get("metric_value", 0)))
    result = "충족" if count >= thr else "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_fs_scan() -> CollectedResult:
    """6.3.1.1_1 — 파일시스템 취약점 스캔: fs_vuln_count == 0"""
    item_id, maturity = "6.3.1.1_1", "기존"
    mk, thr = "fs_vuln_count", 0.0
    data, error = _scan_fs({"path": TRIVY_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("fs_vuln_count", data.get("metric_value", 0)))
    if count == 0:
        result = "충족"
    elif count <= 10:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_sbom() -> CollectedResult:
    """6.4.1.1_1 — SBOM 생성: sbom_component_count >= 1"""
    item_id, maturity = "6.4.1.1_1", "기존"
    mk, thr = "sbom_component_count", 1.0
    data, error = _scan_sbom({"image_name": TRIVY_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("sbom_component_count", data.get("metric_value", 0)))
    result = "충족" if count >= thr else "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_dependency_scan() -> CollectedResult:
    """6.4.1.2_1 — 의존성 취약점 스캔: dependency_vuln_count == 0"""
    item_id, maturity = "6.4.1.2_1", "초기"
    mk, thr = "dependency_vuln_count", 0.0
    data, error = _scan_sbom({"image_name": TRIVY_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("dependency_vuln_count", data.get("metric_value", 0)))
    if count == 0:
        result = "충족"
    elif count <= 5:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_sbom_full() -> CollectedResult:
    """6.4.1.3_1 — SBOM 전체 구성요소 식별: sbom_component_count >= 10"""
    item_id, maturity = "6.4.1.3_1", "향상"
    mk, thr = "sbom_component_count", 10.0
    data, error = _scan_sbom({"image_name": TRIVY_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("sbom_component_count", data.get("metric_value", 0)))
    if count >= thr:
        result = "충족"
    elif count >= 1:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_risk_scan() -> CollectedResult:
    """6.5.1.1_1 — 리스크 기반 스캔: risk_score <= 50"""
    item_id, maturity = "6.5.1.1_1", "향상"
    mk, thr = "risk_score", 50.0
    data, error = _scan_image({"image_name": TRIVY_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    score = float(data.get("risk_score", data.get("metric_value", 100)))
    if score <= thr:
        result = "충족"
    elif score <= 80:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, score, thr, data)


def collect_supply_chain_scan() -> CollectedResult:
    """6.5.1.2_1 — 공급망 보안 스캔: supply_chain_vuln_count == 0"""
    item_id, maturity = "6.5.1.2_1", "최적화"
    mk, thr = "supply_chain_vuln_count", 0.0
    data, error = _scan_sbom({"image_name": TRIVY_TARGET})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("supply_chain_vuln_count", data.get("metric_value", 0)))
    if count == 0:
        result = "충족"
    elif count <= 3:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)
