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

# 세션 단위로 사용자가 입력한 외부 스캔 대상. _run_collectors가 호출 직전 주입.
# 동시 세션 충돌 방지를 위해 _run_collectors 측에서 락으로 직렬화한다.
_current_target: str | None = None


def set_session_target(target: str | None) -> None:
    """세션별 trivy 스캔 대상을 주입(또는 None으로 해제)."""
    global _current_target
    _current_target = (target or None)


def _get_target() -> str:
    return _current_target or TRIVY_TARGET


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
    """5.4.1.2_2 — 이미지 취약점 스캔: critical_vuln_count == 0"""
    item_id, maturity = "5.4.1.2_2", "초기"
    mk, thr = "critical_vuln_count", 0.0
    data, error = _scan_image({"image_name": _get_target()})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("critical_vuln_count", data.get("metric_value", 0)))
    if count == 0:
        result = "충족"
    elif count <= 5:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_cicd_scan_ratio() -> CollectedResult:
    """5.4.1.2_3 — CI/CD 파이프라인 스캔 비율: scan_ratio >= 0.9"""
    item_id, maturity = "5.4.1.2_3", "초기"
    mk, thr = "scan_ratio", 0.9
    data, error = _scan_image({"image_name": _get_target()})
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
    """5.4.1.2_4 — 무결성 검증 및 격리: integrity_check_passed >= 1"""
    item_id, maturity = "5.4.1.2_4", "초기"
    mk, thr = "integrity_check_passed", 1.0
    data, error = _scan_fs({"path": _get_target()})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    passed = float(data.get("integrity_check_passed", data.get("metric_value", 0)))
    if passed >= thr:
        result = "충족"
    elif passed > 0:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, passed, thr, data)


def collect_policy_compliance_scan() -> CollectedResult:
    """5.4.1.3_2 — 정책 컴플라이언스 스캔: policy_violation_count == 0"""
    item_id, maturity = "5.4.1.3_2", "향상"
    mk, thr = "policy_violation_count", 0.0
    data, error = _scan_image({"image_name": _get_target()})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("policy_violation_count", data.get("metric_value", 0)))
    if count == 0:
        result = "충족"
    elif count <= 5:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_full_component_scan() -> CollectedResult:
    """5.4.1.3_4 — 전체 컴포넌트 스캔 비율: component_scan_ratio >= 0.9"""
    item_id, maturity = "5.4.1.3_4", "향상"
    mk, thr = "component_scan_ratio", 0.9
    data, error = _scan_fs({"path": _get_target()})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    ratio = float(data.get("component_scan_ratio", data.get("metric_value", 0)))
    if ratio >= thr:
        result = "충족"
    elif ratio >= 0.5:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, ratio, thr, data)


def collect_fs_scan() -> CollectedResult:
    """5.5.1.2_1 — 파일시스템 스캔 수행: scan_performed >= 1"""
    item_id, maturity = "5.5.1.2_1", "초기"
    mk, thr = "scan_performed", 1.0
    data, error = _scan_fs({"path": _get_target()})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    performed = 1.0 if data else 0.0
    result = "충족" if performed >= thr else "미충족"
    return _ok(item_id, maturity, result, mk, performed, thr, data)


def collect_sbom() -> CollectedResult:
    """5.5.1.2_3 — SBOM 생성: sbom_component_count >= 1"""
    item_id, maturity = "5.5.1.2_3", "초기"
    mk, thr = "sbom_component_count", 1.0
    data, error = _scan_sbom({"image_name": _get_target()})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("sbom_component_count", data.get("metric_value", 0)))
    result = "충족" if count >= thr else "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_dependency_scan() -> CollectedResult:
    """5.5.1.3_1 — 의존성 Critical 취약점: critical_dep_count == 0"""
    item_id, maturity = "5.5.1.3_1", "향상"
    mk, thr = "critical_dep_count", 0.0
    data, error = _scan_fs({"path": _get_target()})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("critical_dep_count", data.get("metric_value", 0)))
    if count == 0:
        result = "충족"
    elif count <= 5:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_sbom_full() -> CollectedResult:
    """5.5.1.3_2 — SBOM 전체 구성요소 식별: sbom_component_count >= 1"""
    item_id, maturity = "5.5.1.3_2", "향상"
    mk, thr = "sbom_component_count", 1.0
    data, error = _scan_sbom({"image_name": _get_target()})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("sbom_component_count", data.get("metric_value", 0)))
    if count >= thr:
        result = "충족"
    elif count > 0:
        result = "부분충족"
    else:
        result = "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)


def collect_risk_scan() -> CollectedResult:
    """5.5.2.2_1 — 소프트웨어 위험 평가 스캔 수행: scan_performed >= 1"""
    item_id, maturity = "5.5.2.2_1", "초기"
    mk, thr = "scan_performed", 1.0
    data, error = _scan_image({"image_name": _get_target()})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    performed = 1.0 if data else 0.0
    result = "충족" if performed >= thr else "미충족"
    return _ok(item_id, maturity, result, mk, performed, thr, data)


def collect_supply_chain_scan() -> CollectedResult:
    """5.5.2.3_1 — SBOM 기반 공급망 스캔: sbom_scan_count >= 1"""
    item_id, maturity = "5.5.2.3_1", "향상"
    mk, thr = "sbom_scan_count", 1.0
    data, error = _scan_sbom({"image_name": _get_target()})
    if error:
        return _err(item_id, maturity, mk, thr, error, data)
    count = float(data.get("sbom_scan_count", data.get("metric_value", 0)))
    result = "충족" if count >= thr else "미충족"
    return _ok(item_id, maturity, result, mk, count, thr, data)
