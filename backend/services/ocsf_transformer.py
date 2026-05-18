"""OCSF (Open Cybersecurity Schema Framework) 1.x 변환 레이어.

수집된 raw_json + 채점 결과를 OCSF 표준 이벤트 형식으로 변환한다.
- raw 데이터는 손실 없이 `raw_data` 필드에 그대로 보존
- 도구별로 OCSF Category / Class 매핑:
    keycloak → 3 IAM / 3002 Authentication
    wazuh    → 2 Findings / 2004 Detection Finding
    nmap     → 4 Network Activity / 4001 Network Activity
    trivy    → 2 Findings / 2002 Vulnerability Finding

조회 시점 변환 (read-side). 별도 컬럼 추가 없이 기존 raw_json 으로부터 생성한다.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional


OCSF_VERSION = "1.1.0"

# 도구 → (category_uid, category_name, class_uid, class_name, activity_id, activity_name)
_TOOL_CLASS: dict[str, tuple[int, str, int, str, int, str]] = {
    "keycloak": (3, "Identity & Access Management", 3002, "Authentication",       1, "Logon"),
    "wazuh":    (2, "Findings",                     2004, "Detection Finding",    1, "Create"),
    "nmap":     (4, "Network Activity",             4001, "Network Activity",     6, "Traffic"),
    "trivy":    (2, "Findings",                     2002, "Vulnerability Finding", 1, "Create"),
}

# 진단 결과 → OCSF status
_RESULT_STATUS: dict[str, tuple[str, int]] = {
    "충족":     ("Success", 1),
    "부분충족": ("Other",   99),
    "미충족":   ("Failure", 2),
    "평가불가": ("Unknown", 0),
}

# 진단 결과 → OCSF severity (0 Unknown / 1 Informational / 2 Low / 3 Medium / 4 High / 5 Critical / 6 Fatal)
_RESULT_SEVERITY: dict[str, tuple[int, str]] = {
    "충족":     (1, "Informational"),
    "부분충족": (3, "Medium"),
    "미충족":   (4, "High"),
    "평가불가": (0, "Unknown"),
}

_VENDOR: dict[str, str] = {
    "keycloak": "Red Hat",
    "wazuh":    "Wazuh Inc.",
    "nmap":     "Nmap Project",
    "trivy":    "Aqua Security",
}


def _epoch_ms(ts: Optional[datetime]) -> int:
    if ts is None:
        return 0
    try:
        return int(ts.timestamp() * 1000)
    except Exception:
        return 0


def to_ocsf_event(
    *,
    tool: str,
    item_id: str,
    pillar: str,
    item_name: str,
    maturity: Optional[str],
    metric_key: Optional[str],
    metric_value: Optional[float],
    threshold: Optional[float],
    raw_json,
    collected_at: Optional[datetime],
    result: str,
    score: Optional[float],
    error: Optional[str],
) -> dict:
    """단일 수집 결과를 OCSF 이벤트 dict 로 변환."""
    cat_uid, cat_name, cls_uid, cls_name, act_id, act_name = _TOOL_CLASS.get(
        tool, (0, "Unknown", 0, "Base Event", 0, "Unknown"),
    )
    status_name, status_id = _RESULT_STATUS.get(result, ("Unknown", 0))
    sev_id, sev_name = _RESULT_SEVERITY.get(result, (0, "Unknown"))
    type_uid = cls_uid * 100 + act_id

    event: dict = {
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": tool.capitalize(),
                "vendor_name": _VENDOR.get(tool, "Unknown"),
            },
            "profiles": ["security_control"],
        },
        "category_uid": cat_uid,
        "category_name": cat_name,
        "class_uid": cls_uid,
        "class_name": cls_name,
        "type_uid": type_uid,
        "activity_id": act_id,
        "activity_name": act_name,
        "time": _epoch_ms(collected_at),
        "severity_id": sev_id,
        "severity": sev_name,
        "status": status_name,
        "status_id": status_id,
        "observables": [
            {"name": "zt.item_id",    "type_id": 0, "type": "Other", "value": item_id},
            {"name": "zt.pillar",     "type_id": 0, "type": "Other", "value": pillar},
            {"name": "zt.metric_key", "type_id": 0, "type": "Other", "value": metric_key or ""},
        ],
        "raw_data": raw_json,
        "unmapped": {
            "zt_assessment": {
                "item_id": item_id,
                "item_name": item_name,
                "maturity": maturity,
                "result": result,
                "score": score,
                "metric_value": metric_value,
                "threshold": threshold,
                "error": error,
            },
        },
    }

    # Findings 카테고리 클래스(2002/2004) 는 finding_info 필수 필드를 채워 OCSF 적합성 향상
    if cat_uid == 2:
        event["finding_info"] = {
            "title": f"{tool} {item_id}: {result}",
            "uid": f"{tool}-{item_id}",
            "types": [result],
            "desc": item_name,
        }

    # Authentication 클래스(3002) 는 actor 필드 있을 때 강해진다 — 익명 사용자 표기
    if cls_uid == 3002:
        event["actor"] = {
            "user": {"name": "zt-assessment-service", "type": "System"},
        }

    return event


def build_session_ocsf(
    *,
    session_id: int,
    rows: list,
) -> dict:
    """세션 단위 OCSF 응답 envelope 생성.

    rows: [(CollectedData, Checklist, DiagnosisResult|None)] 튜플 리스트
    """
    events = []
    for cd, cl, dr in rows:
        events.append(to_ocsf_event(
            tool=cd.tool,
            item_id=cl.item_id,
            pillar=cl.pillar,
            item_name=cl.item_name,
            maturity=cl.maturity,
            metric_key=cd.metric_key,
            metric_value=cd.metric_value,
            threshold=cd.threshold,
            raw_json=cd.raw_json,
            collected_at=cd.collected_at,
            result=(dr.result if dr else "평가불가"),
            score=(dr.score if dr else None),
            error=cd.error,
        ))

    # 카테고리/클래스/심각도 분포 — UI 요약 카드용
    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for ev in events:
        by_category[ev["category_name"]] = by_category.get(ev["category_name"], 0) + 1
        by_severity[ev["severity"]]      = by_severity.get(ev["severity"], 0) + 1

    return {
        "session_id": session_id,
        "ocsf_version": OCSF_VERSION,
        "event_count": len(events),
        "by_category": by_category,
        "by_severity": by_severity,
        "events": events,
    }
