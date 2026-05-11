from typing import List, Dict
from datetime import datetime, timezone


CollectedResult = dict
ScoringOutput = dict


def score_single_item(collected: CollectedResult) -> dict:
    if collected.get("error"):
        return {"result": "평가불가", "score": 0.0, "recommendation": "수집 오류로 인해 평가할 수 없습니다."}

    metric_value = collected.get("metric_value")
    threshold = collected.get("threshold")
    maturity_score = collected.get("maturity_score", 1)

    if metric_value is None or threshold is None or threshold == 0:
        return {"result": "평가불가", "score": 0.0, "recommendation": "임계값 또는 측정값 누락"}

    if metric_value >= threshold:
        result = "충족"
        weight = 1.0
    elif metric_value >= threshold * 0.7:
        result = "부분충족"
        weight = 0.5
    else:
        result = "미충족"
        weight = 0.0

    score = maturity_score * weight
    return {"result": result, "score": score, "recommendation": ""}


def determine_maturity_level(total_score: float) -> str:
    if total_score >= 3.5:
        return "최적화"
    elif total_score >= 2.5:
        return "향상"
    elif total_score >= 1.5:
        return "초기"
    else:
        return "기존"


def score_session(
    session_id: int,
    collected_results: List[CollectedResult],
    checklist_meta: List[dict],
) -> ScoringOutput:
    meta_by_check_id: Dict[int, dict] = {}
    meta_by_item_id: Dict[str, dict] = {}
    for m in checklist_meta:
        if m.get("check_id"):
            meta_by_check_id[m["check_id"]] = m
        if m.get("item_id"):
            meta_by_item_id[m["item_id"]] = m

    checklist_results = []
    pillar_score_lists: Dict[str, List[float]] = {}

    for collected in collected_results:
        check_id = collected.get("check_id")
        item_id = collected.get("item_id")
        meta = (
            meta_by_check_id.get(check_id)
            or meta_by_item_id.get(str(item_id) if item_id else "")
            or {}
        )

        merged = {**collected, "maturity_score": meta.get("maturity_score", 1)}
        item_result = score_single_item(merged)

        pillar = meta.get("pillar", "미분류")
        pillar_score_lists.setdefault(pillar, []).append(item_result["score"])

        checklist_results.append({
            "item_id": item_id or meta.get("item_id"),
            "check_id": check_id or meta.get("check_id"),
            "pillar": pillar,
            "result": item_result["result"],
            "score": item_result["score"],
            "recommendation": item_result.get("recommendation", ""),
        })

    pillar_scores: Dict[str, float] = {
        pillar: sum(scores) / len(scores)
        for pillar, scores in pillar_score_lists.items()
        if scores
    }

    all_values = list(pillar_scores.values())
    total_score = sum(all_values) / len(all_values) if all_values else 0.0

    return {
        "session_id": session_id,
        "pillar_scores": pillar_scores,
        "total_score": round(total_score, 4),
        "maturity_level": determine_maturity_level(total_score),
        "checklist_results": checklist_results,
        "assessed_at": datetime.now(timezone.utc).isoformat(),
    }


def generate_recommendations(
    checklist_results: List[dict],
    improvement_guides: List[dict],
) -> List[dict]:
    PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    TERM_ORDER = {"단기": 0, "중기": 1, "장기": 2}

    failed_check_ids = {
        r["check_id"]
        for r in checklist_results
        if r.get("result") in ("미충족", "부분충족")
    }

    matched = [g for g in improvement_guides if g.get("check_id") in failed_check_ids]
    matched.sort(key=lambda g: (
        PRIORITY_ORDER.get(g.get("priority", "Low"), 3),
        TERM_ORDER.get(g.get("term", "장기"), 2),
    ))
    return matched
