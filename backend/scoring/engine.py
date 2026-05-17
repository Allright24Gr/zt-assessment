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

    if metric_value is None or threshold is None:
        return {"result": "평가불가", "score": 0.0, "recommendation": "임계값 또는 측정값 누락"}

    if threshold == 0:
        # "낮을수록 좋음" 역방향 판정 (미패치 취약점 수, 평문 알림 수 등)
        if metric_value == 0:
            result, weight = "충족", 1.0
        elif metric_value <= 5:
            result, weight = "부분충족", 0.5
        else:
            result, weight = "미충족", 0.0
    elif metric_value >= threshold:
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
    """B-2 개선 (2026-05-17):

    - 평가불가 항목은 pillar 점수 산정에서 **제외** (이전: 0점으로 들어가 평균 깎음)
    - pillar 점수 = Σ(maturity_score × weight) / Σ(maturity_score) × 4
      → 가이드라인 4단계(기존1/초기2/향상3/최적화4) 의도가 반영된 가중 평균 (0~4 정규화)
    - total = 평가 가능한 pillar 점수의 평균 (평가불가만 있는 pillar 는 제외)
    - 결과 dict 에 evaluable / unevaluable 카운트도 함께 노출 → 신뢰도 표시용 (B-3 기반)
    """
    meta_by_check_id: Dict[int, dict] = {}
    meta_by_item_id: Dict[str, dict] = {}
    for m in checklist_meta:
        if m.get("check_id"):
            meta_by_check_id[m["check_id"]] = m
        if m.get("item_id"):
            meta_by_item_id[m["item_id"]] = m

    checklist_results = []
    # pillar → {"score_sum": Σ(maturity_score × weight), "weight_sum": Σ(maturity_score), "unevaluable": cnt}
    pillar_agg: Dict[str, dict] = {}

    for collected in collected_results:
        check_id = collected.get("check_id")
        item_id = collected.get("item_id")
        meta = (
            meta_by_check_id.get(check_id)
            or meta_by_item_id.get(str(item_id) if item_id else "")
            or {}
        )

        maturity_score = meta.get("maturity_score", 1) or 1
        merged = {**collected, "maturity_score": maturity_score}
        item_result = score_single_item(merged)

        pillar = meta.get("pillar", "미분류")
        agg = pillar_agg.setdefault(pillar, {"score_sum": 0.0, "weight_sum": 0.0, "unevaluable": 0})

        if item_result["result"] == "평가불가":
            agg["unevaluable"] += 1  # 분모에 포함 X — 평균에서 빠짐
        else:
            agg["score_sum"] += item_result["score"]
            agg["weight_sum"] += maturity_score

        checklist_results.append({
            "item_id": item_id or meta.get("item_id"),
            "check_id": check_id or meta.get("check_id"),
            "pillar": pillar,
            "result": item_result["result"],
            "score": item_result["score"],
            "recommendation": item_result.get("recommendation", ""),
        })

    # pillar 점수 0~4 정규화 (가이드라인 4단계 일치)
    pillar_scores: Dict[str, float] = {}
    pillar_unevaluable: Dict[str, int] = {}
    for pillar, agg in pillar_agg.items():
        pillar_unevaluable[pillar] = agg["unevaluable"]
        if agg["weight_sum"] > 0:
            pillar_scores[pillar] = round(agg["score_sum"] / agg["weight_sum"] * 4.0, 4)
        # weight_sum == 0 → 그 pillar 는 전부 평가불가. pillar_scores 에 등록 안 함 (총점 계산서 제외).

    # 총점 = 평가 가능한 pillar 들의 평균. 모든 pillar 가 평가불가면 0.0
    evaluable_scores = list(pillar_scores.values())
    total_score = sum(evaluable_scores) / len(evaluable_scores) if evaluable_scores else 0.0

    # 신뢰도: 전체 결과 중 평가 가능한 항목 비율
    total_items = len(collected_results)
    evaluable_items = sum(1 for r in checklist_results if r["result"] != "평가불가")
    confidence = (evaluable_items / total_items) if total_items > 0 else 0.0

    return {
        "session_id": session_id,
        "pillar_scores": pillar_scores,
        "pillar_unevaluable": pillar_unevaluable,
        "total_score": round(total_score, 4),
        "maturity_level": determine_maturity_level(total_score),
        "evaluable_items": evaluable_items,
        "unevaluable_items": total_items - evaluable_items,
        "confidence": round(confidence, 4),  # 0~1 — UI 에 % 로 표시
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
