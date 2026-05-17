"""
ImprovementGuide → 위험-노력 매트릭스 자동 분류.

위험도 (X축): priority 기반 — Critical=4, High=3, Medium=2, Low=1
노력도 (Y축): term + difficulty 결합 — 단기/하=1 ~ 장기/상=5

분류 4종:
- Quick Win:    위험 >= 3 AND 노력 <= 2 — 즉시 실행
- Major Project: 위험 >= 3 AND 노력 >= 3 — 분기/연간 계획
- Fill-in:      위험 <= 2 AND 노력 <= 2 — 여유 시 실행
- Thankless:    위험 <= 2 AND 노력 >= 3 — 보류 또는 재검토
"""

RISK_FROM_PRIORITY = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
TERM_TO_EFFORT = {"단기": 1, "중기": 2, "장기": 3}
DIFFICULTY_TO_EFFORT = {"하": 0, "중": 1, "상": 2}


def compute_risk_effort(guide: dict) -> dict:
    """guide(dict) → risk, effort, quadrant, rank.

    rank: 매트릭스 내 우선순위 (Quick Win 1순위, Major Project 2순위, Fill-in 3, Thankless 4)
    sort_key: (rank, -risk, effort) — 사분면 → 위험 desc → 노력 asc 정렬
    """
    risk = RISK_FROM_PRIORITY.get(guide.get("priority", "Medium"), 2)
    term = TERM_TO_EFFORT.get(guide.get("term", "중기"), 2)
    diff = DIFFICULTY_TO_EFFORT.get(guide.get("difficulty", "중"), 1)
    effort = term + diff  # 1~5

    if risk >= 3 and effort <= 2:
        quadrant, rank = "Quick Win", 1
    elif risk >= 3 and effort >= 3:
        quadrant, rank = "Major Project", 2
    elif risk <= 2 and effort <= 2:
        quadrant, rank = "Fill-in", 3
    else:
        quadrant, rank = "Thankless", 4

    return {
        **guide,
        "risk_score": risk,
        "effort_score": effort,
        "quadrant": quadrant,
        "quadrant_rank": rank,
        "sort_key": (rank, -risk, effort),
    }


def sort_guides_by_matrix(guides: list[dict]) -> list[dict]:
    """위험-노력 매트릭스 정렬 + 사분면 메타데이터 부착."""
    enriched = [compute_risk_effort(g) for g in guides]
    enriched.sort(key=lambda g: g["sort_key"])
    return enriched


def matrix_summary(guides: list[dict]) -> dict:
    """사분면별 카운트 + Quick Win 상위 3개 추출."""
    from collections import defaultdict
    quad_count: dict[str, int] = defaultdict(int)
    enriched = [compute_risk_effort(g) for g in guides]
    for g in enriched:
        quad_count[g["quadrant"]] += 1
    quick_wins = sorted(
        [g for g in enriched if g["quadrant"] == "Quick Win"],
        key=lambda g: (-g["risk_score"], g["effort_score"]),
    )[:3]
    return {
        "quadrant_counts": dict(quad_count),
        "top_quick_wins": [
            {
                "guide_id": g.get("guide_id"),
                "task": g.get("task"),
                "risk_score": g["risk_score"],
                "effort_score": g["effort_score"],
            }
            for g in quick_wins
        ],
    }
