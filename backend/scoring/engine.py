from typing import List, Dict, Optional
from datetime import datetime


CollectedResult = dict
ScoringOutput = dict
# {
#   "session_id": int,
#   "pillar_scores": Dict[str, float],   # pillar → 평균 성숙도 점수
#   "total_score": float,
#   "maturity_level": str,               # 기존 / 초기 / 향상 / 최적화
#   "checklist_results": List[dict],     # 항목별 result + score
#   "assessed_at": str
# }

MATURITY_LEVELS = {
    (0.0, 1.5): "기존",
    (1.5, 2.5): "초기",
    (2.5, 3.5): "향상",
    (3.5, 4.0): "최적화",
}


def score_single_item(collected: CollectedResult) -> dict:
    """
    수집 결과 단건을 받아 result(충족/부분충족/미충족/평가불가)와 score를 반환한다.

    Args:
        collected: CollectedResult 형식 dict

    Returns:
        {"result": str, "score": float, "recommendation": str}
    """
    # TODO: collected["error"] 있으면 result="평가불가", score=0.0 반환
    # TODO: metric_value vs threshold 비교
    # TODO: 비율에 따라 충족(1.0) / 부분충족(0.5) / 미충족(0.0) 판정
    # TODO: maturity_score × 판정 가중치로 score 산출
    raise NotImplementedError


def score_session(
    session_id: int,
    collected_results: List[CollectedResult],
    checklist_meta: List[dict],
) -> ScoringOutput:
    """
    세션 전체 수집 결과를 받아 필라별·전체 성숙도 점수를 계산한다.

    Args:
        session_id: 진단 세션 ID
        collected_results: 해당 세션의 CollectedResult 목록
        checklist_meta: Checklist 메타 목록 (pillar, maturity_score 포함)

    Returns:
        ScoringOutput 형식 dict
    """
    # TODO: item_id로 collected_results와 checklist_meta 매핑
    # TODO: 항목별 score_single_item 호출
    # TODO: pillar별 평균 점수 계산
    # TODO: 전체 평균 계산 → maturity_level 결정
    # TODO: ScoringOutput 조립 후 반환
    raise NotImplementedError


def determine_maturity_level(total_score: float) -> str:
    """
    전체 평균 점수(0.0~4.0)를 성숙도 레벨 문자열로 변환한다.

    Args:
        total_score: 0.0 ~ 4.0 범위의 점수

    Returns:
        "기존" | "초기" | "향상" | "최적화"
    """
    # TODO: MATURITY_LEVELS 범위 테이블로 레벨 결정
    raise NotImplementedError


def generate_recommendations(
    checklist_results: List[dict],
    improvement_guides: List[dict],
) -> List[dict]:
    """
    미충족·부분충족 항목에 대응하는 개선 가이드를 우선순위 순으로 정렬하여 반환한다.

    Args:
        checklist_results: score_session 반환값의 checklist_results
        improvement_guides: ImprovementGuide 목록

    Returns:
        우선순위 정렬된 개선 가이드 목록
    """
    # TODO: result in ("미충족", "부분충족") 필터링
    # TODO: check_id로 improvement_guides 매핑
    # TODO: priority(Critical>High>Medium>Low), term(단기>중기>장기) 정렬
    raise NotImplementedError
