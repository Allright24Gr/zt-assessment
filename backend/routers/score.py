from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Optional
from database import get_db

router = APIRouter()


@router.get("/summary")
def get_score_summary(session_id: Optional[int] = None, db: Session = Depends(get_db)):
    """세션별 필라(Pillar)별 성숙도 점수 요약을 반환한다."""
    # TODO: MaturityScore 조회
    # TODO: 전체 평균, 필라별 점수, 성숙도 레벨 계산
    # TODO: ScoreSummary 형식으로 반환
    raise NotImplementedError


@router.get("/trend")
def get_score_trend(org_id: int, limit: int = 12, db: Session = Depends(get_db)):
    """조직의 시간순 점수 추이(ScoreHistory)를 반환한다."""
    # TODO: ScoreHistory 조회 (org_id, assessed_at 정렬)
    # TODO: limit 건수 제한
    # TODO: 시계열 배열 형식으로 반환
    raise NotImplementedError


@router.get("/checklist/{session_id}")
def get_checklist_scores(session_id: int, db: Session = Depends(get_db)):
    """세션의 체크리스트 항목별 상세 점수를 반환한다."""
    # TODO: DiagnosisResult + Checklist 조인 조회
    # TODO: ChecklistDetail 형식으로 직렬화
    raise NotImplementedError
