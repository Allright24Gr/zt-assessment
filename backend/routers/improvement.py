from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Optional
from database import get_db

router = APIRouter()


@router.get("/")
def get_improvements(
    pillar: Optional[str] = None,
    term: Optional[str] = None,
    priority: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """개선 가이드 목록을 필터 조건에 따라 반환한다."""
    # TODO: ImprovementGuide 조회 (pillar, term, priority 필터 선택)
    # TODO: Improvement 형식으로 직렬화
    raise NotImplementedError


@router.get("/{guide_id}")
def get_improvement_detail(guide_id: int, db: Session = Depends(get_db)):
    """특정 개선 가이드의 상세 정보(단계별 조치, 예상 효과 등)를 반환한다."""
    # TODO: ImprovementGuide 단건 조회
    # TODO: 연결된 Checklist 정보 포함
    raise NotImplementedError


@router.get("/session/{session_id}")
def get_session_improvements(session_id: int, db: Session = Depends(get_db)):
    """세션의 미충족·부분충족 항목에 연결된 개선 가이드를 반환한다."""
    # TODO: DiagnosisResult (result != 충족) 조회
    # TODO: check_id로 ImprovementGuide 매핑
    # TODO: 우선순위·기간 정렬 후 반환
    raise NotImplementedError
