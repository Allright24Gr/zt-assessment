from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Optional
from database import get_db

router = APIRouter()


@router.get("/")
def get_checklist(
    pillar: Optional[str] = None,
    maturity: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """체크리스트 항목 목록을 반환한다. pillar, maturity 필터 선택 가능."""
    # TODO: Checklist 조회 (pillar, maturity 필터 선택)
    # TODO: ChecklistItem 형식으로 직렬화하여 반환
    raise NotImplementedError
