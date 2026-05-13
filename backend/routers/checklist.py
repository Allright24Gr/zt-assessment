from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Optional

from database import get_db
from models import Checklist

router = APIRouter()


@router.get("/")
def get_checklist(
    pillar: Optional[str] = None,
    maturity: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """체크리스트 항목 목록을 반환한다. pillar, maturity 필터 선택 가능."""
    q = db.query(Checklist)
    if pillar:
        q = q.filter(Checklist.pillar == pillar)
    if maturity:
        q = q.filter(Checklist.maturity == maturity)
    items = q.order_by(Checklist.check_id).all()

    return [
        {
            "check_id": c.check_id,
            "item_id": c.item_id,
            "item_num": c.item_num,
            "pillar": c.pillar,
            "category": c.category,
            "item_name": c.item_name,
            "maturity": c.maturity,
            "maturity_score": c.maturity_score,
            "diagnosis_type": c.diagnosis_type,
            "tool": c.tool,
            "weight": c.weight,
            "evidence": c.evidence,
            "criteria": c.criteria,
            "fields": c.fields,
            "logic": c.logic,
            "exceptions": c.exceptions,
        }
        for c in items
    ]
