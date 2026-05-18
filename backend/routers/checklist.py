from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional

from database import get_db
from models import Checklist, User
from routers.auth import get_current_user

router = APIRouter()


@router.get("/")
def get_checklist(
    pillar: Optional[str] = None,
    maturity: Optional[str] = None,
    limit: int = Query(500, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """체크리스트 항목 목록을 반환한다. pillar, maturity 필터 + limit/offset 페이지네이션."""
    q = db.query(Checklist)
    if pillar:
        q = q.filter(Checklist.pillar == pillar)
    if maturity:
        q = q.filter(Checklist.maturity == maturity)
    total = q.count()
    items = q.order_by(Checklist.check_id).offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
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
        ],
    }
