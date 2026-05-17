"""
admin/checklist — Checklist 테이블 관리 (admin 전용).

GET    /api/admin/checklist            : 전체 목록 (페이징 + pillar/diagnosis_type 필터)
POST   /api/admin/checklist            : 신규 항목 생성
PUT    /api/admin/checklist/{check_id} : 수정 (item_name, criteria, maturity_score, threshold 등)
DELETE /api/admin/checklist/{check_id} : 삭제 (참조하는 CollectedData/Result 있으면 거부)
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import Checklist, CollectedData, DiagnosisResult, User
from routers.auth import get_current_user

router = APIRouter()


def _require_admin(user: User) -> None:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin 권한이 필요합니다.")


class ChecklistCreate(BaseModel):
    item_id: str = Field(min_length=5, max_length=30)
    pillar: str = Field(min_length=1, max_length=100)
    category: str = Field(min_length=1, max_length=100)
    item_name: str = Field(min_length=1, max_length=200)
    maturity: str = Field(min_length=1, max_length=20)
    maturity_score: int = Field(ge=1, le=4)
    diagnosis_type: str = Field(min_length=1, max_length=20)
    tool: str = Field(min_length=1, max_length=100)
    evidence: Optional[str] = None
    criteria: Optional[str] = None
    fields: Optional[str] = None
    logic: Optional[str] = None
    exceptions: Optional[str] = None
    weight: float = Field(default=0.1, ge=0.0, le=10.0)


class ChecklistUpdate(BaseModel):
    pillar: Optional[str] = None
    category: Optional[str] = None
    item_name: Optional[str] = None
    maturity: Optional[str] = None
    maturity_score: Optional[int] = Field(default=None, ge=1, le=4)
    diagnosis_type: Optional[str] = None
    tool: Optional[str] = None
    evidence: Optional[str] = None
    criteria: Optional[str] = None
    fields: Optional[str] = None
    logic: Optional[str] = None
    exceptions: Optional[str] = None
    weight: Optional[float] = Field(default=None, ge=0.0, le=10.0)


@router.get("/checklist")
def list_checklist(
    pillar: Optional[str] = None,
    diagnosis_type: Optional[str] = None,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    q = db.query(Checklist)
    if pillar:
        q = q.filter(Checklist.pillar == pillar)
    if diagnosis_type:
        q = q.filter(Checklist.diagnosis_type == diagnosis_type)
    total = q.count()
    rows = q.order_by(Checklist.item_id).offset(offset).limit(limit).all()
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "check_id": r.check_id,
                "item_id": r.item_id,
                "pillar": r.pillar,
                "category": r.category,
                "item_name": r.item_name,
                "maturity": r.maturity,
                "maturity_score": r.maturity_score,
                "diagnosis_type": r.diagnosis_type,
                "tool": r.tool,
                "weight": r.weight,
                "evidence": r.evidence,
                "criteria": r.criteria,
                "fields": r.fields,
                "logic": r.logic,
                "exceptions": r.exceptions,
            }
            for r in rows
        ],
    }


@router.post("/checklist")
def create_checklist(
    req: ChecklistCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    if db.query(Checklist).filter(Checklist.item_id == req.item_id).first():
        raise HTTPException(status_code=409, detail="이미 존재하는 item_id 입니다.")
    row = Checklist(**req.model_dump())
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"status": "ok", "check_id": row.check_id, "item_id": row.item_id}


@router.put("/checklist/{check_id}")
def update_checklist(
    check_id: int,
    req: ChecklistUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    row = db.query(Checklist).filter(Checklist.check_id == check_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="체크리스트 항목을 찾을 수 없습니다.")
    patch = req.model_dump(exclude_none=True)
    for k, v in patch.items():
        setattr(row, k, v)
    db.commit()
    return {"status": "ok", "check_id": check_id, "updated_fields": list(patch.keys())}


@router.delete("/checklist/{check_id}")
def delete_checklist(
    check_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    row = db.query(Checklist).filter(Checklist.check_id == check_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="체크리스트 항목을 찾을 수 없습니다.")
    # 참조 무결성 가드 — CollectedData / DiagnosisResult 가 있으면 차단.
    cd_cnt = db.query(CollectedData).filter(CollectedData.check_id == check_id).count()
    dr_cnt = db.query(DiagnosisResult).filter(DiagnosisResult.check_id == check_id).count()
    if cd_cnt or dr_cnt:
        raise HTTPException(
            status_code=409,
            detail=f"이 항목을 참조하는 데이터가 있어 삭제 불가 (collected={cd_cnt}, results={dr_cnt})",
        )
    db.delete(row)
    db.commit()
    return {"status": "ok", "check_id": check_id}
