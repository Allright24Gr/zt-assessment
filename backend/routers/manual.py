from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import Optional
from database import get_db

router = APIRouter()


@router.post("/submit")
def manual_submit(
    session_id: int,
    check_id: int,
    result: str,
    evidence_summary: Optional[dict] = None,
    db: Session = Depends(get_db),
):
    """수동 진단 항목의 결과를 제출한다."""
    # TODO: result 값 검증 (충족/부분충족/미충족/평가불가)
    # TODO: DiagnosisResult 저장
    # TODO: Evidence 저장 (evidence_summary 있을 경우)
    raise NotImplementedError
