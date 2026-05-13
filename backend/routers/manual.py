from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, timezone

from database import get_db
from models import DiagnosisSession, Checklist, DiagnosisResult, Evidence, CollectedData

router = APIRouter()

VALID_RESULTS = {"충족", "부분충족", "미충족", "평가불가"}


@router.post("/submit")
def manual_submit(
    session_id: int,
    item_id: str,
    result: str,
    evidence_text: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """수동 진단 항목의 결과를 제출한다."""

    if result not in VALID_RESULTS:
        raise HTTPException(
            status_code=400,
            detail=f"result는 {VALID_RESULTS} 중 하나여야 합니다."
        )

    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")

    checklist = db.query(Checklist).filter(Checklist.item_id == item_id).first()
    if not checklist:
        raise HTTPException(status_code=404, detail=f"체크리스트 항목을 찾을 수 없습니다: {item_id}")

    if checklist.diagnosis_type != "수동":
        raise HTTPException(
            status_code=400,
            detail="자동 진단 항목은 수동 제출이 불가합니다."
        )

    check_id = checklist.check_id
    weight_map = {"충족": 1.0, "부분충족": 0.5, "미충족": 0.0, "평가불가": 0.0}

    existing_cd = db.query(CollectedData).filter(
        CollectedData.session_id == session_id,
        CollectedData.check_id == check_id,
    ).first()
    if existing_cd:
        existing_cd.tool = "수동"
        existing_cd.metric_key = "manual_result"
        existing_cd.metric_value = weight_map.get(result, 0.0)
        existing_cd.threshold = 1.0
        existing_cd.raw_json = {"manual": True, "evidence": evidence_text}
        existing_cd.error = None
        existing_cd.collected_at = datetime.now(timezone.utc)
    else:
        db.add(CollectedData(
            session_id=session_id,
            check_id=check_id,
            tool="수동",
            metric_key="manual_result",
            metric_value=weight_map.get(result, 0.0),
            threshold=1.0,
            raw_json={"manual": True, "evidence": evidence_text},
            error=None,
        ))

    existing = db.query(DiagnosisResult).filter(
        DiagnosisResult.session_id == session_id,
        DiagnosisResult.check_id == check_id,
    ).first()
    if existing:
        existing.result = result
        existing.score = checklist.maturity_score * weight_map.get(result, 0.0)
        existing.recommendation = ""
    else:
        db.add(DiagnosisResult(
            session_id=session_id,
            check_id=check_id,
            result=result,
            score=checklist.maturity_score * weight_map.get(result, 0.0),
            recommendation="",
        ))

    if evidence_text:
        db.add(Evidence(
            session_id=session_id,
            check_id=check_id,
            source="수동입력",
            observed=evidence_text,
            location="",
            reason="",
            impact=None,
        ))

    db.commit()

    return {
        "status": "ok",
        "session_id": session_id,
        "item_id": item_id,
        "result": result,
    }


@router.get("/items/{session_id}")
def get_manual_items(session_id: int, db: Session = Depends(get_db)):
    """세션에서 수동 진단이 필요한 항목 목록을 반환한다."""
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")

    manual_items = db.query(Checklist).filter(
        Checklist.diagnosis_type == "수동"
    ).all()

    submitted = {
        r.check_id
        for r in db.query(DiagnosisResult).filter(
            DiagnosisResult.session_id == session_id
        ).all()
    }

    return {
        "items": [
            {
                "check_id": item.check_id,
                "item_id": item.item_id,
                "pillar": item.pillar,
                "category": item.category,
                "item_name": item.item_name,
                "maturity": item.maturity,
                "criteria": item.criteria or "",
                "submitted": item.check_id in submitted,
            }
            for item in manual_items
        ],
        "total": len(manual_items),
        "submitted_count": len([i for i in manual_items if i.check_id in submitted]),
    }
