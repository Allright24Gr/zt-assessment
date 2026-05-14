from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List
from datetime import datetime, timezone

from database import get_db
from models import DiagnosisSession, Checklist, DiagnosisResult, Evidence, CollectedData

router = APIRouter()

VALID_RESULTS = {"충족", "부분충족", "미충족", "평가불가"}


class ManualAnswer(BaseModel):
    check_id: str
    value: str
    evidence: str = ""


class ManualSubmitRequest(BaseModel):
    session_id: int
    answers: List[ManualAnswer]


@router.post("/submit")
def manual_submit(req: ManualSubmitRequest, db: Session = Depends(get_db)):
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == req.session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")

    weight_map = {"충족": 1.0, "부분충족": 0.5, "미충족": 0.0, "평가불가": 0.0}
    saved = 0

    for ans in req.answers:
        result = ans.value if ans.value in VALID_RESULTS else "평가불가"
        evidence_text = ans.evidence or None

        checklist = db.query(Checklist).filter(Checklist.item_id == ans.check_id).first()
        if not checklist or checklist.diagnosis_type != "수동":
            continue

        check_id = checklist.check_id

        existing_cd = db.query(CollectedData).filter(
            CollectedData.session_id == req.session_id,
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
                session_id=req.session_id,
                check_id=check_id,
                tool="수동",
                metric_key="manual_result",
                metric_value=weight_map.get(result, 0.0),
                threshold=1.0,
                raw_json={"manual": True, "evidence": evidence_text},
                error=None,
            ))

        existing = db.query(DiagnosisResult).filter(
            DiagnosisResult.session_id == req.session_id,
            DiagnosisResult.check_id == check_id,
        ).first()
        if existing:
            existing.result = result
            existing.score = checklist.maturity_score * weight_map.get(result, 0.0)
            existing.recommendation = ""
        else:
            db.add(DiagnosisResult(
                session_id=req.session_id,
                check_id=check_id,
                result=result,
                score=checklist.maturity_score * weight_map.get(result, 0.0),
                recommendation="",
            ))

        if evidence_text:
            db.add(Evidence(
                session_id=req.session_id,
                check_id=check_id,
                source="수동입력",
                observed=evidence_text,
                location="",
                reason="",
                impact=None,
            ))

        saved += 1

    db.commit()

    return {
        "status": "ok",
        "session_id": req.session_id,
        "submitted_count": saved,
    }


@router.get("/items/{session_id}")
def get_manual_items(
    session_id: int,
    excluded_tools: str = "",
    db: Session = Depends(get_db),
):
    """수동 진단 항목 + 미사용 도구 항목을 반환한다.
    excluded_tools: 쉼표 구분 도구명 (예: 'nmap,trivy') — 해당 도구 자동 항목도 수동으로 포함.
    """
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")

    excluded_list = [t.strip().lower() for t in excluded_tools.split(",") if t.strip()]

    if excluded_list:
        manual_items = db.query(Checklist).filter(
            or_(
                Checklist.diagnosis_type == "수동",
                Checklist.tool.in_(excluded_list),
            )
        ).all()
    else:
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
