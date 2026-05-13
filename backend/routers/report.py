from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from database import get_db
from models import (
    DiagnosisSession, DiagnosisResult, MaturityScore,
    Checklist, Organization, User,
)
from scoring.engine import determine_maturity_level

router = APIRouter()


@router.get("/generate/{session_id}")
def generate_report(
    session_id: int,
    fmt: str = "json",
    db: Session = Depends(get_db),
):
    """진단 세션 결과를 리포트로 생성한다. fmt=json(기본값)만 지원."""

    if fmt not in ("json",):
        raise HTTPException(status_code=400, detail="현재 fmt=json만 지원합니다.")

    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")

    org = db.query(Organization).filter(Organization.org_id == session.org_id).first()
    user = db.query(User).filter(User.user_id == session.user_id).first()

    maturity_rows = db.query(MaturityScore).filter(
        MaturityScore.session_id == session_id
    ).all()
    pillar_scores = [
        {
            "pillar": m.pillar,
            "score": round(m.score, 4),
            "level": determine_maturity_level(m.score),
            "pass_cnt": m.pass_cnt,
            "fail_cnt": m.fail_cnt,
            "na_cnt": m.na_cnt,
        }
        for m in maturity_rows
    ]

    results = (
        db.query(DiagnosisResult, Checklist)
        .join(Checklist, DiagnosisResult.check_id == Checklist.check_id)
        .filter(DiagnosisResult.session_id == session_id)
        .all()
    )

    checklist_results = []
    fail_items = []
    for dr, cl in results:
        item = {
            "item_id": cl.item_id,
            "pillar": cl.pillar,
            "category": cl.category,
            "item_name": cl.item_name,
            "maturity": cl.maturity,
            "maturity_score": cl.maturity_score,
            "diagnosis_type": cl.diagnosis_type,
            "tool": cl.tool,
            "result": dr.result,
            "score": dr.score or 0.0,
            "criteria": cl.criteria or "",
            "recommendation": dr.recommendation or "",
        }
        checklist_results.append(item)
        if dr.result in ("미충족", "부분충족"):
            fail_items.append(item)

    total = len(checklist_results)
    pass_cnt = sum(1 for r in checklist_results if r["result"] == "충족")
    partial_cnt = sum(1 for r in checklist_results if r["result"] == "부분충족")
    fail_cnt = sum(1 for r in checklist_results if r["result"] == "미충족")
    na_cnt = sum(1 for r in checklist_results if r["result"] == "평가불가")

    overall_score = session.total_score or 0.0
    overall_level = session.level or determine_maturity_level(overall_score)

    report = {
        "report_generated_at": datetime.now(timezone.utc).isoformat(),
        "session": {
            "session_id": session.session_id,
            "org": org.name if org else "",
            "manager": user.name if user else "",
            "started_at": session.started_at.isoformat() if session.started_at else "",
            "completed_at": session.completed_at.isoformat() if session.completed_at else "",
            "status": session.status,
        },
        "summary": {
            "overall_score": round(overall_score, 4),
            "overall_level": overall_level,
            "total_items": total,
            "pass_cnt": pass_cnt,
            "partial_cnt": partial_cnt,
            "fail_cnt": fail_cnt,
            "na_cnt": na_cnt,
            "pass_rate": round(pass_cnt / total, 4) if total > 0 else 0.0,
        },
        "pillar_scores": pillar_scores,
        "checklist_results": checklist_results,
        "improvement_targets": fail_items,
    }

    return JSONResponse(content=report)
