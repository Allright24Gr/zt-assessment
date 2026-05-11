from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional

from database import get_db
from models import MaturityScore, ScoreHistory, DiagnosisResult, Checklist, DiagnosisSession
from scoring.engine import determine_maturity_level

router = APIRouter()


@router.get("/summary")
def get_score_summary(session_id: int, db: Session = Depends(get_db)):
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")

    maturity_rows = db.query(MaturityScore).filter(
        MaturityScore.session_id == session_id
    ).all()

    results = (
        db.query(DiagnosisResult, Checklist)
        .join(Checklist, DiagnosisResult.check_id == Checklist.check_id)
        .filter(DiagnosisResult.session_id == session_id)
        .all()
    )

    pillar_counts: dict = {}
    for dr, cl in results:
        pillar = cl.pillar
        if pillar not in pillar_counts:
            pillar_counts[pillar] = {"pass": 0, "fail": 0, "na": 0}
        if dr.result == "충족":
            pillar_counts[pillar]["pass"] += 1
        elif dr.result in ("미충족", "부분충족"):
            pillar_counts[pillar]["fail"] += 1
        else:
            pillar_counts[pillar]["na"] += 1

    pillar_scores = []
    for m in maturity_rows:
        counts = pillar_counts.get(m.pillar, {"pass": 0, "fail": 0, "na": 0})
        pillar_scores.append({
            "pillar": m.pillar,
            "score": round(m.score, 4),
            "level": determine_maturity_level(m.score),
            "pass_cnt": counts["pass"],
            "fail_cnt": counts["fail"],
            "na_cnt": counts["na"],
        })

    overall = session.total_score or 0.0
    overall_level = session.level or determine_maturity_level(overall)

    weakest = min(pillar_scores, key=lambda p: p["score"]) if pillar_scores else None

    return {
        "overall_score": overall,
        "overall_level": overall_level,
        "pillar_scores": pillar_scores,
        "weakest_pillar": weakest,
    }


@router.get("/trend")
def get_score_trend(
    org_id: int,
    limit: int = 12,
    db: Session = Depends(get_db),
):
    rows = (
        db.query(ScoreHistory)
        .filter(ScoreHistory.org_id == org_id)
        .order_by(ScoreHistory.assessed_at.asc())
        .limit(limit)
        .all()
    )

    trend = [
        {
            "date": r.assessed_at.isoformat() if r.assessed_at else "",
            "score": r.total_score,
            "level": r.maturity_level,
            "session_id": r.session_id,
        }
        for r in rows
    ]
    return {"trend": trend}


@router.get("/checklist/{session_id}")
def get_checklist_scores(session_id: int, db: Session = Depends(get_db)):
    rows = (
        db.query(DiagnosisResult, Checklist)
        .join(Checklist, DiagnosisResult.check_id == Checklist.check_id)
        .filter(DiagnosisResult.session_id == session_id)
        .all()
    )
    if not rows:
        raise HTTPException(status_code=404, detail="결과가 없습니다.")

    items = []
    for dr, cl in rows:
        items.append({
            "id": cl.item_id,
            "pillar": cl.pillar,
            "category": cl.category,
            "item": cl.item_name,
            "maturity": cl.maturity,
            "maturity_score": cl.maturity_score,
            "question": cl.question,
            "diagnosis_type": cl.diagnosis_type,
            "tool": cl.tool,
            "result": dr.result,
            "score": dr.score or 0.0,
            "evidence": cl.evidence or "",
            "criteria": cl.criteria or "",
            "fields": cl.fields or "",
            "logic": cl.logic or "",
            "exceptions": cl.exceptions or "",
            "recommendation": dr.recommendation or "",
        })
    return {"items": items, "total": len(items)}
