from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional
from datetime import datetime, timezone
import httpx
import os

from database import get_db
from models import (
    DiagnosisSession, Checklist, CollectedData,
    DiagnosisResult, MaturityScore, ScoreHistory, Organization, User,
)
from scoring.engine import score_session, determine_maturity_level

router = APIRouter()

SHUFFLE_URL = os.environ.get("SHUFFLE_URL", "http://shuffle:3000")
SHUFFLE_API_KEY = os.environ.get("SHUFFLE_API_KEY", "")
SHUFFLE_WORKFLOW_ID = os.environ.get("SHUFFLE_WORKFLOW_ID", "")


@router.post("/run")
def run_assessment(
    org_id: int,
    user_id: int,
    db: Session = Depends(get_db),
):
    org = db.query(Organization).filter(Organization.org_id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="조직을 찾을 수 없습니다.")
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    session = DiagnosisSession(
        org_id=org_id,
        user_id=user_id,
        status="진행 중",
        started_at=datetime.now(timezone.utc),
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    if SHUFFLE_WORKFLOW_ID:
        try:
            with httpx.Client(timeout=10.0) as client:
                client.post(
                    f"{SHUFFLE_URL}/api/v1/workflows/{SHUFFLE_WORKFLOW_ID}/execute",
                    headers={"Authorization": f"Bearer {SHUFFLE_API_KEY}"},
                    json={"execution_argument": {"session_id": session.session_id}},
                )
        except Exception:
            pass

    return {
        "session_id": session.session_id,
        "status": "진행 중",
        "message": "진단이 시작되었습니다.",
        "started_at": session.started_at.isoformat(),
    }


@router.post("/webhook")
def assessment_webhook(payload: dict, db: Session = Depends(get_db)):
    session_id = payload.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id가 필요합니다.")

    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")

    results = payload.get("results", [])
    for item in results:
        item_id_str = item.get("item_id")
        checklist = None
        if item_id_str:
            checklist = db.query(Checklist).filter(Checklist.item_id == item_id_str).first()
        check_id = checklist.check_id if checklist else None
        if not check_id:
            continue

        existing = db.query(CollectedData).filter(
            CollectedData.session_id == session_id,
            CollectedData.check_id == check_id,
        ).first()

        if existing:
            existing.tool = item.get("tool", existing.tool)
            existing.metric_key = item.get("metric_key", existing.metric_key)
            existing.metric_value = item.get("metric_value")
            existing.threshold = item.get("threshold")
            existing.raw_json = item.get("raw_json")
            existing.error = item.get("error")
            existing.collected_at = datetime.now(timezone.utc)
        else:
            db.add(CollectedData(
                session_id=session_id,
                check_id=check_id,
                tool=item.get("tool", "unknown"),
                metric_key=item.get("metric_key", ""),
                metric_value=item.get("metric_value"),
                threshold=item.get("threshold"),
                raw_json=item.get("raw_json"),
                error=item.get("error"),
            ))

    db.commit()

    auto_total = db.query(func.count(Checklist.check_id)).filter(
        Checklist.diagnosis_type == "자동"
    ).scalar() or 0

    collected_count = db.query(func.count(CollectedData.data_id)).filter(
        CollectedData.session_id == session_id
    ).scalar() or 0

    if auto_total > 0 and collected_count >= auto_total:
        _trigger_scoring(session_id, db)

    return {"status": "ok", "saved": len(results)}


def _trigger_scoring(session_id: int, db: Session):
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        return

    collected_rows = db.query(CollectedData).filter(
        CollectedData.session_id == session_id
    ).all()

    check_ids = [r.check_id for r in collected_rows]
    meta_rows = db.query(Checklist).filter(Checklist.check_id.in_(check_ids)).all()

    checklist_meta = [
        {
            "check_id": m.check_id,
            "item_id": m.item_id,
            "pillar": m.pillar,
            "maturity_score": m.maturity_score,
            "category": m.category,
            "item_name": m.item_name,
        }
        for m in meta_rows
    ]

    collected_results = [
        {
            "check_id": r.check_id,
            "tool": r.tool,
            "metric_key": r.metric_key,
            "metric_value": r.metric_value,
            "threshold": r.threshold,
            "raw_json": r.raw_json,
            "error": r.error,
        }
        for r in collected_rows
    ]

    output = score_session(session_id, collected_results, checklist_meta)

    for cr in output["checklist_results"]:
        check_id = cr.get("check_id")
        if not check_id:
            continue
        existing = db.query(DiagnosisResult).filter(
            DiagnosisResult.session_id == session_id,
            DiagnosisResult.check_id == check_id,
        ).first()
        if existing:
            existing.result = cr["result"]
            existing.score = cr["score"]
            existing.recommendation = cr.get("recommendation", "")
        else:
            db.add(DiagnosisResult(
                session_id=session_id,
                check_id=check_id,
                result=cr["result"],
                score=cr["score"],
                recommendation=cr.get("recommendation", ""),
            ))

    db.query(MaturityScore).filter(MaturityScore.session_id == session_id).delete()
    for pillar, score in output["pillar_scores"].items():
        db.add(MaturityScore(session_id=session_id, pillar=pillar, score=score))

    db.add(ScoreHistory(
        session_id=session_id,
        org_id=session.org_id,
        pillar_scores=output["pillar_scores"],
        total_score=output["total_score"],
        maturity_level=output["maturity_level"],
    ))

    session.status = "완료"
    session.level = output["maturity_level"]
    session.total_score = output["total_score"]
    session.completed_at = datetime.now(timezone.utc)
    db.commit()


@router.get("/result")
def get_result(session_id: int, db: Session = Depends(get_db)):
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
    for dr, cl in results:
        checklist_results.append({
            "id": cl.item_id,
            "pillar": cl.pillar,
            "category": cl.category,
            "item": cl.item_name,
            "maturity": cl.maturity,
            "maturity_score": cl.maturity_score,
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

    overall = session.total_score or 0.0

    return {
        "session": {
            "id": session.session_id,
            "org": org.name if org else "",
            "date": session.started_at.isoformat() if session.started_at else "",
            "manager": user.name if user else "",
            "user_id": session.user_id,
            "level": session.level or "",
            "status": session.status,
            "score": session.total_score,
            "errors": [],
        },
        "pillar_scores": pillar_scores,
        "overall_score": overall,
        "overall_level": session.level or determine_maturity_level(overall),
        "checklist_results": checklist_results,
    }


@router.get("/history")
def get_history(
    org_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    query = db.query(DiagnosisSession)
    if org_id is not None:
        query = query.filter(DiagnosisSession.org_id == org_id)
    sessions = query.order_by(DiagnosisSession.started_at.desc()).all()

    org_ids = list({s.org_id for s in sessions})
    user_ids = list({s.user_id for s in sessions})
    orgs = {o.org_id: o for o in db.query(Organization).filter(Organization.org_id.in_(org_ids)).all()}
    users = {u.user_id: u for u in db.query(User).filter(User.user_id.in_(user_ids)).all()}

    items = []
    for s in sessions:
        org = orgs.get(s.org_id)
        user = users.get(s.user_id)
        items.append({
            "id": s.session_id,
            "org": org.name if org else "",
            "date": s.started_at.isoformat() if s.started_at else "",
            "manager": user.name if user else "",
            "user_id": s.user_id,
            "level": s.level or "",
            "status": s.status,
            "score": s.total_score,
            "errors": [],
        })

    return {"sessions": items, "total": len(items)}
