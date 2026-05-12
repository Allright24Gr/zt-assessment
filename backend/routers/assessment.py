from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional
from datetime import datetime, timezone
import os
import requests as http_requests

from database import get_db
from models import (
    DiagnosisSession, CollectedData, Checklist,
    DiagnosisResult, MaturityScore, ScoreHistory,
)
from scoring.engine import score_session, determine_maturity_level

router = APIRouter()

SHUFFLE_URL = os.environ.get("SHUFFLE_URL", "http://shuffle:3000")
SHUFFLE_WORKFLOW_ID = os.environ.get("SHUFFLE_WORKFLOW_ID", "")
SHUFFLE_API_KEY = os.environ.get("SHUFFLE_API_KEY", "")


@router.post("/run")
def run_assessment(org_id: int, user_id: int, db: Session = Depends(get_db)):
    """DiagnosisSession 생성 후 Shuffle 워크플로우 트리거."""
    session = DiagnosisSession(org_id=org_id, user_id=user_id, status="진행 중")
    db.add(session)
    db.commit()
    db.refresh(session)

    if SHUFFLE_WORKFLOW_ID:
        try:
            http_requests.post(
                f"{SHUFFLE_URL}/api/v1/workflows/{SHUFFLE_WORKFLOW_ID}/execute",
                headers={"Authorization": f"Bearer {SHUFFLE_API_KEY}"},
                json={"session_id": session.session_id, "org_id": org_id},
                timeout=10,
            )
        except Exception:
            pass

    started = session.started_at
    return {
        "session_id": session.session_id,
        "status": "진행 중",
        "message": "진단이 시작되었습니다.",
        "started_at": started.isoformat() if started else datetime.now(timezone.utc).isoformat(),
    }


def _trigger_scoring(session_id: int, db: Session) -> None:
    """CollectedData를 읽어 채점 후 결과 테이블을 저장한다."""
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        return

    collected_rows = (
        db.query(CollectedData)
        .filter(CollectedData.session_id == session_id)
        .all()
    )
    checklist_rows = db.query(Checklist).all()
    meta_by_check_id = {c.check_id: c for c in checklist_rows}

    collected_results = [
        {
            "check_id": cd.check_id,
            "item_id": meta_by_check_id[cd.check_id].item_id if cd.check_id in meta_by_check_id else "",
            "metric_value": cd.metric_value,
            "threshold": cd.threshold,
            "error": cd.error,
            "raw_json": cd.raw_json or {},
        }
        for cd in collected_rows
    ]
    checklist_meta = [
        {
            "check_id": c.check_id,
            "item_id": c.item_id,
            "pillar": c.pillar,
            "maturity_score": c.maturity_score,
            "weight": c.weight,
        }
        for c in checklist_rows
    ]

    output = score_session(session_id, collected_results, checklist_meta)

    # pillar별 pass/fail/na 집계
    pillar_counts: dict = {}
    for cr in output["checklist_results"]:
        p = cr["pillar"]
        pillar_counts.setdefault(p, {"pass_cnt": 0, "fail_cnt": 0, "na_cnt": 0})
        if cr["result"] == "충족":
            pillar_counts[p]["pass_cnt"] += 1
        elif cr["result"] == "평가불가":
            pillar_counts[p]["na_cnt"] += 1
        else:
            pillar_counts[p]["fail_cnt"] += 1

    # DiagnosisResult upsert
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

    # MaturityScore upsert
    for pillar, score in output["pillar_scores"].items():
        counts = pillar_counts.get(pillar, {})
        existing = db.query(MaturityScore).filter(
            MaturityScore.session_id == session_id,
            MaturityScore.pillar == pillar,
        ).first()
        attrs = {
            "score": score,
            "level": determine_maturity_level(score),
            "pass_cnt": counts.get("pass_cnt", 0),
            "fail_cnt": counts.get("fail_cnt", 0),
            "na_cnt": counts.get("na_cnt", 0),
        }
        if existing:
            for k, v in attrs.items():
                setattr(existing, k, v)
        else:
            db.add(MaturityScore(session_id=session_id, pillar=pillar, **attrs))

    # ScoreHistory upsert
    existing_sh = db.query(ScoreHistory).filter(
        ScoreHistory.session_id == session_id
    ).first()
    if existing_sh:
        existing_sh.pillar_scores = output["pillar_scores"]
        existing_sh.total_score = output["total_score"]
        existing_sh.maturity_level = output["maturity_level"]
    else:
        db.add(ScoreHistory(
            session_id=session_id,
            org_id=session.org_id,
            pillar_scores=output["pillar_scores"],
            total_score=output["total_score"],
            maturity_level=output["maturity_level"],
        ))

    session.status = "완료"
    session.total_score = output["total_score"]
    session.level = output["maturity_level"]
    session.completed_at = datetime.now(timezone.utc)
    db.commit()


@router.post("/webhook")
def assessment_webhook(payload: dict, db: Session = Depends(get_db)):
    """Shuffle에서 수집 결과를 수신하고, 완료 시 채점을 트리거한다."""
    session_id = payload.get("session_id")
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id required")

    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # results 배열 또는 단건 결과 처리
    raw_results = payload.get("results", [])
    if not isinstance(raw_results, list):
        raw_results = [raw_results]
    if not raw_results and payload.get("item_id"):
        raw_results = [payload]

    checklist_map = {c.item_id: c for c in db.query(Checklist).all()}

    saved = 0
    for r in raw_results:
        item_id = r.get("item_id", "")
        cl = checklist_map.get(item_id)
        if not cl:
            continue
        existing = db.query(CollectedData).filter(
            CollectedData.session_id == session_id,
            CollectedData.check_id == cl.check_id,
        ).first()
        data = {
            "tool": r.get("tool", ""),
            "metric_key": r.get("metric_key", ""),
            "metric_value": r.get("metric_value"),
            "threshold": r.get("threshold"),
            "raw_json": r.get("raw_json") or {},
            "error": r.get("error"),
        }
        if existing:
            for k, v in data.items():
                setattr(existing, k, v)
        else:
            db.add(CollectedData(session_id=session_id, check_id=cl.check_id, **data))
        saved += 1

    db.commit()

    # 자동 진단 항목 수집 완료 여부 확인
    auto_total = (
        db.query(func.count(Checklist.check_id))
        .filter(Checklist.diagnosis_type == "자동")
        .scalar() or 0
    )
    collected_count = (
        db.query(func.count(CollectedData.data_id))
        .filter(CollectedData.session_id == session_id)
        .scalar() or 0
    )

    if auto_total > 0 and collected_count >= auto_total:
        try:
            _trigger_scoring(session_id, db)
        except Exception as exc:
            sess = db.query(DiagnosisSession).filter(
                DiagnosisSession.session_id == session_id
            ).first()
            if sess:
                sess.status = "오류"
                db.commit()
            raise HTTPException(status_code=500, detail=f"채점 실패: {exc}")

    return {"status": "ok", "saved": saved}


@router.get("/result")
def get_result(session_id: Optional[int] = None, db: Session = Depends(get_db)):
    """session_id에 해당하는 진단 결과를 반환한다."""
    if session_id is None:
        raise HTTPException(status_code=400, detail="session_id required")

    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    results = (
        db.query(DiagnosisResult, Checklist)
        .join(Checklist, DiagnosisResult.check_id == Checklist.check_id)
        .filter(DiagnosisResult.session_id == session_id)
        .all()
    )
    pillar_scores = (
        db.query(MaturityScore)
        .filter(MaturityScore.session_id == session_id)
        .all()
    )

    return {
        "session": {
            "session_id": session.session_id,
            "org_id": session.org_id,
            "user_id": session.user_id,
            "status": session.status,
            "level": session.level,
            "total_score": session.total_score,
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "completed_at": session.completed_at.isoformat() if session.completed_at else None,
        },
        "pillar_scores": [
            {
                "pillar": ps.pillar,
                "score": round(ps.score, 4),
                "level": ps.level,
                "pass_cnt": ps.pass_cnt,
                "fail_cnt": ps.fail_cnt,
                "na_cnt": ps.na_cnt,
            }
            for ps in pillar_scores
        ],
        "overall_score": round(session.total_score, 4) if session.total_score is not None else 0.0,
        "overall_level": session.level or "기존",
        "checklist_results": [
            {
                "item_id": cl.item_id,
                "check_id": cl.check_id,
                "pillar": cl.pillar,
                "category": cl.category,
                "item_name": cl.item_name,
                "maturity": cl.maturity,
                "result": dr.result,
                "score": dr.score,
                "recommendation": dr.recommendation,
            }
            for dr, cl in results
        ],
    }


@router.get("/history")
def get_history(org_id: Optional[int] = None, db: Session = Depends(get_db)):
    """조직별 또는 전체 진단 세션 이력을 반환한다."""
    q = db.query(DiagnosisSession)
    if org_id:
        q = q.filter(DiagnosisSession.org_id == org_id)
    sessions = q.order_by(DiagnosisSession.started_at.desc()).all()

    return [
        {
            "session_id": s.session_id,
            "org_id": s.org_id,
            "user_id": s.user_id,
            "status": s.status,
            "level": s.level,
            "total_score": s.total_score,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }
        for s in sessions
    ]
