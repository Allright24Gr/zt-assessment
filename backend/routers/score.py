from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional

from database import get_db
from models import MaturityScore, ScoreHistory, DiagnosisResult, Checklist, DiagnosisSession, User
from scoring.engine import determine_maturity_level
from routers.auth import get_current_user, assert_session_access, assert_org_access

router = APIRouter()


def _load_session_or_404(db: Session, session_id: int) -> DiagnosisSession:
    s = db.query(DiagnosisSession).filter(DiagnosisSession.session_id == session_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    return s


@router.get("/summary")
def get_score_summary(
    session_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """세션별 pillar 성숙도 점수 요약을 반환한다."""
    if session_id is None:
        raise HTTPException(status_code=400, detail="session_id required")

    session = _load_session_or_404(db, session_id)
    assert_session_access(current_user, session)

    pillar_scores = (
        db.query(MaturityScore)
        .filter(MaturityScore.session_id == session_id)
        .all()
    )
    if not pillar_scores:
        raise HTTPException(status_code=404, detail="Score not found for this session")

    scores = [ps.score for ps in pillar_scores]
    overall = sum(scores) / len(scores) if scores else 0.0

    return {
        "overall_score": round(overall, 4),
        "overall_level": determine_maturity_level(overall),
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
    }


@router.get("/trend")
def get_score_trend(
    org_id: int,
    limit: int = 12,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """조직의 시간순 점수 추이를 반환한다."""
    assert_org_access(current_user, org_id)
    histories = (
        db.query(ScoreHistory)
        .filter(ScoreHistory.org_id == org_id)
        .order_by(ScoreHistory.assessed_at.asc())
        .limit(limit)
        .all()
    )

    return [
        {
            "history_id": h.history_id,
            "session_id": h.session_id,
            "total_score": h.total_score,
            "maturity_level": h.maturity_level,
            "pillar_scores": h.pillar_scores,
            "assessed_at": h.assessed_at.isoformat() if h.assessed_at else None,
        }
        for h in histories
    ]


@router.get("/checklist/{session_id}")
def get_checklist_scores(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """세션의 체크리스트 항목별 상세 점수를 반환한다."""
    session = _load_session_or_404(db, session_id)
    assert_session_access(current_user, session)

    results = (
        db.query(DiagnosisResult, Checklist)
        .join(Checklist, DiagnosisResult.check_id == Checklist.check_id)
        .filter(DiagnosisResult.session_id == session_id)
        .all()
    )

    return [
        {
            "item_id": cl.item_id,
            "check_id": cl.check_id,
            "pillar": cl.pillar,
            "category": cl.category,
            "item_name": cl.item_name,
            "maturity": cl.maturity,
            "maturity_score": cl.maturity_score,
            "result": dr.result,
            "score": dr.score,
            "recommendation": dr.recommendation,
        }
        for dr, cl in results
    ]
