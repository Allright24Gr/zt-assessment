from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import case
from sqlalchemy.orm import Session
from typing import Optional

from database import get_db
from models import ImprovementGuide, DiagnosisResult, Checklist, DiagnosisSession, User
from routers.auth import get_current_user, assert_session_access
from services.improvement_customizer import customize_guide
from services.risk_effort_matrix import sort_guides_by_matrix, matrix_summary

router = APIRouter()

_PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_TERM_ORDER = {"단기": 0, "중기": 1, "장기": 2}


def _priority_case():
    return case(
        (ImprovementGuide.priority == "Critical", 0),
        (ImprovementGuide.priority == "High", 1),
        (ImprovementGuide.priority == "Medium", 2),
        (ImprovementGuide.priority == "Low", 3),
        else_=3,
    )


def _term_case():
    return case(
        (ImprovementGuide.term == "단기", 0),
        (ImprovementGuide.term == "중기", 1),
        (ImprovementGuide.term == "장기", 2),
        else_=2,
    )


@router.get("/")
def get_improvements(
    pillar: Optional[str] = None,
    term: Optional[str] = None,
    priority: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """개선 가이드 카탈로그 (조직 무관 글로벌 참조 테이블).

    ImprovementGuide 는 체크리스트별 권고를 담은 시드 데이터로 사용자 데이터가 아니다.
    따라서 조직 격리는 적용하지 않는다 (인증만 요구). 세션 컨텍스트 권고는
    /session/{id} 사용.
    """
    q = db.query(ImprovementGuide)
    if pillar:
        q = q.filter(ImprovementGuide.pillar == pillar)
    if term:
        q = q.filter(ImprovementGuide.term == term)
    if priority:
        q = q.filter(ImprovementGuide.priority == priority)
    guides = q.order_by(_priority_case(), _term_case()).all()

    return [
        {
            "guide_id": g.guide_id,
            "check_id": g.check_id,
            "pillar": g.pillar,
            "current_level": g.current_level,
            "next_level": g.next_level,
            "recommended_tool": g.recommended_tool,
            "task": g.task,
            "priority": g.priority,
            "term": g.term,
            "duration": g.duration,
            "difficulty": g.difficulty,
            "owner": g.owner,
            "expected_gain": g.expected_gain,
        }
        for g in guides
    ]


# /session/{session_id}를 /{guide_id} 보다 먼저 등록해야 라우팅 충돌 방지
@router.get("/session/{session_id}")
def get_session_improvements(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """세션의 미충족·부분충족 항목에 연결된 개선 가이드를 우선순위 순으로 반환한다."""
    session = db.query(DiagnosisSession).filter(DiagnosisSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    assert_session_access(current_user, session)

    failed_check_ids = {
        r.check_id
        for r in db.query(DiagnosisResult).filter(
            DiagnosisResult.session_id == session_id,
            DiagnosisResult.result.in_(["미충족", "부분충족"]),
        ).all()
    }

    if not failed_check_ids:
        return []

    guides = (
        db.query(ImprovementGuide)
        .filter(ImprovementGuide.check_id.in_(failed_check_ids))
        .order_by(_priority_case(), _term_case())
        .all()
    )

    # session.extra.profile_select 추출 후 권고 맞춤
    profile_select = None
    if isinstance(session.extra, dict):
        ps = session.extra.get("profile_select")
        if isinstance(ps, dict):
            profile_select = ps

    customized = [
        customize_guide(
            {
                "guide_id": g.guide_id,
                "check_id": g.check_id,
                "pillar": g.pillar,
                "task": g.task,
                "priority": g.priority,
                "term": g.term,
                "difficulty": g.difficulty,
                "recommended_tool": g.recommended_tool,
                "expected_gain": g.expected_gain,
            },
            profile_select,
        )
        for g in guides
    ]
    # 위험-노력 매트릭스 정렬 + 각 item 에 quadrant / risk_score / effort_score 부착.
    # 응답 형식은 list 그대로 (frontend 호환성 유지). matrix summary 는 별도 endpoint.
    return sort_guides_by_matrix(customized)


@router.get("/session/{session_id}/matrix")
def get_session_improvement_matrix(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """세션 개선 가이드의 위험-노력 매트릭스 요약 (사분면별 카운트 + Quick Win 상위 3개)."""
    session = db.query(DiagnosisSession).filter(DiagnosisSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    assert_session_access(current_user, session)

    failed_check_ids = {
        r.check_id
        for r in db.query(DiagnosisResult).filter(
            DiagnosisResult.session_id == session_id,
            DiagnosisResult.result.in_(["미충족", "부분충족"]),
        ).all()
    }
    if not failed_check_ids:
        return {"quadrant_counts": {}, "top_quick_wins": []}

    guides = (
        db.query(ImprovementGuide)
        .filter(ImprovementGuide.check_id.in_(failed_check_ids))
        .all()
    )

    profile_select = None
    if isinstance(session.extra, dict):
        ps = session.extra.get("profile_select")
        if isinstance(ps, dict):
            profile_select = ps

    customized = [
        customize_guide(
            {
                "guide_id": g.guide_id,
                "check_id": g.check_id,
                "pillar": g.pillar,
                "task": g.task,
                "priority": g.priority,
                "term": g.term,
                "difficulty": g.difficulty,
                "recommended_tool": g.recommended_tool,
                "expected_gain": g.expected_gain,
            },
            profile_select,
        )
        for g in guides
    ]
    return matrix_summary(customized)


@router.get("/{guide_id}")
def get_improvement_detail(
    guide_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """특정 개선 가이드의 상세 정보를 반환한다."""
    guide = db.query(ImprovementGuide).filter(
        ImprovementGuide.guide_id == guide_id
    ).first()
    if not guide:
        raise HTTPException(status_code=404, detail="Guide not found")

    checklist = None
    if guide.check_id:
        checklist = db.query(Checklist).filter(
            Checklist.check_id == guide.check_id
        ).first()

    return {
        "guide_id": guide.guide_id,
        "check_id": guide.check_id,
        "pillar": guide.pillar,
        "current_level": guide.current_level,
        "next_level": guide.next_level,
        "recommended_tool": guide.recommended_tool,
        "task": guide.task,
        "priority": guide.priority,
        "term": guide.term,
        "duration": guide.duration,
        "difficulty": guide.difficulty,
        "owner": guide.owner,
        "expected_gain": guide.expected_gain,
        "related_item": guide.related_item,
        "steps": guide.steps,
        "expected_effect": guide.expected_effect,
        "checklist": {
            "item_id": checklist.item_id,
            "item_name": checklist.item_name,
            "category": checklist.category,
        } if checklist else None,
    }
