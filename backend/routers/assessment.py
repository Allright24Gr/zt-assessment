from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Optional
from database import get_db

router = APIRouter()


@router.post("/run")
def run_assessment(
    org_id: int,
    user_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """진단 세션을 시작하고 백그라운드에서 데이터 수집·채점을 실행한다."""
    # TODO: DiagnosisSession 레코드 생성
    # TODO: background_tasks.add_task(run_collection_pipeline, session_id, db)
    # TODO: 생성된 session_id 반환
    raise NotImplementedError


@router.get("/result")
def get_result(session_id: Optional[int] = None, db: Session = Depends(get_db)):
    """session_id에 해당하는 진단 결과(DiagnosisResult + MaturityScore)를 반환한다."""
    # TODO: DiagnosisResult, MaturityScore, Evidence 조인 조회
    # TODO: ChecklistDetail 형식으로 직렬화하여 반환
    raise NotImplementedError


@router.get("/history")
def get_history(org_id: Optional[int] = None, db: Session = Depends(get_db)):
    """조직별 또는 전체 진단 세션 이력을 반환한다."""
    # TODO: DiagnosisSession 목록 조회 (org_id 필터 선택)
    # TODO: Session 형식으로 직렬화하여 반환
    raise NotImplementedError


@router.post("/webhook")
def assessment_webhook(payload: dict, db: Session = Depends(get_db)):
    """Shuffle SOAR 또는 외부 도구에서 수집 결과를 수신하는 웹훅 엔드포인트."""
    # TODO: payload 검증
    # TODO: CollectedData 저장
    # TODO: 해당 세션의 채점 트리거
    raise NotImplementedError
