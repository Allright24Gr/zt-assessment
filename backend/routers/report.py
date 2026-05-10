from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from database import get_db

router = APIRouter()


@router.get("/generate/{session_id}")
def generate_report(
    session_id: int,
    fmt: str = "json",
    db: Session = Depends(get_db),
):
    """진단 세션 결과를 JSON 또는 PDF 형식의 보고서로 생성한다."""
    # TODO: fmt 검증 (json / pdf)
    # TODO: session_id로 DiagnosisResult, MaturityScore, ScoreHistory 수집
    # TODO: json: dict 직렬화 후 JSONResponse 반환
    # TODO: pdf: reportlab/weasyprint로 PDF 생성 후 StreamingResponse 반환
    raise NotImplementedError
