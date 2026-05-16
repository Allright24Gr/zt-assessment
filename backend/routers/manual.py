from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List, Optional
from datetime import datetime, timezone
from pathlib import Path
import io
import openpyxl

from database import get_db
from models import DiagnosisSession, Checklist, DiagnosisResult, Evidence, CollectedData, User
from routers.auth import get_current_user, assert_session_access

router = APIRouter()

MATURITY_NUM = {"기존": 1, "초기": 2, "향상": 3, "최적화": 4}
VALID_RESULTS = {"충족", "부분충족", "미충족", "평가불가"}


def _normalize_result(v: str) -> str:
    """부분 충족 → 부분충족 등 공백 정규화."""
    return v.replace(" ", "") if v else "평가불가"


def _build_judgment_map(wb: openpyxl.Workbook) -> dict:
    """judgment_mapping 시트에서 (M_id, 선택값) → 판정결과 딕셔너리 생성."""
    ws = wb["judgment_mapping"]
    mapping = {}
    for r in range(2, ws.max_row + 1):
        row = [ws.cell(r, c).value for c in range(1, 7)]
        m_id, _, _, _, choice, verdict = row
        if m_id and m_id != "항목ID" and choice and verdict:
            mapping[(str(m_id).strip(), str(choice).strip())] = _normalize_result(str(verdict).strip())
    return mapping


def _find_checklist(db: Session, item_no_str: str, maturity: str, question: str) -> Optional[Checklist]:
    """항목번호+성숙도+질문으로 Checklist 행을 찾는다.

    Excel 항목번호 예: "1.1.1 사용자 인벤토리" → prefix "1.1.1"
    DB item_id 형식: "{prefix}.{maturity_num}_{counter}" → "1.1.1.1_1"
    """
    if not item_no_str:
        return None
    prefix = item_no_str.strip().split()[0]
    mat_num = MATURITY_NUM.get(maturity, 0)
    if mat_num == 0:
        return None

    pattern = f"{prefix}.{mat_num}_%"
    candidates = db.query(Checklist).filter(Checklist.item_id.like(pattern)).all()
    if not candidates:
        return None

    q = (question or "").strip()
    if q:
        for c in candidates:
            if c.item_name and c.item_name.strip() == q:
                return c
    return candidates[0]


class ManualAnswer(BaseModel):
    check_id: str
    value: str
    evidence: str = ""


class ManualSubmitRequest(BaseModel):
    session_id: int
    answers: List[ManualAnswer]


@router.post("/upload")
async def manual_upload(
    session_id: int = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """수동 체크리스트 Excel 파일을 업로드해 DiagnosisResult를 일괄 생성한다.

    Excel 형식: manual-checklist.xlsx (manual_diagnosis + judgment_mapping 시트)
    """
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    assert_session_access(current_user, session)

    content = await file.read()
    try:
        wb = openpyxl.load_workbook(io.BytesIO(content), data_only=True)
    except Exception:
        raise HTTPException(status_code=400, detail="올바른 Excel(.xlsx) 파일이 아닙니다.")

    if "manual_diagnosis" not in wb.sheetnames or "judgment_mapping" not in wb.sheetnames:
        raise HTTPException(
            status_code=400,
            detail="manual_diagnosis / judgment_mapping 시트가 필요합니다.",
        )

    judgment_map = _build_judgment_map(wb)
    ws = wb["manual_diagnosis"]

    weight_map = {"충족": 1.0, "부분충족": 0.5, "미충족": 0.0, "평가불가": 0.0}
    saved = 0
    unmatched = 0
    skipped = 0

    for r in range(4, ws.max_row + 1):
        row = [ws.cell(r, c).value for c in range(1, 9)]
        m_id, category, item_no, maturity, question, _, choice, note = row

        # 카테고리 구분행·미입력 건너뜀
        if not m_id or str(m_id).startswith("▸") or not choice:
            skipped += 1
            continue

        m_id_str = str(m_id).strip()
        choice_str = str(choice).strip()
        note_str = str(note).strip() if note else ""

        verdict = judgment_map.get((m_id_str, choice_str))
        if not verdict:
            # 정확 매칭 실패 시 선택값 자체가 판정결과인 경우 허용
            verdict = _normalize_result(choice_str)
            if verdict not in VALID_RESULTS:
                verdict = "평가불가"

        checklist = _find_checklist(db, str(item_no), str(maturity), str(question))
        if not checklist:
            unmatched += 1
            continue

        check_id = checklist.check_id
        score = checklist.maturity_score * weight_map.get(verdict, 0.0)

        # CollectedData upsert
        existing_cd = db.query(CollectedData).filter(
            CollectedData.session_id == session_id,
            CollectedData.check_id == check_id,
        ).first()
        if existing_cd:
            existing_cd.tool = "수동"
            existing_cd.metric_key = "manual_result"
            existing_cd.metric_value = weight_map.get(verdict, 0.0)
            existing_cd.threshold = 1.0
            existing_cd.raw_json = {"manual": True, "choice": choice_str, "note": note_str}
            existing_cd.error = None
            existing_cd.collected_at = datetime.now(timezone.utc)
        else:
            db.add(CollectedData(
                session_id=session_id,
                check_id=check_id,
                tool="수동",
                metric_key="manual_result",
                metric_value=weight_map.get(verdict, 0.0),
                threshold=1.0,
                raw_json={"manual": True, "choice": choice_str, "note": note_str},
                error=None,
            ))

        # DiagnosisResult upsert
        existing_dr = db.query(DiagnosisResult).filter(
            DiagnosisResult.session_id == session_id,
            DiagnosisResult.check_id == check_id,
        ).first()
        if existing_dr:
            existing_dr.result = verdict
            existing_dr.score = score
        else:
            db.add(DiagnosisResult(
                session_id=session_id,
                check_id=check_id,
                result=verdict,
                score=score,
                recommendation="",
            ))

        if note_str:
            db.add(Evidence(
                session_id=session_id,
                check_id=check_id,
                source="수동입력(Excel)",
                observed=note_str,
                location="",
                reason="",
                impact=None,
            ))

        saved += 1

    db.commit()
    return {
        "status":          "ok",
        "session_id":      session_id,
        "parsed_count":    saved,
        "unmatched_count": unmatched,
        "skipped_count":   skipped,
    }


@router.post("/submit")
def manual_submit(
    req: ManualSubmitRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == req.session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    assert_session_access(current_user, session)

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


@router.get("/template")
def download_template(current_user: User = Depends(get_current_user)):
    """사용자에게 배포할 빈 manual-checklist.xlsx 템플릿을 반환한다."""
    candidates = [
        Path("/app/manual-checklist.xlsx"),
        Path(__file__).parent.parent / "manual-checklist.xlsx",
    ]
    for p in candidates:
        if p.exists():
            return FileResponse(
                path=str(p),
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                filename="manual-checklist.xlsx",
            )
    raise HTTPException(status_code=404, detail="템플릿 파일을 찾을 수 없습니다.")


@router.get("/items/{session_id}")
def get_manual_items(
    session_id: int,
    excluded_tools: str = "",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """수동 진단 항목 + 미사용 도구 항목을 반환한다.
    excluded_tools: 쉼표 구분 도구명 (예: 'nmap,trivy') — 해당 도구 자동 항목도 수동으로 포함.
    """
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    assert_session_access(current_user, session)

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
