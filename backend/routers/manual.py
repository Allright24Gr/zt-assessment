from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List, Optional
from datetime import datetime, timezone
from pathlib import Path
from copy import copy
import io
import os
import uuid
import logging
import openpyxl
from openpyxl.styles import Alignment, Font, PatternFill, Border, Side
from openpyxl.worksheet.datavalidation import DataValidation

from database import get_db
from models import DiagnosisSession, Checklist, DiagnosisResult, Evidence, CollectedData, User
from routers.auth import get_current_user, assert_session_access

logger = logging.getLogger(__name__)
router = APIRouter()

# P1-7: 증적 파일 업로드 설정
EVIDENCE_STORAGE_DIR = os.getenv("EVIDENCE_STORAGE_DIR", "/var/lib/zt-assessment/evidence")
MAX_EVIDENCE_SIZE_MB = int(os.getenv("MAX_EVIDENCE_SIZE_MB", "10"))
_ALLOWED_EVIDENCE_MIMES = {
    "application/pdf":  "pdf",
    "image/png":        "png",
    "image/jpeg":       "jpg",
    "image/gif":        "gif",
    "image/webp":       "webp",
}

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
    """사용자에게 배포할 빈 manual-checklist.xlsx 템플릿을 반환한다.

    정적 양식 — xlsx 원래 수동 진단 98건만 포함. 자동 폴백 항목은 미포함이므로
    세션이 있다면 GET /template/{session_id} 동적 양식 사용을 권장.
    """
    p = _find_base_template()
    if p:
        return FileResponse(
            path=str(p),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            filename="manual-checklist.xlsx",
        )
    raise HTTPException(status_code=404, detail="템플릿 파일을 찾을 수 없습니다.")


def _find_base_template() -> Optional[Path]:
    """배포 환경 (/app/...) 과 로컬 dev 환경 양쪽에서 base xlsx 위치 탐색."""
    for p in (Path("/app/manual-checklist.xlsx"),
              Path(__file__).parent.parent / "manual-checklist.xlsx"):
        if p.exists():
            return p
    return None


# ─── 세션별 동적 양식 생성 ──────────────────────────────────────────────────
# T-Markov 같은 SaaS 환경(Keycloak/Wazuh 미사용)에서는 자동 항목이 수동으로
# 폴백되는데, 정적 양식엔 그 폴백 항목이 없다. 세션의 profile_select 와
# selected_tools 를 기반으로 폴백 항목까지 포함한 양식을 동적 생성한다.

_IDP_AUTO_TOOLS_FOR_FALLBACK = {"keycloak", "entra"}
_SIEM_AUTO_TOOLS_FOR_FALLBACK = {"wazuh"}


def _resolve_fallback_tools(session: DiagnosisSession) -> set[str]:
    """세션 환경에서 자동 폴백되는 도구 집합 산출.

    예: profile_select={idp_type: 'google_workspace', siem_type: 'none'}
        → {'keycloak', 'entra', 'wazuh'} 모두 폴백(자동 항목이 수동으로 떨어짐).
    """
    extra = session.extra if isinstance(session.extra, dict) else {}
    ps = extra.get("profile_select") if isinstance(extra.get("profile_select"), dict) else {}
    idp_sel = (ps.get("idp_type") or "").lower()
    siem_sel = (ps.get("siem_type") or "").lower()

    fallback: set[str] = set()
    # IdP 자동 도구 중 사용자가 선택하지 않은 것 → 폴백
    if idp_sel:
        for t in _IDP_AUTO_TOOLS_FOR_FALLBACK:
            if idp_sel != t:
                fallback.add(t)
    if siem_sel:
        for t in _SIEM_AUTO_TOOLS_FOR_FALLBACK:
            if siem_sel != t:
                fallback.add(t)
    return fallback


# 폴백 항목 기본 선택지 — 가이드 §5 톤에 맞춘 4단계.
# 기존 수동 항목 다수가 (운영 중, 계획, 미도입) 3선택지를 쓰므로 동일 패턴 유지.
_FALLBACK_CHOICES = [
    ("운영 중",     "충족"),
    ("부분 운영",   "부분 충족"),
    ("미도입",      "미충족"),
    ("평가 불가",   "평가 불가"),
]


# 카테고리(Pillar) 정렬 순서 — 기존 양식과 동일하게 6 Pillar 순으로.
_PILLAR_ORDER = [
    "식별자 및 신원",
    "기기 및 엔드포인트",
    "네트워크",
    "시스템",
    "애플리케이션 및 워크로드",
    "데이터",
]


def _pillar_sort_key(pillar: str) -> int:
    try:
        return _PILLAR_ORDER.index(pillar)
    except ValueError:
        return len(_PILLAR_ORDER)


def _build_session_template_xlsx(session: DiagnosisSession, db: Session) -> bytes:
    """세션 기반 동적 xlsx 생성 — 기존 정적 양식에 폴백 항목 추가.

    동작:
      1) base manual-checklist.xlsx 로드.
      2) 폴백 도구의 Checklist 항목을 DB 에서 조회 (이미 수동 양식에 있는 항목은 제외).
      3) manual_diagnosis 시트 끝에 카테고리 구분행 + 데이터 행 추가.
      4) judgment_mapping 시트 끝에 동일 M_id 의 4선택지(_FALLBACK_CHOICES) 추가.
      5) bytes 로 직렬화.
    """
    base = _find_base_template()
    if not base:
        raise HTTPException(status_code=500, detail="base 양식 파일을 찾을 수 없습니다.")

    wb = openpyxl.load_workbook(base)
    ws_diag = wb["manual_diagnosis"]
    ws_judg = wb["judgment_mapping"]

    # 기존 양식에 이미 포함된 (item_no_prefix, maturity) 조합 — 중복 추가 방지.
    existing_keys: set[tuple[str, str]] = set()
    for r in range(4, ws_diag.max_row + 1):
        mid = ws_diag.cell(r, 1).value
        if not mid or str(mid).startswith("▸"):
            continue
        item_no = str(ws_diag.cell(r, 3).value or "").split()[0] if ws_diag.cell(r, 3).value else ""
        maturity = str(ws_diag.cell(r, 4).value or "").strip()
        if item_no and maturity:
            existing_keys.add((item_no, maturity))

    fallback_tools = _resolve_fallback_tools(session)
    if not fallback_tools:
        # 폴백 없음 — 그대로 출력 (=정적 양식과 동일)
        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()

    # 폴백 도구 매핑된 Checklist 항목 조회
    rows = db.query(Checklist).filter(
        Checklist.tool.in_(sorted(fallback_tools))
    ).all()
    # 카테고리·item_id 순으로 정렬
    rows.sort(key=lambda c: (_pillar_sort_key(c.pillar or ""), c.item_id or ""))

    # 기존 양식에 이미 있는 항목 제외
    new_items = []
    for cl in rows:
        prefix = (cl.item_id or "").split("_", 1)[0]  # "1.1.1.1"
        item_no_prefix = ".".join(prefix.split(".")[:3])  # "1.1.1"
        key = (item_no_prefix, cl.maturity or "")
        if key in existing_keys:
            continue
        new_items.append((cl, item_no_prefix))

    if not new_items:
        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()

    # 다음 M_id 번호 산출
    max_m_num = 0
    for r in range(4, ws_diag.max_row + 1):
        v = ws_diag.cell(r, 1).value
        if v and isinstance(v, str) and v.startswith("M"):
            try:
                max_m_num = max(max_m_num, int(v[1:]))
            except ValueError:
                pass
    next_m = max_m_num + 1

    # 행 스타일 캐시 — base 양식의 데이터 행 1개를 샘플로 사용 (Row 5)
    sample_row = 5
    cell_styles = {}
    for col in range(1, 9):
        sc = ws_diag.cell(sample_row, col)
        cell_styles[col] = {
            "font":      copy(sc.font),
            "fill":      copy(sc.fill),
            "border":    copy(sc.border),
            "alignment": copy(sc.alignment),
        }

    # 카테고리 구분행 스타일 (Row 4)
    cat_styles = {}
    for col in range(1, 9):
        sc = ws_diag.cell(4, col)
        cat_styles[col] = {
            "font":      copy(sc.font),
            "fill":      copy(sc.fill),
            "border":    copy(sc.border),
            "alignment": copy(sc.alignment),
        }

    # 폴백 항목을 Pillar 별로 그룹화
    by_pillar: dict[str, list] = {}
    for cl, item_no_prefix in new_items:
        by_pillar.setdefault(cl.pillar or "기타", []).append((cl, item_no_prefix))

    # manual_diagnosis 시트 끝에 추가
    append_at = ws_diag.max_row + 2  # 한 줄 띄움

    # 안내 헤더 (폴백 섹션 구분)
    notice_row = append_at
    nc = ws_diag.cell(notice_row, 1)
    nc.value = (
        f"▼ 자동 폴백 항목 — 사용 환경(IdP/SIEM)에서 자동 진단이 불가능해 수동으로 평가해야 하는 항목 "
        f"({len(new_items)}건)"
    )
    nc.font = Font(name="Arial", size=11, bold=True, color="FFB91C1C")
    nc.fill = PatternFill("solid", fgColor="FFFEE2E2")
    ws_diag.merge_cells(start_row=notice_row, start_column=1, end_row=notice_row, end_column=8)
    nc.alignment = Alignment(horizontal="left", vertical="center", wrap_text=True)
    append_at += 1

    new_mapping_rows: list[tuple] = []  # (m_id, pillar, item_no_full, maturity, choice, verdict)

    for pillar in sorted(by_pillar.keys(), key=_pillar_sort_key):
        items = by_pillar[pillar]
        # 카테고리 구분행
        cat_cell = ws_diag.cell(append_at, 1)
        cat_cell.value = f"▸  {pillar}"
        ws_diag.merge_cells(start_row=append_at, start_column=1, end_row=append_at, end_column=8)
        for col in range(1, 9):
            c = ws_diag.cell(append_at, col)
            cs = cat_styles.get(col, {})
            if cs.get("font"):      c.font      = copy(cs["font"])
            if cs.get("fill"):      c.fill      = copy(cs["fill"])
            if cs.get("border"):    c.border    = copy(cs["border"])
            if cs.get("alignment"): c.alignment = copy(cs["alignment"])
        append_at += 1

        for cl, item_no_prefix in items:
            m_id = f"M{next_m:03d}"
            next_m += 1
            item_no_full = (cl.category or item_no_prefix)
            row_vals = [
                m_id,
                pillar,
                item_no_full,
                cl.maturity or "",
                cl.item_name or "",
                cl.criteria or "",
                None,  # ★ 담당자 선택 (필수) — 빈 칸
                None,  # 비고/증적메모
            ]
            for col, val in enumerate(row_vals, start=1):
                c = ws_diag.cell(append_at, col)
                c.value = val
                cs = cell_styles.get(col, {})
                if cs.get("font"):      c.font      = copy(cs["font"])
                if cs.get("fill"):      c.fill      = copy(cs["fill"])
                if cs.get("border"):    c.border    = copy(cs["border"])
                if cs.get("alignment"): c.alignment = copy(cs["alignment"])

            # judgment_mapping 행 누적
            for choice, verdict in _FALLBACK_CHOICES:
                new_mapping_rows.append(
                    (m_id, pillar, item_no_full, cl.maturity or "", choice, verdict)
                )
            append_at += 1

    # judgment_mapping 시트에 폴백 매핑 추가
    judg_append = ws_judg.max_row + 1
    for tup in new_mapping_rows:
        for col, val in enumerate(tup, start=1):
            ws_judg.cell(judg_append, col).value = val
        judg_append += 1

    # 드롭다운(데이터 검증) 추가 — ★ 담당자 선택 (필수) 컬럼(G)에 폴백 행만
    # _FALLBACK_CHOICES 의 choice 값만 허용
    fallback_choice_str = ",".join(c for c, _ in _FALLBACK_CHOICES)
    dv = DataValidation(
        type="list",
        formula1=f'"{fallback_choice_str}"',
        allow_blank=True,
        showErrorMessage=True,
        errorTitle="선택값 확인",
        error="드롭다운에서 선택해주세요.",
    )
    # 폴백 데이터 행 범위 (notice_row+1 ~ append_at-1)
    first_data_row = notice_row + 1
    last_data_row = append_at - 1
    if last_data_row >= first_data_row:
        dv.add(f"G{first_data_row}:G{last_data_row}")
        ws_diag.add_data_validation(dv)

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


@router.get("/template/{session_id}")
def download_session_template(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """세션별 동적 양식 — 자동 폴백 항목까지 포함한 xlsx 생성·반환.

    SKT 가이드 §1·§5 권고: "자동수집이 안 되는 항목을 평가불가로 방치하지 말고
    수동 증적을 붙여 판정" 하기 위한 핵심 도구. T-Markov 처럼 Keycloak/Wazuh 환경이
    아닌 SaaS 형 평가에서는 이 동적 양식이 정적 양식보다 훨씬 많은 항목을 포함한다.
    """
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    assert_session_access(current_user, session)

    try:
        data = _build_session_template_xlsx(session, db)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("[manual] session template build failed: %s", exc)
        raise HTTPException(status_code=500, detail="양식 생성에 실패했습니다.")

    filename = f"manual-checklist-session-{session_id}.xlsx"
    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/items/{session_id}")
def get_manual_items(
    session_id: int,
    excluded_tools: str = "",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """수동 진단 항목 + 미사용 도구 항목을 반환한다.
    excluded_tools: 쉼표 구분 도구명 (예: 'nmap,trivy') — 해당 도구 자동 항목도 수동으로 포함.

    추가: session.extra.profile_select 가 있으면 사용자가 쓰는 IdP/SIEM 외 자동 도구의
    체크리스트 항목을 자동으로 폴백 노출한다(예: idp_type='entra' → keycloak 항목 수동).
    """
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    assert_session_access(current_user, session)

    excluded_set = {t.strip().lower() for t in excluded_tools.split(",") if t.strip()}
    # session.extra.profile_select 기반 자동 폴백 — _resolve_fallback_tools 와 동일 규칙.
    excluded_set |= _resolve_fallback_tools(session)
    excluded_list = sorted(excluded_set)
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


# ─── P1-7: 수동 증적 파일 업로드 / 다운로드 ────────────────────────────────────


def _resolve_check_id(db: Session, check_id_raw) -> Optional[int]:
    """check_id 가 숫자(PK) 또는 item_id 문자열로 올 수 있도록 둘 다 지원."""
    if check_id_raw is None:
        return None
    if isinstance(check_id_raw, int):
        return check_id_raw
    s = str(check_id_raw).strip()
    if not s:
        return None
    if s.isdigit():
        return int(s)
    cl = db.query(Checklist).filter(Checklist.item_id == s).first()
    return cl.check_id if cl else None


@router.post("/upload-evidence")
async def upload_evidence(
    session_id: int = Form(...),
    check_id: str = Form(...),
    file: UploadFile = File(...),
    note: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """진단 항목별 증적 파일 업로드 (PDF/이미지). 세션 권한 검증 후 로컬 디스크 저장."""
    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    assert_session_access(current_user, session)

    resolved_check_id = _resolve_check_id(db, check_id)
    if resolved_check_id is None:
        raise HTTPException(status_code=400, detail="check_id 가 유효하지 않습니다.")
    checklist = db.query(Checklist).filter(Checklist.check_id == resolved_check_id).first()
    if not checklist:
        raise HTTPException(status_code=404, detail="체크리스트 항목을 찾을 수 없습니다.")

    mime = (file.content_type or "").lower()
    if mime not in _ALLOWED_EVIDENCE_MIMES:
        raise HTTPException(
            status_code=400,
            detail=f"허용되지 않는 파일 형식입니다. (허용: {', '.join(sorted(_ALLOWED_EVIDENCE_MIMES))})",
        )

    max_bytes = MAX_EVIDENCE_SIZE_MB * 1024 * 1024
    content = await file.read()
    file_size = len(content)
    if file_size == 0:
        raise HTTPException(status_code=400, detail="빈 파일은 업로드할 수 없습니다.")
    if file_size > max_bytes:
        raise HTTPException(
            status_code=400,
            detail=f"파일 크기가 너무 큽니다. (최대 {MAX_EVIDENCE_SIZE_MB}MB)",
        )

    ext = _ALLOWED_EVIDENCE_MIMES[mime]
    target_dir = Path(EVIDENCE_STORAGE_DIR) / str(session_id) / str(resolved_check_id)
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.error("[evidence] storage dir mkdir failed: %s", exc)
        raise HTTPException(status_code=500, detail="증적 저장소 초기화에 실패했습니다.")

    filename = f"{uuid.uuid4().hex}.{ext}"
    target_path = target_dir / filename
    try:
        with open(target_path, "wb") as fp:
            fp.write(content)
    except OSError as exc:
        logger.error("[evidence] write failed: %s", exc)
        raise HTTPException(status_code=500, detail="증적 파일 저장에 실패했습니다.")

    original_filename = (file.filename or "")[:255] or None
    note_str = (note or "").strip() or None

    existing = db.query(Evidence).filter(
        Evidence.session_id == session_id,
        Evidence.check_id == resolved_check_id,
    ).first()

    old_file_path: Optional[str] = None
    if existing:
        old_file_path = existing.file_path
        existing.source = "수동업로드"
        existing.observed = note_str
        existing.file_path = str(target_path)
        existing.mime_type = mime
        existing.file_size = file_size
        existing.original_filename = original_filename
        evidence = existing
    else:
        evidence = Evidence(
            session_id=session_id,
            check_id=resolved_check_id,
            source="수동업로드",
            observed=note_str,
            location="",
            reason="",
            impact=None,
            file_path=str(target_path),
            mime_type=mime,
            file_size=file_size,
            original_filename=original_filename,
        )
        db.add(evidence)

    db.commit()
    db.refresh(evidence)

    # 이전 파일이 있었다면 best-effort 삭제 (실패 무시 — 메타는 이미 갱신).
    if old_file_path and old_file_path != str(target_path):
        try:
            Path(old_file_path).unlink(missing_ok=True)
        except Exception as exc:
            logger.warning("[evidence] previous file unlink failed: %s", exc)

    return {
        "status":      "ok",
        "evidence_id": evidence.evidence_id,
        "file_path":   evidence.file_path,
        "file_size":   evidence.file_size,
        "mime_type":   evidence.mime_type,
        "original_filename": evidence.original_filename,
    }


@router.get("/evidence/{evidence_id}")
def download_evidence(
    evidence_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """증적 파일 다운로드. 세션 권한 검증."""
    evidence = db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="증적을 찾을 수 없습니다.")
    if not evidence.file_path:
        raise HTTPException(status_code=404, detail="이 증적에는 첨부 파일이 없습니다.")

    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == evidence.session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    assert_session_access(current_user, session)

    path = Path(evidence.file_path)
    if not path.is_file():
        logger.warning("[evidence] file missing on disk: %s", evidence.file_path)
        raise HTTPException(status_code=410, detail="증적 파일이 디스크에서 사라졌습니다.")

    return FileResponse(
        path=str(path),
        media_type=evidence.mime_type or "application/octet-stream",
        filename=evidence.original_filename or path.name,
    )
