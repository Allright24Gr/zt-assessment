from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Any, Optional
from datetime import datetime, timezone
import httpx
import logging
import os
import threading

from database import SessionLocal, get_db
from models import (
    DiagnosisSession, Checklist, CollectedData,
    DiagnosisResult, MaturityScore, ScoreHistory, Organization, User,
)
from scoring.engine import score_session, determine_maturity_level
from routers.auth import (
    get_current_user,
    assert_session_access,
    assert_org_access,
)
from routers.validators import (
    validate_nmap_target,
    validate_trivy_image,
    validate_https_url,
    validate_cred_field,
)

logger = logging.getLogger(__name__)
router = APIRouter()

SHUFFLE_URL     = os.getenv("SHUFFLE_URL", "")
SHUFFLE_API_KEY = os.getenv("SHUFFLE_API_KEY", "")
SELF_BASE_URL   = os.getenv("SELF_BASE_URL", "http://zt-backend:8000")
INTERNAL_TOKEN  = os.getenv("INTERNAL_API_TOKEN", "")

# seed_demo가 만드는 데모 조직의 정확한 이름. 결과/이력 응답에 is_demo 플래그로 노출.
DEMO_ORG_NAME = "데모_조직"

# 도구별 개별 워크플로우 ID (Shuffle UI에서 워크플로우 만든 후 입력)
SHUFFLE_WF = {
    "keycloak": os.getenv("SHUFFLE_WORKFLOW_KEYCLOAK", ""),
    "wazuh":    os.getenv("SHUFFLE_WORKFLOW_WAZUH",    ""),
    "nmap":     os.getenv("SHUFFLE_WORKFLOW_NMAP",     ""),
    "trivy":    os.getenv("SHUFFLE_WORKFLOW_TRIVY",    ""),
}
ALL_TOOLS = ("keycloak", "wazuh", "nmap", "trivy")


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _verify_internal_token(x_internal_token: Optional[str]):
    """X-Internal-Token 헤더 검증. fail-closed: 토큰 미설정 시 503.

    개발 편의를 위해 ZTA_DEV_ALLOW_UNAUTH_WEBHOOK=true 환경변수가 설정된 경우에만
    토큰 검증을 스킵한다. 운영 기본값은 fail-closed.
    """
    if not INTERNAL_TOKEN:
        if os.getenv("ZTA_DEV_ALLOW_UNAUTH_WEBHOOK", "").lower() == "true":
            return
        raise HTTPException(status_code=503, detail="INTERNAL_API_TOKEN not configured")
    if x_internal_token != INTERNAL_TOKEN:
        raise HTTPException(status_code=401, detail="invalid internal token")


def _get_session_or_404(db: Session, session_id: int) -> DiagnosisSession:
    s = db.query(DiagnosisSession).filter(DiagnosisSession.session_id == session_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    return s


def _mask_creds(extra: dict) -> dict:
    """session.extra 응답 직전에 자격 비밀번호를 마스킹.

    Phase 3 이후 비밀번호 자체는 DB에 저장되지 않는다(메모리 dict로만 전달).
    그러나 다음 두 경우에 대비해 마스킹 로직은 그대로 둔다:
      1) 과거에 저장된 세션 (마이그레이션 전 데이터)
      2) 잘못된 입력 경로로 누군가 admin_pass/api_pass를 extra에 넣은 경우
    """
    safe = dict(extra or {})
    for key in ("keycloak_creds", "wazuh_creds"):
        val = safe.get(key)
        if isinstance(val, dict):
            masked = dict(val)
            for pw_field in ("admin_pass", "api_pass"):
                if masked.get(pw_field):
                    masked[pw_field] = "***"
            safe[key] = masked
    return safe


# ─── 자격(비밀번호) 메모리 보관 ────────────────────────────────────────────────
# DB 평문 저장을 피하기 위해 세션 ID → 자격 dict 매핑을 메모리에만 보관한다.
# BackgroundTask(_run_collectors) 가 꺼내 쓰고 finally 에서 즉시 폐기.
# 서버 재시작/장애로 진단이 처리 전에 끊기면 자격은 사라지며 사용자가 재실행해야 한다.
_session_creds_lock = threading.Lock()
_session_creds_store: dict[int, dict] = {}


def _store_session_secrets(session_id: int, kc_creds: dict, wz_creds: dict) -> None:
    """run_assessment 가 호출. {} 가 들어와도 일관성 위해 키는 항상 생성."""
    with _session_creds_lock:
        _session_creds_store[session_id] = {
            "keycloak": dict(kc_creds or {}),
            "wazuh":    dict(wz_creds or {}),
        }


def _pop_session_secrets(session_id: int) -> dict:
    """_run_collectors 가 호출. 메모리에서 자격을 꺼내고 즉시 삭제."""
    with _session_creds_lock:
        return _session_creds_store.pop(session_id, {}) or {}


def _selected_tools_set(session: DiagnosisSession) -> set[str]:
    """세션에 저장된 selected_tools에서 활성화된 도구만 추출."""
    st = session.selected_tools or {}
    if not isinstance(st, dict):
        return set()
    return {t for t, v in st.items() if v and t in ALL_TOOLS}


def _expected_auto_count(db: Session, tools: set[str]) -> int:
    """선택된 도구의 collector 매핑에 등록된 item_id 중 DB에 실재하는 항목 수.

    DB의 tool 컬럼 기준이 아니라 실제 dispatch mapping 기반으로 계산해야
    collector가 처리하지 않는 항목까지 expected에 포함되는 불일치를 피한다.
    """
    if not tools:
        return 0
    item_ids: set[str] = set()
    for tool in tools:
        mapping_fn = _TOOL_DISPATCH.get(tool, (None, False))[0]
        if mapping_fn is None:
            continue
        try:
            for _fn, item_id, _maturity in mapping_fn():
                item_ids.add(item_id)
        except Exception as exc:
            logger.warning("[expected_count] %s mapping failed: %s", tool, exc)
    if not item_ids:
        return 0
    return db.query(func.count(Checklist.check_id)).filter(
        Checklist.item_id.in_(item_ids)
    ).scalar() or 0


# 위험 영역 코드/심각도 매핑 (failed item이 가장 많은 pillar 순서로 코드 부여)
_SEVERITY_BY_PILLAR = {
    "식별자 및 신원":         ("E001", "신원 위험 영역"),
    "기기 및 엔드포인트":     ("E002", "기기 위험 영역"),
    "네트워크":               ("E003", "네트워크 위험 영역"),
    "시스템":                 ("E004", "시스템 위험 영역"),
    "애플리케이션 및 워크로드": ("E005", "애플리케이션 위험 영역"),
    "데이터":                 ("E006", "데이터 위험 영역"),
}


def _build_session_errors(db: Session, session_id: int) -> list[dict]:
    """미충족·부분충족 결과를 pillar 단위로 묶어 위험 영역 카드용 errors를 생성한다."""
    rows = (
        db.query(DiagnosisResult, Checklist)
        .join(Checklist, DiagnosisResult.check_id == Checklist.check_id)
        .filter(
            DiagnosisResult.session_id == session_id,
            DiagnosisResult.result.in_(("미충족", "부분충족")),
        )
        .all()
    )
    if not rows:
        return []

    by_pillar: dict[str, list] = {}
    for dr, cl in rows:
        by_pillar.setdefault(cl.pillar, []).append((dr, cl))

    errors = []
    for pillar, items in sorted(by_pillar.items(), key=lambda kv: -len(kv[1])):
        code, area = _SEVERITY_BY_PILLAR.get(pillar, ("E999", f"{pillar} 위험 영역"))
        miss_cnt = sum(1 for dr, _ in items if dr.result == "미충족")
        # 심각도: 미충족 비율 기반
        ratio = miss_cnt / max(len(items), 1)
        severity = "Critical" if ratio >= 0.5 else "High" if ratio >= 0.2 else "Medium"
        sample = items[0][1]
        errors.append({
            "code": code,
            "area": area,
            "pillar": pillar,
            "severity": severity,
            "message": f"{pillar} 영역에서 미충족·부분충족 {len(items)}건 발견 ({sample.item_name})",
            "fail_count": len(items),
            "miss_count": miss_cnt,
        })
    return errors


# ──────────────────────────────────────────────────────────────────────────────
# Pydantic Models
# ──────────────────────────────────────────────────────────────────────────────

class AssessmentRunRequest(BaseModel):
    org_name: str = "기본 조직"
    manager: str = "담당자"
    email: str = "manager@example.com"
    department: Optional[str] = None
    contact: Optional[str] = None
    org_type: Optional[str] = None       # 기관 유형 → Organization.industry
    infra_type: Optional[str] = None     # 인프라 유형 → Organization.cloud_type
    employees: Optional[int] = None
    servers: Optional[int] = None
    applications: Optional[int] = None
    note: Optional[str] = None
    pillar_scope: dict = Field(default_factory=dict)
    tool_scope: dict = Field(default_factory=dict)
    # 외부 스캔 대상 (사용자가 NewAssessment에서 직접 입력)
    # 예: {"nmap": "scanme.nmap.org", "trivy": "nginx:1.25"}
    scan_targets: dict = Field(default_factory=dict)
    # 사용자 환경 IdP/SIEM 자격 (NewAssessment에서 직접 입력)
    # 예: {"url": "https://idp.example.com", "admin_user": "...", "admin_pass": "..."}
    keycloak_creds: Optional[dict] = None
    # 예: {"url": "https://wazuh.example.com:55000", "api_user": "...", "api_pass": "..."}
    wazuh_creds: Optional[dict] = None


class WebhookResultItem(BaseModel):
    item_id: Optional[str] = None
    tool: Optional[str] = None
    metric_key: Optional[str] = None
    metric_value: Optional[float] = None
    threshold: Optional[float] = None
    raw_json: Optional[dict] = None
    error: Optional[str] = None
    result: Optional[str] = None


class WebhookPayload(BaseModel):
    session_id: int
    results: list[WebhookResultItem] = Field(default_factory=list)


class InternalCollectPayload(BaseModel):
    session_id: int


# ──────────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/run")
def run_assessment(
    req: AssessmentRunRequest,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # ── 입력 검증 (L) ────────────────────────────────────────────────────────
    # scan_targets / IdP·SIEM URL 은 wrapper / collector 로 그대로 전달되므로
    # 인자 주입 위험을 차단하기 위해 형식·메타문자 검증을 먼저 수행한다.
    try:
        scan_targets_in = dict(req.scan_targets or {})
        if "nmap" in scan_targets_in:
            scan_targets_in["nmap"] = validate_nmap_target(scan_targets_in.get("nmap") or "")
        if "trivy" in scan_targets_in:
            scan_targets_in["trivy"] = validate_trivy_image(scan_targets_in.get("trivy") or "")

        kc_in = dict(req.keycloak_creds or {}) if req.keycloak_creds else {}
        if kc_in:
            kc_in["url"] = validate_https_url(kc_in.get("url") or "", "keycloak_creds.url")
            kc_in["admin_user"] = validate_cred_field(
                kc_in.get("admin_user") or "", "keycloak_creds.admin_user"
            )
            kc_in["admin_pass"] = validate_cred_field(
                kc_in.get("admin_pass") or "", "keycloak_creds.admin_pass"
            )

        wz_in = dict(req.wazuh_creds or {}) if req.wazuh_creds else {}
        if wz_in:
            wz_in["url"] = validate_https_url(wz_in.get("url") or "", "wazuh_creds.url")
            wz_in["api_user"] = validate_cred_field(
                wz_in.get("api_user") or "", "wazuh_creds.api_user"
            )
            wz_in["api_pass"] = validate_cred_field(
                wz_in.get("api_pass") or "", "wazuh_creds.api_pass"
            )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Organization upsert + 메타데이터 갱신
    org = db.query(Organization).filter(Organization.name == req.org_name).first()
    if not org:
        org = Organization(name=req.org_name)
        db.add(org)
        db.flush()
    if req.org_type:   org.industry = req.org_type
    if req.infra_type: org.cloud_type = req.infra_type
    if req.employees is not None:
        org.size = (
            "대기업" if req.employees >= 1000 else
            "중견기업" if req.employees >= 300 else
            "중소기업"
        )

    # 진단 실행 주체는 X-Login-Id 로 식별된 current_user.
    # 과거에는 body.email 로 User upsert를 했지만 이제는 본인 또는 admin 만 실행 가능.
    # body.manager/email 은 표시용 메타데이터로만 사용 (User 행 변경 없음).
    if current_user.role != "admin" and current_user.org_id != org.org_id:
        raise HTTPException(
            status_code=403,
            detail="현재 사용자 소속 조직 외의 조직으로 진단을 실행할 수 없습니다.",
        )
    user = current_user
    # admin이 다른 조직에 대해 진단을 트리거할 때만 org 변경 허용.
    if current_user.role == "admin" and user.org_id != org.org_id:
        # admin 본인의 user 행은 그대로 두고, 진단 세션의 user_id 는 admin user 로 기록.
        pass

    # 도구 선택 정규화: 빈 dict → 전체 도구
    tool_scope = req.tool_scope or {t: True for t in ALL_TOOLS}
    selected_tools = sorted(t for t in ALL_TOOLS if tool_scope.get(t))

    # 세션 메타데이터
    # 자격 비밀번호(admin_pass/api_pass)는 DB에 저장하지 않는다.
    # URL/사용자명만 extra에 남기고, 비밀번호는 _store_session_secrets 로 메모리에만 보관.
    kc_meta = {k: v for k, v in kc_in.items() if k in ("url", "admin_user") and v}
    wz_meta = {k: v for k, v in wz_in.items() if k in ("url", "api_user") and v}
    extra = {
        "department":   req.department,
        "contact":      req.contact,
        "employees":    req.employees,
        "servers":      req.servers,
        "applications": req.applications,
        "note":         req.note,
        "pillar_scope": req.pillar_scope,
        "scan_targets": scan_targets_in,
        "keycloak_creds": kc_meta,
        "wazuh_creds":    wz_meta,
    }

    session = DiagnosisSession(
        org_id=org.org_id,
        user_id=user.user_id,
        status="진행 중",
        started_at=datetime.now(timezone.utc),
        selected_tools={t: True for t in selected_tools},
        extra=extra,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    # 자격 비밀번호는 메모리에만 보관 → _run_collectors 가 pop 해서 사용 후 폐기.
    _store_session_secrets(session.session_id, kc_in, wz_in)

    # Shuffle 경로 우선, 미설정 시 직접 collector 실행
    has_shuffle = bool(SHUFFLE_URL) and any(SHUFFLE_WF.get(t) for t in selected_tools)
    if has_shuffle:
        background.add_task(_trigger_shuffle_workflows, session.session_id, selected_tools)
    elif selected_tools:
        background.add_task(_run_collectors, session.session_id, list(selected_tools))

    return {
        "session_id":   session.session_id,
        "status":       "진행 중",
        "message":      "진단이 시작되었습니다.",
        "started_at":   session.started_at.isoformat(),
        "selected_tools": selected_tools,
    }


@router.get("/status/{session_id}")
def get_assessment_status(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """자동 수집 진행 상태를 반환한다 (프론트 폴링용).

    도구별 / 필러별 진행률까지 포함하여 InProgress 페이지의 시각화에 그대로 사용 가능.
    """
    session = _get_session_or_404(db, session_id)
    assert_session_access(current_user, session)
    tools = _selected_tools_set(session)

    # 도구별 mapping에서 expected item_id 모으기
    tool_item_ids: dict[str, set[str]] = {}
    for tool in tools:
        mapping_fn = _TOOL_DISPATCH.get(tool, (None, False))[0]
        if mapping_fn is None:
            continue
        try:
            tool_item_ids[tool] = {item_id for _fn, item_id, _m in mapping_fn()}
        except Exception as exc:
            logger.warning("[status] %s mapping failed: %s", tool, exc)
            tool_item_ids[tool] = set()

    all_item_ids = set().union(*tool_item_ids.values()) if tool_item_ids else set()
    auto_total = 0
    expected_checks: list[Checklist] = []
    if all_item_ids:
        expected_checks = db.query(Checklist).filter(
            Checklist.item_id.in_(all_item_ids)
        ).all()
        auto_total = len(expected_checks)

    # 실제 수집된 데이터 (도구별/check_id별)
    collected_rows = []
    if tools:
        collected_rows = db.query(CollectedData).filter(
            CollectedData.session_id == session_id,
            CollectedData.tool.in_(tools),
        ).all()
    collected_check_ids = {r.check_id for r in collected_rows}
    collected_by_tool: dict[str, int] = {}
    for r in collected_rows:
        collected_by_tool[r.tool] = collected_by_tool.get(r.tool, 0) + 1

    # 도구별 진행률
    tool_progress = []
    for tool in sorted(tools):
        expected = len(tool_item_ids.get(tool, set()))
        collected = collected_by_tool.get(tool, 0)
        tool_progress.append({
            "tool":      tool,
            "collected": collected,
            "expected":  expected,
        })

    # 필러별 진행률 (check_id 기준)
    pillar_expected: dict[str, int] = {}
    pillar_collected: dict[str, int] = {}
    for cl in expected_checks:
        pillar_expected[cl.pillar] = pillar_expected.get(cl.pillar, 0) + 1
        if cl.check_id in collected_check_ids:
            pillar_collected[cl.pillar] = pillar_collected.get(cl.pillar, 0) + 1
    pillar_progress = [
        {"pillar": p, "collected": pillar_collected.get(p, 0), "expected": exp}
        for p, exp in pillar_expected.items()
    ]

    collected_count = len(collected_check_ids)

    return {
        "session_id":      session_id,
        "status":          session.status,
        "selected_tools":  sorted(tools),
        "collected_count": collected_count,
        "auto_total":      auto_total,
        "collection_done": auto_total == 0 or collected_count >= auto_total,
        "tool_progress":   tool_progress,
        "pillar_progress": pillar_progress,
    }


@router.post("/finalize/{session_id}")
def finalize_assessment(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """수동 제출 완료 후 채점을 명시적으로 트리거한다."""
    session = _get_session_or_404(db, session_id)
    assert_session_access(current_user, session)
    if session.status == "완료":
        return {"status": "already_completed", "session_id": session_id}
    _trigger_scoring(session_id, db)
    return {"status": "ok", "session_id": session_id}


@router.post("/internal/collect/{tool}")
def internal_collect(
    tool: str,
    payload: InternalCollectPayload,
    background: BackgroundTasks,
    x_internal_token: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    """Shuffle 워크플로우가 호출하는 단일 도구 수집 엔드포인트."""
    _verify_internal_token(x_internal_token)
    if tool not in ALL_TOOLS:
        raise HTTPException(status_code=400, detail=f"지원하지 않는 도구입니다: {tool}")
    _get_session_or_404(db, payload.session_id)
    background.add_task(_run_collectors, payload.session_id, [tool])
    return {"status": "ok", "tool": tool, "session_id": payload.session_id}


@router.post("/webhook")
def assessment_webhook(
    payload: WebhookPayload,
    x_internal_token: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
):
    _verify_internal_token(x_internal_token)
    _get_session_or_404(db, payload.session_id)

    saved = 0
    for item in payload.results:
        if not item.item_id:
            continue
        checklist = db.query(Checklist).filter(Checklist.item_id == item.item_id).first()
        if not checklist:
            continue
        _upsert_collected(db, payload.session_id, checklist.check_id, item.dict())
        saved += 1

    db.commit()
    return {"status": "ok", "saved": saved}


@router.get("/result")
def get_result(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = _get_session_or_404(db, session_id)
    assert_session_access(current_user, session)
    org = db.query(Organization).filter(Organization.org_id == session.org_id).first()
    user = db.query(User).filter(User.user_id == session.user_id).first()

    maturity_rows = db.query(MaturityScore).filter(
        MaturityScore.session_id == session_id
    ).all()
    pillar_scores = [
        {
            "pillar": m.pillar,
            "score":  round(m.score, 4),
            "level":  determine_maturity_level(m.score),
            "pass_cnt": m.pass_cnt,
            "fail_cnt": m.fail_cnt,
            "na_cnt":   m.na_cnt,
        }
        for m in maturity_rows
    ]

    results = (
        db.query(DiagnosisResult, Checklist)
        .join(Checklist, DiagnosisResult.check_id == Checklist.check_id)
        .filter(DiagnosisResult.session_id == session_id)
        .all()
    )

    checklist_results = [
        {
            "id":             cl.item_id,
            "pillar":         cl.pillar,
            "category":       cl.category,
            "item":           cl.item_name,
            "maturity":       cl.maturity,
            "maturity_score": cl.maturity_score,
            "diagnosis_type": cl.diagnosis_type,
            "tool":           cl.tool,
            "result":         dr.result,
            "score":          dr.score or 0.0,
            "evidence":       cl.evidence or "",
            "criteria":       cl.criteria or "",
            "fields":         cl.fields or "",
            "logic":          cl.logic or "",
            "exceptions":     cl.exceptions or "",
            "recommendation": dr.recommendation or "",
        }
        for dr, cl in results
    ]

    return {
        "session": {
            "id":      session.session_id,
            "org":     org.name if org else "",
            "org_id":  session.org_id,
            "date":    session.started_at.isoformat() if session.started_at else "",
            "manager": user.name if user else "",
            "user_id": session.user_id,
            "level":   session.level or "",
            "status":  session.status,
            "score":   session.total_score,
            "errors":  _build_session_errors(db, session_id),
            "extra":   _mask_creds(session.extra or {}),
            "is_demo": bool(org and org.name == DEMO_ORG_NAME),
        },
        "pillar_scores":     pillar_scores,
        "overall_score":     session.total_score or 0.0,
        "overall_level":     session.level or determine_maturity_level(session.total_score or 0.0),
        "checklist_results": checklist_results,
    }


@router.get("/history")
def get_history(
    org_id: Optional[int] = None,
    org_name: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # 일반 사용자: 자기 조직 세션만. admin: 전체.
    query = db.query(DiagnosisSession)
    if current_user.role != "admin":
        query = query.filter(DiagnosisSession.org_id == current_user.org_id)
        # 일반 사용자가 다른 org_id/name 으로 필터하려 해도 자기 조직으로 강제.
        org_id = None
        org_name = None
    if org_id is not None:
        query = query.filter(DiagnosisSession.org_id == org_id)
    if org_name:
        org = db.query(Organization).filter(Organization.name == org_name).first()
        if not org:
            return {"sessions": [], "total": 0, "completed_count": 0}
        query = query.filter(DiagnosisSession.org_id == org.org_id)
    sessions = query.order_by(DiagnosisSession.started_at.desc()).all()

    org_ids = list({s.org_id for s in sessions})
    user_ids = list({s.user_id for s in sessions})
    orgs  = {o.org_id: o for o in db.query(Organization).filter(Organization.org_id.in_(org_ids)).all()}
    users = {u.user_id: u for u in db.query(User).filter(User.user_id.in_(user_ids)).all()}

    items = []
    completed_count = 0
    for s in sessions:
        if s.status == "완료":
            completed_count += 1
        org_obj = orgs.get(s.org_id)
        items.append({
            "id":      s.session_id,
            "org":     org_obj.name if org_obj else "",
            "org_id":  s.org_id,
            "date":    s.started_at.isoformat() if s.started_at else "",
            "manager": users.get(s.user_id).name if users.get(s.user_id) else "",
            "user_id": s.user_id,
            "level":   s.level or "",
            "status":  s.status,
            "score":   s.total_score,
            "errors":  _build_session_errors(db, s.session_id) if s.status == "완료" else [],
            "is_demo": bool(org_obj and org_obj.name == DEMO_ORG_NAME),
        })

    return {"sessions": items, "total": len(items), "completed_count": completed_count}


# ──────────────────────────────────────────────────────────────────────────────
# Background helpers
# ──────────────────────────────────────────────────────────────────────────────

def _upsert_collected(db: Session, session_id: int, check_id: int, item: dict):
    existing = db.query(CollectedData).filter(
        CollectedData.session_id == session_id,
        CollectedData.check_id == check_id,
    ).first()
    fields = dict(
        tool=item.get("tool") or "unknown",
        metric_key=item.get("metric_key") or "",
        metric_value=item.get("metric_value"),
        threshold=item.get("threshold"),
        raw_json=item.get("raw_json"),
        error=item.get("error"),
    )
    if existing:
        for k, v in fields.items():
            setattr(existing, k, v)
        existing.collected_at = datetime.now(timezone.utc)
    else:
        db.add(CollectedData(session_id=session_id, check_id=check_id, **fields))


def _trigger_shuffle_workflows(session_id: int, selected_tools: list[str]):
    """선택된 도구에 해당하는 Shuffle 워크플로우만 개별 트리거 (BackgroundTasks 내에서 동기 실행)."""
    payload = {
        "execution_argument": {
            "session_id":  session_id,
            "webhook_url": f"{SELF_BASE_URL}/api/assessment/webhook",
            "internal_token": INTERNAL_TOKEN or None,
        }
    }
    with httpx.Client(timeout=10.0) as client:
        for tool in selected_tools:
            wf_id = SHUFFLE_WF.get(tool, "")
            if not wf_id:
                continue
            try:
                client.post(
                    f"{SHUFFLE_URL}/api/v1/workflows/{wf_id}/execute",
                    headers={"Authorization": f"Bearer {SHUFFLE_API_KEY}"},
                    json=payload,
                )
            except Exception as exc:
                logger.warning("[shuffle] %s workflow trigger failed: %s", tool, exc)


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
    meta_rows = db.query(Checklist).filter(Checklist.check_id.in_(check_ids)).all() if check_ids else []
    checklist_meta = [
        {
            "check_id":       m.check_id,
            "item_id":        m.item_id,
            "pillar":         m.pillar,
            "maturity_score": m.maturity_score,
            "category":       m.category,
            "item_name":      m.item_name,
        }
        for m in meta_rows
    ]
    collected_results = [
        {
            "check_id":     r.check_id,
            "tool":         r.tool,
            "metric_key":   r.metric_key,
            "metric_value": r.metric_value,
            "threshold":    r.threshold,
            "raw_json":     r.raw_json,
            "error":        r.error,
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
                session_id=session_id, check_id=check_id,
                result=cr["result"], score=cr["score"],
                recommendation=cr.get("recommendation", ""),
            ))

    # 필러별 pass/fail/na 집계
    pillar_counts: dict = {}
    for cr in output["checklist_results"]:
        p = cr.get("pillar", "미분류")
        c = pillar_counts.setdefault(p, {"pass": 0, "fail": 0, "na": 0})
        r = cr.get("result", "")
        if r == "충족":               c["pass"] += 1
        elif r in ("미충족", "부분충족"): c["fail"] += 1
        else:                           c["na"]   += 1

    db.query(MaturityScore).filter(MaturityScore.session_id == session_id).delete()
    for pillar, score in output["pillar_scores"].items():
        c = pillar_counts.get(pillar, {"pass": 0, "fail": 0, "na": 0})
        db.add(MaturityScore(
            session_id=session_id, pillar=pillar, score=score,
            level=determine_maturity_level(score),
            pass_cnt=c["pass"], fail_cnt=c["fail"], na_cnt=c["na"],
        ))

    db.add(ScoreHistory(
        session_id=session_id, org_id=session.org_id,
        pillar_scores=output["pillar_scores"],
        total_score=output["total_score"],
        maturity_level=output["maturity_level"],
    ))

    session.status = "완료"
    session.level = output["maturity_level"]
    session.total_score = output["total_score"]
    session.completed_at = datetime.now(timezone.utc)
    db.commit()


# ──────────────────────────────────────────────────────────────────────────────
# Collector dispatcher (Shuffle 미사용 시 fallback)
# ──────────────────────────────────────────────────────────────────────────────

def _kc_mapping():
    from collectors.keycloak_collector import (
        collect_user_role_ratio, collect_idp_inventory, collect_client_group_inventory,
        collect_idp_registered, collect_active_idp_multi,
        collect_mfa_required, collect_otp_flow, collect_webauthn_status,
        collect_conditional_auth, collect_session_policy, collect_stepup_auth,
        collect_dynamic_auth_flow, collect_realm_count, collect_icam_inventory,
        collect_custom_auth_flow, collect_webauthn_users, collect_context_policy,
        collect_authz_clients, collect_rbac_policy, collect_session_policy_advanced,
        collect_aggregate_policy, collect_resource_permission, collect_password_policy,
        collect_role_change_events, collect_central_authz_policy, collect_abac_policy,
        collect_central_authz_ratio, collect_mfa_required_actions,
        collect_webauthn_credential_users, collect_sso_clients, collect_conditional_policy,
        collect_data_abac_policy,
    )
    return [
        (collect_user_role_ratio,           "1.1.1.2_1",  "초기"),
        (collect_idp_inventory,             "1.1.1.3_1",  "향상"),
        (collect_client_group_inventory,    "1.1.1.4_2",  "최적화"),
        (collect_idp_registered,            "1.1.2.1_1",  "기존"),
        (collect_active_idp_multi,          "1.1.2.2_1",  "초기"),
        (collect_mfa_required,              "1.2.1.1_1",  "기존"),
        (collect_otp_flow,                  "1.2.1.2_1",  "초기"),
        (collect_webauthn_status,           "1.2.1.2_2",  "초기"),
        (collect_conditional_auth,          "1.2.1.3_1",  "향상"),
        (collect_session_policy,            "1.2.2.1_1",  "기존"),
        (collect_stepup_auth,               "1.2.2.2_1",  "초기"),
        (collect_dynamic_auth_flow,         "1.2.2.3_1",  "향상"),
        (collect_realm_count,               "1.3.1.1_1",  "기존"),
        (collect_icam_inventory,            "1.3.1.2_1",  "초기"),
        (collect_custom_auth_flow,          "1.3.1.2_2",  "초기"),
        (collect_webauthn_users,            "1.3.2.2_1",  "향상"),
        (collect_context_policy,            "1.3.2.2_2",  "향상"),
        (collect_authz_clients,             "1.4.1.1_3",  "기존"),
        (collect_rbac_policy,               "1.4.1.2_1",  "초기"),
        (collect_session_policy_advanced,   "1.4.1.3_1",  "향상"),
        (collect_aggregate_policy,          "1.4.1.3_2",  "향상"),
        (collect_resource_permission,       "1.4.1.3_3",  "향상"),
        (collect_password_policy,           "1.4.2.2_1",  "초기"),
        (collect_role_change_events,        "1.4.2.2_2",  "초기"),
        (collect_central_authz_policy,      "4.1.1.2_1",  "초기"),
        (collect_abac_policy,               "4.1.1.3_1",  "향상"),
        (collect_central_authz_ratio,       "4.1.1.4_2",  "최적화"),
        (collect_mfa_required_actions,      "4.2.2.2_2",  "초기"),
        (collect_webauthn_credential_users, "4.2.2.3_1",  "향상"),
        (collect_sso_clients,               "4.3.1.3_5",  "향상"),
        (collect_conditional_policy,        "4.1.1.3_2",  "향상"),
        (collect_data_abac_policy,          "6.2.1.3_1",  "향상"),
    ]


def _wz_mapping():
    from collectors.wazuh_collector import (
        collect_auth_failure_alerts, collect_active_response_auth, collect_agent_sca_ratio,
        collect_sca_average, collect_high_risk_alerts, collect_behavior_alerts,
        collect_activity_rules, collect_privilege_change_alerts, collect_sca_compliance,
        collect_policy_violation_alerts, collect_sca_auto_remediation, collect_os_inventory,
        collect_sca_access_control, collect_auto_block, collect_agent_registration,
        collect_agent_keepalive, collect_unauthorized_device_alerts,
        collect_vulnerability_summary, collect_realtime_monitoring, collect_os_distribution,
        collect_sca_policy_ratio, collect_continuous_monitoring, collect_auto_threat_response,
        collect_edr_agents, collect_threat_detection_alerts, collect_vuln_asset_list,
        collect_vuln_scan_ratio, collect_critical_unfixed_vulns,
        collect_segment_policy_alerts, collect_lateral_movement_alerts, collect_ids_alerts,
        collect_attack_response, collect_realtime_threat_alerts, collect_tls_cleartext_alerts,
        collect_backup_history, collect_agent_uptime, collect_policy_change_alerts,
        collect_privilege_escalation_alerts, collect_fim_status, collect_fim_collection_ratio,
        collect_dlp_alerts,
    )
    return [
        (collect_auth_failure_alerts,         "1.1.1.3_2",  "향상"),
        (collect_active_response_auth,        "1.2.1.4_1",  "최적화"),
        (collect_agent_sca_ratio,             "1.2.2.1_2",  "기존"),
        (collect_sca_average,                 "1.3.1.2_3",  "초기"),
        (collect_high_risk_alerts,            "1.3.1.4_2",  "최적화"),
        (collect_behavior_alerts,             "1.3.2.3_1",  "향상"),
        (collect_activity_rules,              "1.4.1.1_1",  "기존"),
        (collect_privilege_change_alerts,     "1.4.2.3_2",  "향상"),
        (collect_sca_compliance,              "2.1.1.2_1",  "초기"),
        (collect_policy_violation_alerts,     "2.1.1.2_2",  "초기"),
        (collect_sca_auto_remediation,        "2.1.1.3_1",  "향상"),
        (collect_sca_access_control,          "2.1.1.3_2",  "향상"),
        (collect_os_inventory,                "2.2.1.1_1",  "기존"),
        (collect_auto_block,                  "2.2.1.4_1",  "최적화"),
        (collect_agent_registration,          "2.3.1.1_2",  "기존"),
        (collect_agent_keepalive,             "2.3.1.2_1",  "초기"),
        (collect_unauthorized_device_alerts,  "2.3.1.3_1",  "향상"),
        (collect_vulnerability_summary,       "2.3.1.3_2",  "향상"),
        (collect_realtime_monitoring,         "2.3.1.4_1",  "최적화"),
        (collect_os_distribution,             "2.3.2.1_1",  "기존"),
        (collect_sca_policy_ratio,            "2.3.2.1_2",  "기존"),
        (collect_continuous_monitoring,       "2.3.2.2_2",  "초기"),
        (collect_auto_threat_response,        "2.3.2.4_1",  "최적화"),
        (collect_edr_agents,                  "2.4.1.1_1",  "기존"),
        (collect_threat_detection_alerts,     "2.4.1.2_1",  "초기"),
        (collect_vuln_asset_list,             "2.4.2.1_2",  "기존"),
        (collect_vuln_scan_ratio,             "2.4.2.3_1",  "향상"),
        (collect_critical_unfixed_vulns,      "2.4.2.4_2",  "최적화"),
        (collect_segment_policy_alerts,       "3.1.1.2_1",  "초기"),
        (collect_lateral_movement_alerts,     "3.1.2.2_1",  "초기"),
        (collect_ids_alerts,                  "3.2.1.1_1",  "기존"),
        (collect_attack_response,             "3.2.1.2_1",  "초기"),
        (collect_realtime_threat_alerts,      "3.2.1.3_1",  "향상"),
        (collect_tls_cleartext_alerts,        "3.3.1.3_1",  "향상"),
        (collect_backup_history,              "3.5.1.1_2",  "기존"),
        (collect_agent_uptime,                "3.5.1.3_1",  "향상"),
        (collect_policy_change_alerts,        "4.1.1.2_3",  "초기"),
        (collect_privilege_escalation_alerts, "4.2.1.3_1",  "향상"),
        (collect_fim_status,                  "6.1.1.2_1",  "초기"),
        (collect_fim_collection_ratio,        "6.1.1.2_2",  "초기"),
        (collect_dlp_alerts,                  "6.5.1.2_1",  "초기"),
    ]


def _nm_mapping():
    from collectors.nmap_collector import (
        collect_host_discovery, collect_port_service_map, collect_subnet_topology,
        collect_subnet_traffic_map, collect_micro_segment_ports, collect_tls_ratio,
        collect_tls_services, collect_tls_advanced, collect_app_traffic_map,
        collect_network_redundancy, collect_subnet_segmentation, collect_perimeter_model,
        collect_system_subnet_separation, collect_vpn_ports,
    )
    return [
        (collect_host_discovery,           "2.1.1.1_1",  "기존"),
        (collect_port_service_map,         "2.4.2.2_1",  "초기"),
        (collect_subnet_topology,          "3.1.1.1_1",  "기존"),
        (collect_subnet_traffic_map,       "3.1.1.1_2",  "기존"),
        (collect_micro_segment_ports,      "3.1.2.1_1",  "기존"),
        (collect_tls_ratio,                "3.3.1.1_1",  "기존"),
        (collect_tls_services,             "3.3.1.1_2",  "기존"),
        (collect_tls_advanced,             "3.3.1.3_2",  "향상"),
        (collect_app_traffic_map,          "3.4.1.2_1",  "초기"),
        (collect_network_redundancy,       "3.5.1.2_3",  "초기"),
        (collect_subnet_segmentation,      "4.3.1.1_1",  "기존"),
        (collect_perimeter_model,          "4.3.1.1_2",  "기존"),
        (collect_system_subnet_separation, "4.3.1.2_1",  "초기"),
        (collect_vpn_ports,                "5.3.1.1_1",  "기존"),
    ]


def _tr_mapping():
    from collectors.trivy_collector import (
        collect_image_scan, collect_cicd_scan_ratio, collect_integrity_check,
        collect_policy_compliance_scan, collect_full_component_scan, collect_fs_scan,
        collect_sbom, collect_dependency_scan, collect_sbom_full,
        collect_risk_scan, collect_supply_chain_scan,
    )
    return [
        (collect_image_scan,             "5.4.1.2_2",  "초기"),
        (collect_cicd_scan_ratio,        "5.4.1.2_3",  "초기"),
        (collect_integrity_check,        "5.4.1.2_4",  "초기"),
        (collect_policy_compliance_scan, "5.4.1.3_2",  "향상"),
        (collect_full_component_scan,    "5.4.1.3_4",  "향상"),
        (collect_fs_scan,                "5.5.1.2_1",  "초기"),
        (collect_sbom,                   "5.5.1.2_3",  "초기"),
        (collect_dependency_scan,        "5.5.1.3_1",  "향상"),
        (collect_sbom_full,              "5.5.1.3_2",  "향상"),
        (collect_risk_scan,              "5.5.2.2_1",  "초기"),
        (collect_supply_chain_scan,      "5.5.2.3_1",  "향상"),
    ]


# ──────────────────────────────────────────────────────────────────────────────
# Auto-discovery: collector 모듈의 collect_* 함수 docstring에서 item_id 추출
# 명시 매핑(_kc_mapping 등)에 이미 등록된 함수/item_id는 자동 추가에서 제외한다.
# ──────────────────────────────────────────────────────────────────────────────

import importlib
import re as _re

_MATURITY_BY_LEVEL = {1: "기존", 2: "초기", 3: "향상", 4: "최적화"}
_DOC_ITEM_ID_RE = _re.compile(r"\s*(\d+\.\d+\.\d+\.\d+_\d+)\b")


def _maturity_from_item_id(item_id: str) -> Optional[str]:
    head = item_id.split("_", 1)[0]
    parts = head.split(".")
    if len(parts) != 4:
        return None
    try:
        return _MATURITY_BY_LEVEL.get(int(parts[3]))
    except ValueError:
        return None


def _autodiscover(module_name: str, base: list) -> list:
    """기존 explicit mapping(base)에 docstring 기반 자동 매핑을 합쳐서 반환."""
    try:
        mod = importlib.import_module(module_name)
    except Exception as exc:
        logger.warning("[autodiscover] %s import failed: %s", module_name, exc)
        return base

    base_fns = {fn.__name__ for fn, _, _ in base}
    base_iids = {iid for _, iid, _ in base}
    extra: list = []
    for name in dir(mod):
        if not name.startswith("collect_") or name in base_fns:
            continue
        fn = getattr(mod, name, None)
        if not callable(fn):
            continue
        doc = (fn.__doc__ or "")
        m = _DOC_ITEM_ID_RE.match(doc)
        if not m:
            continue
        item_id = m.group(1)
        if item_id in base_iids:
            continue  # 명시 매핑이 우선
        maturity = _maturity_from_item_id(item_id)
        if not maturity:
            continue
        extra.append((fn, item_id, maturity))
    return base + extra


_TOOL_MODULE = {
    "keycloak": "collectors.keycloak_collector",
    "wazuh":    "collectors.wazuh_collector",
    "nmap":     "collectors.nmap_collector",
    "trivy":    "collectors.trivy_collector",
}

# 명시 매핑 함수 캐시(원본 함수)
_BASE_MAPPING_FNS = {
    "keycloak": _kc_mapping,
    "wazuh":    _wz_mapping,
    "nmap":     _nm_mapping,
    "trivy":    _tr_mapping,
}


def _full_mapping(tool: str) -> list:
    base_fn = _BASE_MAPPING_FNS.get(tool)
    if base_fn is None:
        return []
    try:
        base = base_fn()
    except Exception as exc:
        logger.warning("[mapping] %s base load failed: %s", tool, exc)
        base = []
    module_name = _TOOL_MODULE.get(tool)
    if not module_name:
        return base
    return _autodiscover(module_name, base)


# 외부 노출용: 기존 _TOOL_DISPATCH 구조 유지 (mapping_fn, takes_args)
_TOOL_DISPATCH = {
    "keycloak": (lambda: _full_mapping("keycloak"), True),
    "wazuh":    (lambda: _full_mapping("wazuh"),    True),
    "nmap":     (lambda: _full_mapping("nmap"),     False),
    "trivy":    (lambda: _full_mapping("trivy"),    False),
}


# ──────────────────────────────────────────────────────────────────────────────
# 도구 가용성 프리체크 — 외부 도구가 응답하지 않으면 collector 호출 스킵하고
# 해당 도구의 모든 매핑을 '평가불가'로 일괄 처리한다.
# ──────────────────────────────────────────────────────────────────────────────

import socket
from urllib.parse import urlparse


def _probe_tcp(url_or_hostport: str, timeout: float = 2.0) -> Optional[str]:
    """URL 또는 host:port를 TCP connect로 확인. 성공 시 None, 실패 시 에러 메시지."""
    try:
        if "://" in url_or_hostport:
            parsed = urlparse(url_or_hostport)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        else:
            host, _, port_s = url_or_hostport.partition(":")
            port = int(port_s) if port_s else 80
        if not host:
            return "host 정보 없음"
        with socket.create_connection((host, int(port)), timeout=timeout):
            return None
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


# docker-compose 번들 환경의 placeholder 값들. 사용자가 .env를 운영 환경으로
# 덮어쓰지 않으면 collector는 의미 없는 데이터만 긁기 때문에 미연결로 간주한다.
# ZTA_FORCE_REAL_COLLECTION=true 설정 시 이 검사는 건너뛴다.
_PLACEHOLDER_HOSTS = {"keycloak", "wazuh", "localhost", "127.0.0.1"}
_PLACEHOLDER_TARGETS = {"127.0.0.1", "localhost", "", ".", "nginx:latest"}


def _is_placeholder_url(url: str) -> bool:
    if not url:
        return True
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return True
    return host in _PLACEHOLDER_HOSTS


def _tool_configured(tool: str) -> Optional[str]:
    """진단 대상이 실제로 설정됐는지 확인. None=정상, str=미설정 사유."""
    if os.getenv("ZTA_FORCE_REAL_COLLECTION", "").lower() == "true":
        return None  # 강제 우회

    if tool == "keycloak":
        url = os.getenv("KEYCLOAK_URL", "")
        admin_user = os.getenv("KEYCLOAK_ADMIN_USER", "")
        admin_pass = os.getenv("KEYCLOAK_ADMIN_PASS", "")
        if _is_placeholder_url(url):
            return "Keycloak 미연결: KEYCLOAK_URL이 번들 placeholder. .env에 운영 IDP 주소 설정 필요"
        if not admin_user or not admin_pass:
            return "Keycloak 미연결: KEYCLOAK_ADMIN_USER/PASS 미설정"
        return None

    if tool == "wazuh":
        url = os.getenv("WAZUH_API_URL", "")
        api_user = os.getenv("WAZUH_API_USER", "")
        api_pass = os.getenv("WAZUH_API_PASS", "")
        if _is_placeholder_url(url):
            return "Wazuh 미연결: WAZUH_API_URL이 번들 placeholder. .env에 운영 SIEM 주소 설정 필요"
        if not api_user or not api_pass:
            return "Wazuh 미연결: WAZUH_API_USER/PASS 미설정"
        return None

    if tool == "nmap":
        target = os.getenv("NMAP_TARGET", "").strip()
        if target in _PLACEHOLDER_TARGETS:
            return f"Nmap 미연결: NMAP_TARGET이 placeholder('{target or 'empty'}'). .env에 진단 대상 네트워크/호스트 설정 필요"
        return None

    if tool == "trivy":
        target = os.getenv("TRIVY_TARGET", "").strip()
        if target in _PLACEHOLDER_TARGETS:
            return f"Trivy 미연결: TRIVY_TARGET이 placeholder('{target or 'empty'}'). .env에 진단 대상 이미지/경로 설정 필요"
        return None

    return f"unknown tool: {tool}"


def _tool_health(tool: str) -> Optional[str]:
    """도구 가용성 + 설정 체크. None=정상, str=에러 메시지.

    1) 진단 대상이 설정됐는지(_tool_configured) — placeholder/기본값이면 미연결.
    2) 설정됐다면 실제 TCP 연결 가능 여부 확인.
    """
    config_err = _tool_configured(tool)
    if config_err:
        return config_err

    if tool == "keycloak":
        return _probe_tcp(os.getenv("KEYCLOAK_URL", "http://keycloak:8080"))
    if tool == "wazuh":
        return _probe_tcp(os.getenv("WAZUH_API_URL", "https://wazuh:55000"))
    if tool == "nmap":
        return _probe_tcp(os.getenv("NMAP_WRAPPER_URL", "http://localhost:8001"))
    if tool == "trivy":
        return _probe_tcp(os.getenv("TRIVY_WRAPPER_URL", "http://localhost:8002"))
    return f"unknown tool: {tool}"


def _unavailable_result(tool: str, item_id: str, maturity: str, error_msg: str) -> dict:
    return {
        "item_id":      item_id,
        "maturity":     maturity,
        "tool":         tool,
        "result":       "평가불가",
        "metric_key":   "tool_unavailable",
        "metric_value": 0.0,
        "threshold":    1.0,
        "raw_json":     {},
        "error":        error_msg,
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }


def _safe_call(fn, item_id: str, maturity: str, takes_args: bool, tool_name: str) -> dict:
    try:
        return fn(item_id, maturity) if takes_args else fn()
    except Exception as exc:
        logger.warning("[collector] %s(%s) failed: %s", tool_name, item_id, exc)
        return _unavailable_result(tool_name, item_id, maturity, str(exc))


# 동시 세션이 nmap/trivy의 모듈-전역 _current_target을 덮어쓰지 않도록 직렬화.
# 시연용 환경 기준이며, 대규모 동시 진단이 필요해지면 collector 시그니처에 target
# 인자를 정식으로 추가하는 리팩터링이 필요하다.
_collector_lock = threading.Lock()


def _run_collectors(session_id: int, tools: list[str]):
    """선택된 도구들로 collector 실행 후 결과를 DB에 직접 저장 (httpx 자기호출 없음).

    각 도구는 호출 전 _tool_health로 가용성을 확인한다. 도구가 닫혀있으면
    그 도구의 모든 매핑을 '평가불가'로 일괄 표시하고 함수 호출은 스킵한다.
    사용자가 nmap/trivy 스캔 대상 또는 Keycloak/Wazuh 자격을 직접 입력한
    경우 session.extra 의 해당 키를 각 collector 모듈 전역에 주입한다.
    """
    if not tools:
        return

    # 세션의 사용자 입력 조회.
    # - scan_targets / IdP·SIEM URL·user 등 비민감 정보 → DB extra 에서 로드.
    # - 자격 비밀번호(admin_pass/api_pass) → 메모리 dict 에서 pop (DB 평문 저장 금지).
    # 자격은 로깅에 절대 포함하지 않는다.
    scan_targets: dict = {}
    keycloak_creds: dict = {}
    wazuh_creds: dict = {}
    db_pre = SessionLocal()
    try:
        sess = db_pre.query(DiagnosisSession).filter(
            DiagnosisSession.session_id == session_id
        ).first()
        if sess and isinstance(sess.extra, dict):
            raw = sess.extra.get("scan_targets") or {}
            if isinstance(raw, dict):
                scan_targets = {k: (v or "").strip() for k, v in raw.items() if v}
            # extra 에는 URL/user 만 들어있다 (Phase 3 이후). 비번은 메모리에서 합칠 것.
            kc_meta = sess.extra.get("keycloak_creds") or {}
            if isinstance(kc_meta, dict):
                keycloak_creds = {k: v for k, v in kc_meta.items() if v}
            wz_meta = sess.extra.get("wazuh_creds") or {}
            if isinstance(wz_meta, dict):
                wazuh_creds = {k: v for k, v in wz_meta.items() if v}
    except Exception as exc:
        logger.warning("[collector] session lookup failed: %s", exc)
    finally:
        db_pre.close()

    # 메모리에 보관된 자격 비번 합류 (사용 후 폐기 보장)
    secrets_blob = _pop_session_secrets(session_id)
    kc_secret = secrets_blob.get("keycloak") if isinstance(secrets_blob, dict) else None
    wz_secret = secrets_blob.get("wazuh") if isinstance(secrets_blob, dict) else None
    if isinstance(kc_secret, dict):
        for k, v in kc_secret.items():
            if v:
                keycloak_creds[k] = v
    if isinstance(wz_secret, dict):
        for k, v in wz_secret.items():
            if v:
                wazuh_creds[k] = v

    with _collector_lock:
        results: list[dict] = []
        try:
            for tool in tools:
                if tool not in _TOOL_DISPATCH:
                    continue
                mapping_fn, takes_args = _TOOL_DISPATCH[tool]
                try:
                    mapping = mapping_fn()
                except Exception as exc:
                    logger.warning("[collector] %s mapping load failed: %s", tool, exc)
                    continue

                # 사용자 입력 target / 자격 우선. 모듈-전역에 주입.
                explicit_target = scan_targets.get(tool) if tool in ("nmap", "trivy") else None
                explicit_creds: Optional[dict] = None
                if tool == "nmap":
                    from collectors import nmap_collector as _nm
                    _nm.set_session_target(explicit_target)
                elif tool == "trivy":
                    from collectors import trivy_collector as _tr
                    _tr.set_session_target(explicit_target)
                elif tool == "keycloak":
                    from collectors import keycloak_collector as _kc
                    explicit_creds = keycloak_creds or None
                    _kc.set_session_creds(explicit_creds)
                elif tool == "wazuh":
                    from collectors import wazuh_collector as _wz
                    explicit_creds = wazuh_creds or None
                    _wz.set_session_creds(explicit_creds)

                # 가용성 체크:
                # - nmap/trivy: 사용자가 target을 직접 줬으면 wrapper TCP 도달성만 확인.
                # - keycloak/wazuh: 사용자가 URL을 직접 줬으면 그 URL TCP probe만 확인
                #   (placeholder 가드는 .env 디폴트값에만 의미가 있으므로 우회).
                if tool in ("nmap", "trivy") and explicit_target:
                    wrapper_env = "NMAP_WRAPPER_URL" if tool == "nmap" else "TRIVY_WRAPPER_URL"
                    health_err = _probe_tcp(os.getenv(wrapper_env, ""))
                elif tool in ("keycloak", "wazuh") and explicit_creds and explicit_creds.get("url"):
                    health_err = _probe_tcp(explicit_creds["url"])
                else:
                    health_err = _tool_health(tool)

                if health_err:
                    logger.info("[collector] %s unavailable (%s) → %d items 평가불가 처리",
                                tool, health_err, len(mapping))
                    for _fn, item_id, maturity in mapping:
                        results.append(_unavailable_result(tool, item_id, maturity, health_err))
                    continue

                for fn, item_id, maturity in mapping:
                    results.append(_safe_call(fn, item_id, maturity, takes_args, tool))
        finally:
            # 모듈-전역 target / creds 는 다음 세션에 누수되지 않도록 항상 해제.
            try:
                from collectors import nmap_collector as _nm
                _nm.set_session_target(None)
            except Exception:
                pass
            try:
                from collectors import trivy_collector as _tr
                _tr.set_session_target(None)
            except Exception:
                pass
            try:
                from collectors import keycloak_collector as _kc
                _kc.set_session_creds(None)
            except Exception:
                pass
            try:
                from collectors import wazuh_collector as _wz
                _wz.set_session_creds(None)
            except Exception:
                pass

        if not results:
            return

        db = SessionLocal()
        try:
            for item in results:
                item_id_str = item.get("item_id")
                if not item_id_str:
                    continue
                checklist = db.query(Checklist).filter(Checklist.item_id == item_id_str).first()
                if not checklist:
                    continue
                _upsert_collected(db, session_id, checklist.check_id, item)
            db.commit()
        except Exception as exc:
            db.rollback()
            logger.error("[collector] DB write failed: %s", exc)
        finally:
            db.close()
