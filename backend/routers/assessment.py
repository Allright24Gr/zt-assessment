from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Any, Optional
from datetime import datetime, timezone
import logging
import os
import threading
import time

from database import SessionLocal, get_db
from models import (
    DiagnosisSession, Checklist, CollectedData, Evidence,
    DiagnosisResult, MaturityScore, ScoreHistory, Organization, User,
    SharedResult, ScheduledAssessment,
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
    validate_trivy_target,
    validate_https_url,
    validate_cred_field,
    validate_web_probe_target,
    validate_supabase_ref,
    validate_supabase_pat,
    validate_jwt_field,
    validate_vercel_token,
    validate_vercel_id,
    validate_uuid_field,
)
from services.ocsf_transformer import build_session_ocsf
from services import cache as result_cache, config_store

logger = logging.getLogger(__name__)
router = APIRouter()

# seed_demo가 만드는 데모 조직의 정확한 이름. 결과/이력 응답에 is_demo 플래그로 노출.
DEMO_ORG_NAME = "데모_조직"

# 학생 프로젝트 — 라이선스 비용 없이 실제 검증 가능한 4개 오픈소스만 사용.
# IdP=Keycloak / SIEM=Wazuh / 외부 스캔=Nmap, Trivy.
ALL_TOOLS = (
    "keycloak",
    "wazuh",
    "nmap",
    "trivy",
    # 도구 무관 외부 probe — IdP/SIEM 제품 종류와 관계없이 공개 도메인 하나로 측정.
    # T-Markov(Google Workspace + Vercel + Railway, SIEM 없음) 같은 SaaS-only 환경에서도
    # 자동 진단 항목을 늘리기 위해 추가. OIDC/DNS/HTTP/TLS/CT log 5영역 24개 항목.
    "web_probe",
    # T-Markov 같은 Supabase + Vercel + Railway 스택 자동 진단 (IdP/배포/플랫폼).
    # supabase: IdP 카테고리 (Keycloak 대체) — profile_select.idp_type=supabase 일 때 활성.
    # vercel/railway: 배포 플랫폼 — tool_scope 에서 독립 토글.
    "supabase",
    "vercel",
    "railway",
)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

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
            for pw_field in ("admin_pass", "api_pass", "password"):
                if masked.get(pw_field):
                    masked[pw_field] = "***"
            safe[key] = masked
    # Supabase / Vercel / Railway 자격 (DB 평문 저장 금지 정책 + 응답 마스킹).
    for key in ("supabase_creds", "vercel_creds", "railway_creds"):
        val = safe.get(key)
        if isinstance(val, dict):
            masked = dict(val)
            for secret_field in ("pat", "service_role", "anon_key", "token"):
                if masked.get(secret_field):
                    masked[secret_field] = "***"
            safe[key] = masked
    return safe


def build_evaluation_meta(session: DiagnosisSession) -> dict:
    """Reporting/PDF 머리에 표기할 평가 메타데이터.

    SKT T-Markov 가이드 §3 §4 §7 §9 요구사항 — 평가 기준 시점·범위·승인기록·
    수행된 도구·제외된 도구를 한 곳에 노출. session.extra 와 selected_tools 를
    조합해 만든다. 자격 비밀번호는 절대 포함하지 않는다.
    """
    extra = session.extra if isinstance(session.extra, dict) else {}
    selected_map = session.selected_tools if isinstance(session.selected_tools, dict) else {}
    selected = sorted(t for t, v in selected_map.items() if v and t in ALL_TOOLS)
    excluded = sorted(t for t in ALL_TOOLS if t not in selected)

    scan_mode = (extra.get("scan_mode") or "demo").lower()
    profile_select = extra.get("profile_select") if isinstance(extra.get("profile_select"), dict) else {}
    scan_targets = extra.get("scan_targets") if isinstance(extra.get("scan_targets"), dict) else {}
    scan_consent = extra.get("scan_consent") if isinstance(extra.get("scan_consent"), dict) else {}

    # SKT 가이드 §3 평가 착수 전 확정사항 4종
    eval_version = extra.get("evaluation_version") if isinstance(extra.get("evaluation_version"), dict) else {}
    scope_assets = extra.get("evaluation_scope_assets") if isinstance(extra.get("evaluation_scope_assets"), list) else []
    data_class = extra.get("data_classifications") if isinstance(extra.get("data_classifications"), list) else []
    reviewers = extra.get("reviewers") if isinstance(extra.get("reviewers"), dict) else {}

    return {
        "scan_mode":      scan_mode,        # "demo" | "live"
        "started_at":     session.started_at.isoformat() if session.started_at else None,
        "completed_at":   session.completed_at.isoformat() if session.completed_at else None,
        "selected_tools": selected,
        "excluded_tools": excluded,
        "profile_select": {
            "idp_type":  profile_select.get("idp_type")  or "none",
            "siem_type": profile_select.get("siem_type") or "none",
        },
        "scan_targets":   {k: v for k, v in scan_targets.items() if v},
        "scan_consent":   {k: v for k, v in scan_consent.items() if v},  # 빈 키 제거
        # SKT 가이드 §3 평가 착수 전 확정사항
        "evaluation_version":      {k: v for k, v in eval_version.items() if v},
        "evaluation_scope_assets": scope_assets,
        "data_classifications":    data_class,
        "reviewers":               {k: v for k, v in reviewers.items() if v},
    }


# ─── 자격(비밀번호) 메모리 보관 ────────────────────────────────────────────────
# DB 평문 저장을 피하기 위해 세션 ID → 자격 dict 매핑을 메모리에만 보관한다.
# BackgroundTask(_run_collectors) 가 꺼내 쓰고 finally 에서 즉시 폐기.
# 서버 재시작/장애로 진단이 처리 전에 끊기면 자격은 사라지며 사용자가 재실행해야 한다.
_session_creds_lock = threading.Lock()
_session_creds_store: dict[int, dict] = {}


def _store_session_secrets(
    session_id: int,
    kc_creds: dict,
    wz_creds: dict,
    sb_creds: Optional[dict] = None,
    vc_creds: Optional[dict] = None,
    rw_creds: Optional[dict] = None,
) -> None:
    """run_assessment 가 호출. {} 가 들어와도 일관성 위해 키는 항상 생성.

    Supabase/Vercel/Railway 자격(토큰/PAT/JWT)도 DB 평문 저장 금지 정책에 따라
    메모리 dict 로만 보관한다. BackgroundTask 가 사용 후 즉시 폐기.
    """
    with _session_creds_lock:
        _session_creds_store[session_id] = {
            "keycloak": dict(kc_creds or {}),
            "wazuh":    dict(wz_creds or {}),
            "supabase": dict(sb_creds or {}),
            "vercel":   dict(vc_creds or {}),
            "railway":  dict(rw_creds or {}),
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

class ProfileSelect(BaseModel):
    """Step 0 사전 환경 프로파일링 — 사용자 환경의 IdP/SIEM/엔드포인트 종류.

    4개 오픈소스 도구만 지원 (학생 프로젝트, 라이선스 비용 0).
    값에 따라 _resolve_supported_tools 가 tool_scope 를 자동 보정한다.
    예: idp_type='keycloak' → keycloak 매핑 활성.
         idp_type='none' / 기타 → 자동 항목 수동 폴백.

    SKT XDR 명세 §6 "확인 필요 사항" 흡수 4개 항목:
      windows_audit_policy_enabled — 'yes'|'no'|'unknown'. Security 채널 4688/4697/4720
        등 emit 가능 여부. Wazuh Windows 룰 평가 가능성을 좌우한다.
      sysmon_deployed — 'yes'|'no'|'unknown'. Sysmon EID 1·3·10·22·25 등 정밀 행위
        탐지 룰의 측정 가능성을 좌우한다.
      edr_product — 자유 텍스트. 기 운영 EDR 제품명/SKU (없으면 빈문자열). 신원·기기
        Pillar 가산 지표.
      ot_segment_present — 'yes'|'no'|'unknown'. OT 세그먼트 존재 여부. 'yes' 면
        해당 자산은 별도 트랙으로 분리(평가불가 사유 ot_segment_excluded).
    """
    idp_type:   Optional[str] = None  # keycloak | supabase | none
    siem_type:  Optional[str] = None  # wazuh | none
    windows_audit_policy_enabled: Optional[str] = None  # yes | no | unknown
    sysmon_deployed:              Optional[str] = None  # yes | no | unknown
    edr_product:                  Optional[str] = None  # 자유 텍스트
    ot_segment_present:           Optional[str] = None  # yes | no | unknown


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
    # Step 0 — 사용자 IdP/SIEM 환경. 미지원 도구는 자동 폴백.
    profile_select: Optional[ProfileSelect] = None
    # 외부 스캔 대상 (사용자가 NewAssessment에서 직접 입력)
    # 예: {"nmap": "scanme.nmap.org", "trivy": "nginx:1.25"}
    scan_targets: dict = Field(default_factory=dict)
    # 사용자 환경 IdP/SIEM 자격 (NewAssessment에서 직접 입력) — 4 도구만
    # 예: {"url": "https://idp.example.com", "admin_user": "...", "admin_pass": "..."}
    keycloak_creds: Optional[dict] = None
    # 예: {"url": "https://wazuh.example.com:55000", "api_user": "...", "api_pass": "..."}
    wazuh_creds: Optional[dict] = None
    # Supabase 자격 — Management PAT 권장. service_role/anon 은 보조.
    # 예: {"project_ref": "abc123...", "pat": "sbp_...",
    #      "service_role": "eyJ...", "anon_key": "eyJ..."}
    supabase_creds: Optional[dict] = None
    # Vercel 자격 — Personal/Team token + project/team id.
    # 예: {"token": "vcp_...", "team_id": "team_...", "project_id": "prj_..."}
    vercel_creds: Optional[dict] = None
    # Railway 자격 — API token + project/service/environment UUID.
    # 예: {"token": "uuid", "project_id": "uuid", "service_id": "uuid", "environment_id": "uuid"}
    railway_creds: Optional[dict] = None
    # 시연/실 스캔 토글 — "demo" 면 collector 실호출 없이 fake 결과 생성, "live" 면 실제 외부 호출.
    # frontend의 scanMode 토글(NewAssessment Step 1)에서 전달.
    scan_mode: Optional[str] = "demo"
    # 외부 스캔 승인 메타 (SKT 가이드 §3·§4). live + Nmap/Trivy 타겟 있을 때만 의미.
    # 예: {"approver": "최주용 팀장(SKT)", "scheduled_window": "2026-05-25 22:00~24:00 KST",
    #      "intensity": "standard", "exclude_paths": "/admin/*",
    #      "emergency_contact": "010-0000-0000 / oncall@example.com"}
    # session.extra["scan_consent"] 로 보관 → Reporting/PDF 머리에 표기.
    scan_consent: Optional[dict] = None
    # SKT 가이드 §3 평가 착수 전 확정사항 4종 — Reporting/PDF 첫 장에 평가 기준 시점 고정.
    # 예: {"frontend_deployment": "Vercel dpl_abc", "backend_deployment": "Railway xyz",
    #      "git_commit": "a156b40", "version_label": "2026-05-22 배포본"}
    evaluation_version: Optional[dict] = None
    # 예: [{"name": "Frontend URL", "value": "https://...", "included": true}, ...]
    #     기본 8개 항목 (Frontend URL/Backend API/Supabase/Notion/Drive/GitHub/CI·CD/운영자 계정)
    evaluation_scope_assets: Optional[list] = None
    # 예: [{"name": "영업 고객명", "sensitivity": "높음", "storage_location": "Supabase"}, ...]
    data_classifications: Optional[list] = None
    # 예: {"app_owner": "홍길동", "backend_owner": "...", "cloud_owner": "...", "security_reviewer": "..."}
    reviewers: Optional[dict] = None
    # 진단 시작 전 *수동 양식 미리 받기* 흐름용. True 면 세션만 만들고 collector 호출 안 함
    # (status='준비중'). 이후 POST /start/{id} 로 collector 실행 가능.
    skip_collector: Optional[bool] = False


# IdP/SIEM 사용자 선택 ↔ 자동 도구 매핑.
# 같은 카테고리 내 도구는 상호 배타 — 사용자가 선택한 1개만 활성.
_IDP_TOOL_OF = {
    "keycloak": "keycloak",
    "supabase": "supabase",
    # "none" / 미선택 → IdP 자동 도구 비활성 (수동 폴백)
}
_SIEM_TOOL_OF = {
    "wazuh": "wazuh",
    # "none" / 미선택 → SIEM 자동 도구 비활성 (수동 폴백)
}
_IDP_AUTO_TOOLS = {"keycloak", "supabase"}
_SIEM_AUTO_TOOLS = {"wazuh"}


def _resolve_supported_tools(profile_select: Optional[dict], requested: dict) -> dict:
    """tool_scope 와 사용자 환경(profile_select) 교집합으로 실제 실행할 도구 결정.

    카테고리 5종 — IdP / SIEM / EDR / Cloud / ZTNA. 각 카테고리에서 사용자가 선택한
    1개 도구만 활성, 나머지 같은 카테고리 자동 도구는 비활성. 미선택('none' 또는 미지정)
    이면 그 카테고리 자동 도구 전부 비활성 (manual.py /items 가 수동 폴백 노출).
    """
    if not requested:
        requested = {t: True for t in ALL_TOOLS}
    ps = profile_select or {}
    sel_idp  = (ps.get("idp_type")  or "").lower()
    sel_siem = (ps.get("siem_type") or "").lower()
    allowed_idp  = _IDP_TOOL_OF.get(sel_idp)
    allowed_siem = _SIEM_TOOL_OF.get(sel_siem)

    result: dict = {}
    for t in ALL_TOOLS:
        ok = bool(requested.get(t))
        if t in _IDP_AUTO_TOOLS  and sel_idp  and allowed_idp  != t: ok = False
        if t in _SIEM_AUTO_TOOLS and sel_siem and allowed_siem != t: ok = False
        result[t] = ok
    return result


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
            # image / github repo URL 둘 다 허용 (validate_trivy_target가 자동 판별)
            scan_targets_in["trivy"] = validate_trivy_target(scan_targets_in.get("trivy") or "")
        if "web_probe" in scan_targets_in:
            scan_targets_in["web_probe"] = validate_web_probe_target(scan_targets_in.get("web_probe") or "")

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

        # Supabase 자격 — Management PAT 권장. service_role/anon 은 보조 (JWT).
        sb_in = dict(req.supabase_creds or {}) if req.supabase_creds else {}
        if sb_in:
            sb_in["project_ref"] = validate_supabase_ref(sb_in.get("project_ref") or "")
            sb_in["pat"]          = validate_supabase_pat(sb_in.get("pat") or "")
            sb_in["service_role"] = validate_jwt_field(
                sb_in.get("service_role") or "", "supabase_creds.service_role"
            )
            sb_in["anon_key"]     = validate_jwt_field(
                sb_in.get("anon_key") or "", "supabase_creds.anon_key"
            )

        # Vercel 자격 — token + project/team id.
        vc_in = dict(req.vercel_creds or {}) if req.vercel_creds else {}
        if vc_in:
            vc_in["token"]      = validate_vercel_token(vc_in.get("token") or "")
            vc_in["team_id"]    = validate_vercel_id(vc_in.get("team_id") or "", "vercel_creds.team_id")
            vc_in["project_id"] = validate_vercel_id(
                vc_in.get("project_id") or "", "vercel_creds.project_id"
            )

        # Railway 자격 — UUID 토큰/ID.
        rw_in = dict(req.railway_creds or {}) if req.railway_creds else {}
        if rw_in:
            rw_in["token"]          = validate_uuid_field(rw_in.get("token") or "", "railway_creds.token")
            rw_in["project_id"]     = validate_uuid_field(
                rw_in.get("project_id") or "", "railway_creds.project_id"
            )
            rw_in["service_id"]     = validate_uuid_field(
                rw_in.get("service_id") or "", "railway_creds.service_id"
            )
            rw_in["environment_id"] = validate_uuid_field(
                rw_in.get("environment_id") or "", "railway_creds.environment_id"
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

    # 도구 선택 정규화: Step 0 profile_select 와 교집합 보정.
    profile_select_dict = req.profile_select.model_dump(exclude_none=True) if req.profile_select else {}
    resolved_scope = _resolve_supported_tools(profile_select_dict, req.tool_scope or {})
    selected_tools = sorted(t for t in ALL_TOOLS if resolved_scope.get(t))

    # live 모드 자격 미입력 가드 — 사용자가 실 스캔을 선택했는데 자격을 안 넣은 경우.
    # 데모(미지정 포함)는 가드 면제. 외부 스캔 도구(nmap/trivy)는 target 으로 검사.
    live_mode = (req.scan_mode or "demo").strip().lower() == "live"
    if live_mode:
        creds_required = {
            "keycloak":  bool(kc_in.get("url") and kc_in.get("admin_pass")),
            "wazuh":     bool(wz_in.get("url") and wz_in.get("api_pass")),
            "nmap":      bool((scan_targets_in.get("nmap") or "").strip()),
            "trivy":     bool((scan_targets_in.get("trivy") or "").strip()),
            # web_probe 는 별도 target 또는 nmap target 으로 폴백 → 둘 중 하나면 OK.
            "web_probe": bool(
                (scan_targets_in.get("web_probe") or "").strip()
                or (scan_targets_in.get("nmap") or "").strip()
            ),
            # Supabase: project_ref + (PAT or anon_key) 둘 다 있어야 동작.
            "supabase":  bool(sb_in.get("project_ref") and (sb_in.get("pat") or sb_in.get("anon_key"))),
            "vercel":    bool(vc_in.get("token")),
            "railway":   bool(rw_in.get("token")),
        }
        missing = [t for t in selected_tools if not creds_required.get(t, True)]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"실 스캔(live) 모드는 자격이 필요합니다. 누락: {', '.join(missing)}. "
                    f"자격을 입력하거나 데모 모드로 시작하세요."
                ),
            )

    # 세션 메타데이터
    # 자격 비밀번호(admin_pass/api_pass)는 DB에 저장하지 않는다.
    # URL/사용자명만 extra에 남기고, 비밀번호는 _store_session_secrets 로 메모리에만 보관.
    kc_meta = {k: v for k, v in kc_in.items() if k in ("url", "admin_user") and v}
    wz_meta = {k: v for k, v in wz_in.items() if k in ("url", "api_user") and v}
    # 새 도구들의 비민감 메타 (project_ref/team_id 등은 노출 OK, 토큰/PAT/key 는 메모리만).
    sb_meta = {k: v for k, v in sb_in.items() if k in ("project_ref",) and v}
    vc_meta = {k: v for k, v in vc_in.items() if k in ("team_id", "project_id") and v}
    rw_meta = {k: v for k, v in rw_in.items()
               if k in ("project_id", "service_id", "environment_id") and v}
    # scan_mode 정규화. frontend의 demo/live 토글. 미지정 시 안전한 demo.
    scan_mode = (req.scan_mode or "demo").strip().lower()
    if scan_mode not in ("demo", "live"):
        scan_mode = "demo"

    # 외부 스캔 승인 메타 — 허용 키만 추리고 문자열 trim. intensity 는 화이트리스트.
    sc_in = req.scan_consent if isinstance(req.scan_consent, dict) else {}
    sc_meta: dict = {}
    for _k in ("approver", "scheduled_window", "exclude_paths", "emergency_contact"):
        _v = sc_in.get(_k)
        if isinstance(_v, str) and _v.strip():
            sc_meta[_k] = _v.strip()[:300]  # 과도한 길이 방지
    _intensity = (sc_in.get("intensity") or "").strip().lower()
    if _intensity in ("light", "standard"):
        sc_meta["intensity"] = _intensity

    # SKT 가이드 §3 평가 착수 전 확정사항 — 4 카드 정제.
    # (1) 평가 대상 버전
    ev_in = req.evaluation_version if isinstance(req.evaluation_version, dict) else {}
    ev_meta: dict = {}
    for _k in ("frontend_deployment", "backend_deployment", "git_commit", "version_label"):
        _v = ev_in.get(_k)
        if isinstance(_v, str) and _v.strip():
            ev_meta[_k] = _v.strip()[:200]

    # (2) 평가 범위 자산 목록
    sa_in = req.evaluation_scope_assets if isinstance(req.evaluation_scope_assets, list) else []
    sa_meta: list = []
    for _row in sa_in[:30]:  # 최대 30개 자산
        if not isinstance(_row, dict):
            continue
        _name = (_row.get("name") or "").strip()[:80]
        _value = (_row.get("value") or "").strip()[:300]
        _included = bool(_row.get("included", True))
        if _name and _value:
            sa_meta.append({"name": _name, "value": _value, "included": _included})

    # (3) 데이터 등급 분류
    dc_in = req.data_classifications if isinstance(req.data_classifications, list) else []
    dc_meta: list = []
    for _row in dc_in[:30]:
        if not isinstance(_row, dict):
            continue
        _name = (_row.get("name") or "").strip()[:80]
        _sens = (_row.get("sensitivity") or "").strip()
        _loc = (_row.get("storage_location") or "").strip()[:200]
        if _name and _sens in ("낮음", "중간", "높음"):
            dc_meta.append({"name": _name, "sensitivity": _sens, "storage_location": _loc})

    # (4) 판정자 4역할
    rv_in = req.reviewers if isinstance(req.reviewers, dict) else {}
    rv_meta: dict = {}
    for _k in ("app_owner", "backend_owner", "cloud_owner", "security_reviewer"):
        _v = rv_in.get(_k)
        if isinstance(_v, str) and _v.strip():
            rv_meta[_k] = _v.strip()[:80]

    extra = {
        "department":   req.department,
        "contact":      req.contact,
        "employees":    req.employees,
        "servers":      req.servers,
        "applications": req.applications,
        "note":         req.note,
        "pillar_scope": req.pillar_scope,
        "scan_mode":    scan_mode,
        "scan_targets": scan_targets_in,
        "scan_consent": sc_meta,
        "keycloak_creds": kc_meta,
        "wazuh_creds":    wz_meta,
        "supabase_creds": sb_meta,
        "vercel_creds":   vc_meta,
        "railway_creds":  rw_meta,
        # Step 0 결과 — manual.py /items 가 폴백 항목 산출에 사용
        "profile_select": profile_select_dict,
        # SKT 가이드 §3 평가 착수 전 확정사항 4종
        "evaluation_version":      ev_meta,
        "evaluation_scope_assets": sa_meta,
        "data_classifications":    dc_meta,
        "reviewers":               rv_meta,
    }

    # skip_collector=True 면 세션만 만들고 collector 안 돌림. 사용자가 양식 미리 받아
    # 채워서 업로드한 뒤 POST /start/{session_id} 로 진단 시작.
    initial_status = "준비중" if req.skip_collector else "진행 중"
    session = DiagnosisSession(
        org_id=org.org_id,
        user_id=user.user_id,
        status=initial_status,
        started_at=datetime.now(timezone.utc),
        selected_tools={t: True for t in selected_tools},
        extra=extra,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    # 자격 비밀번호/토큰은 메모리에만 보관 → _run_collectors 가 pop 해서 사용 후 폐기.
    _store_session_secrets(session.session_id, kc_in, wz_in,
                           sb_creds=sb_in, vc_creds=vc_in, rw_creds=rw_in)

    if not req.skip_collector:
        if selected_tools:
            background.add_task(_run_collectors, session.session_id, list(selected_tools))
        message = "진단이 시작되었습니다."
    else:
        message = "세션이 준비되었습니다. 양식 작성 후 진단을 시작하세요."

    return {
        "session_id":   session.session_id,
        "status":       initial_status,
        "message":      message,
        "started_at":   session.started_at.isoformat(),
        "selected_tools": selected_tools,
    }


@router.post("/start/{session_id}")
def start_prepared_assessment(
    session_id: int,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """준비중 세션의 자동 collector 를 시작한다.

    POST /run + skip_collector=True 로 미리 만들어둔 세션에 대해 호출.
    수동 양식 채워 업로드 후 [진단 시작] 누르면 frontend 가 이걸 호출.
    """
    session = _get_session_or_404(db, session_id)
    assert_session_access(current_user, session)

    if session.status not in ("준비중", "진행 중"):
        # 완료/실패 세션은 재시작 불가
        raise HTTPException(status_code=400, detail=f"세션이 시작 가능한 상태가 아닙니다 (현재: {session.status})")

    # 이미 진행 중이면 멱등 — 같은 응답
    if session.status == "진행 중":
        return {
            "session_id":   session.session_id,
            "status":       "진행 중",
            "message":      "이미 진단이 시작되어 있습니다.",
            "started_at":   session.started_at.isoformat() if session.started_at else None,
        }

    session.status = "진행 중"
    session.started_at = datetime.now(timezone.utc)
    db.commit()

    selected_tools = sorted(_selected_tools_set(session))
    if selected_tools:
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
    """수동 제출 완료 후 채점을 명시적으로 트리거한다.

    수집 미완료 가드: selected_tools 의 expected 합과 실제 CollectedData 행 수를 비교.
    부족하면 409 — frontend 가 InProgress 폴링을 더 기다리도록 유도.
    """
    session = _get_session_or_404(db, session_id)
    assert_session_access(current_user, session)
    if session.status == "완료":
        return {"status": "already_completed", "session_id": session_id}

    # 수집 미완료 가드 — 데모 모드는 collector 완료 후 자동 채점되므로 일반적으로 여기 안 옴.
    # live 모드에서 사용자가 일찍 finalize 누른 경우만 막는다.
    # expected 는 unique item_id 기준 (다중 매핑 도구가 같은 item_id 에 매핑돼도 1개로 계산).
    # CollectedData 의 (session_id, check_id) 가 UNIQUE 이므로 다중 매핑은 덮어쓰기 발생 →
    # mapping entry 합으로 expected 를 계산하면 영구히 collected < expected 가 되어 409 무한.
    tools = sorted(_selected_tools_set(session))
    if tools:
        unique_iids: set[str] = set()
        for t in tools:
            try:
                for _fn, iid, _m in _full_mapping(t):
                    unique_iids.add(iid)
            except Exception:
                pass
        expected = len(unique_iids)
        if expected > 0:
            collected = db.query(CollectedData).filter(
                CollectedData.session_id == session_id
            ).count()
            if collected < expected:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"수집 진행 중입니다 ({collected}/{expected}). "
                        f"완료 후 다시 시도하세요."
                    ),
                )

    _trigger_scoring(session_id, db)
    return {"status": "ok", "session_id": session_id}


# ─── 목표 성숙도 (SFR-EVAL-004) / 소요시간 (MAR-017) / 캐시 버전 (MAR-016) ───────
_DEFAULT_TARGETS = {
    "식별자 및 신원":          3.5,
    "기기 및 엔드포인트":       3.5,
    "네트워크":                3.0,
    "시스템":                  3.5,
    "애플리케이션 및 워크로드":  3.5,
    "데이터":                  3.0,
}


def _org_target_map(db: Session, org_id: Optional[int]) -> dict[str, float]:
    """pillar → 목표 점수. 조직 설정이 없으면 기본 목표값."""
    out = dict(_DEFAULT_TARGETS)
    if org_id is None:
        return out
    from models import OrgTargetScore
    for r in db.query(OrgTargetScore).filter(OrgTargetScore.org_id == org_id).all():
        out[r.pillar] = r.target_score
    return out


def _session_cache_version(db: Session, session: DiagnosisSession) -> str:
    """결과 캐시 키 버전. 세션 상태·점수·조직 커스터마이징/목표 변경 시 자동 무효화."""
    from models import OrgChecklistOverride, OrgTargetScore
    parts = [
        str(session.status or ""),
        session.completed_at.isoformat() if session.completed_at else "none",
        str(session.total_score),
    ]
    ov_max = db.query(func.max(OrgChecklistOverride.updated_at)).filter(
        OrgChecklistOverride.org_id == session.org_id
    ).scalar()
    tg_max = db.query(func.max(OrgTargetScore.updated_at)).filter(
        OrgTargetScore.org_id == session.org_id
    ).scalar()
    parts.append(str(ov_max))
    parts.append(str(tg_max))
    return "|".join(parts)


def _session_duration(db: Session, session: DiagnosisSession) -> dict:
    """MAR-017: 평가 수행 소요시간 + SLA 충족 여부."""
    sla = config_store.get("assessment_sla_seconds", db)
    duration = None
    within = None
    if session.started_at and session.completed_at:
        try:
            duration = round((session.completed_at - session.started_at).total_seconds(), 1)
            within = duration <= sla
        except Exception:
            duration = None
    return {"duration_seconds": duration, "sla_seconds": sla, "within_sla": within}


@router.get("/result")
def get_result(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = _get_session_or_404(db, session_id)
    assert_session_access(current_user, session)

    # MAR-016: 세션이 바뀌지 않았으면 캐시된 결과 페이로드 재사용.
    cache_key = f"result:{session_id}:{_session_cache_version(db, session)}"
    cached = result_cache.get(cache_key)
    if cached is not None:
        return cached

    org = db.query(Organization).filter(Organization.org_id == session.org_id).first()
    user = db.query(User).filter(User.user_id == session.user_id).first()

    # SFR-CUS-001: 조직 설정에서 제외(disabled)된 항목은 결과 목록에서도 제외.
    overrides = _org_overrides(db, session.org_id)
    disabled_ids = {cid for cid, o in overrides.items() if not o["enabled"]}

    # SFR-EVAL-004: pillar 별 목표 점수 + gap(목표-현재).
    targets = _org_target_map(db, session.org_id)
    maturity_rows = db.query(MaturityScore).filter(
        MaturityScore.session_id == session_id
    ).all()
    pillar_scores = []
    for m in maturity_rows:
        t = targets.get(m.pillar)
        pillar_scores.append({
            "pillar": m.pillar,
            "score":  round(m.score, 4),
            "level":  determine_maturity_level(m.score),
            "pass_cnt": m.pass_cnt,
            "fail_cnt": m.fail_cnt,
            "na_cnt":   m.na_cnt,
            "target":   t,
            "gap":      round(m.score - t, 4) if t is not None else None,
        })

    results = (
        db.query(DiagnosisResult, Checklist)
        .join(Checklist, DiagnosisResult.check_id == Checklist.check_id)
        .filter(DiagnosisResult.session_id == session_id)
        .all()
    )

    # 평가불가 사유 코드(raw_json.reason_code/reason_label) — CollectedData 에서 조회.
    collected_rows = db.query(CollectedData).filter(
        CollectedData.session_id == session_id
    ).all()
    collected_by_check: dict[int, dict] = {}
    for r in collected_rows:
        if isinstance(r.raw_json, dict):
            collected_by_check[r.check_id] = r.raw_json

    checklist_results = []
    submitted_check_ids: set[int] = set()
    for dr, cl in results:
        if cl.check_id in disabled_ids:
            continue
        raw = collected_by_check.get(cl.check_id) or {}
        entry = {
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
            "question":       cl.question or "",
            "evidence":       cl.evidence or "",
            "criteria":       cl.criteria or "",
            "fields":         cl.fields or "",
            "logic":          cl.logic or "",
            "exceptions":     cl.exceptions or "",
            "recommendation": dr.recommendation or "",
        }
        # 평가불가 항목은 사유 코드/라벨을 표면 필드로 추가 노출 (frontend 툴팁용).
        if dr.result == "평가불가":
            rc = raw.get("reason_code")
            if rc:
                entry["unevaluable_reason_code"]  = rc
                entry["unevaluable_reason_label"] = raw.get("reason_label") or UNAVAILABLE_REASONS.get(rc, "")
        checklist_results.append(entry)
        submitted_check_ids.add(cl.check_id)

    # 수동 미제출·자동 미수집 항목도 "평가불가 (미제출)" 로 노출 — 가이드 §6
    # 정신에 맞춰 *진단 안 한 항목* 자체를 결과에서 빠뜨리지 않음.
    # pillar_scope 활성 Pillar 만 노출 (사용자가 진단 범위에서 선택하지 않은 Pillar 는 제외).
    # frontend PILLARS.key 는 "Identify/Device/Network/System/Application/Data" (영문 대문자).
    # 안전을 위해 소문자 변형도 같이 매핑.
    _PILLAR_KEY_TO_NAME = {
        "identify":    "식별자 및 신원",
        "identity":    "식별자 및 신원",
        "device":      "기기 및 엔드포인트",
        "network":     "네트워크",
        "system":      "시스템",
        "application": "애플리케이션 및 워크로드",
        "data":        "데이터",
    }
    extra_meta = session.extra if isinstance(session.extra, dict) else {}
    pillar_scope_dict = extra_meta.get("pillar_scope") if isinstance(extra_meta.get("pillar_scope"), dict) else {}
    if pillar_scope_dict:
        # key 는 대소문자 무시하고 lookup
        active_pillars: set = set()
        for k, v in pillar_scope_dict.items():
            if not v:
                continue
            nm = _PILLAR_KEY_TO_NAME.get(str(k).lower())
            if nm:
                active_pillars.add(nm)
        if not active_pillars:
            # scope 입력은 있는데 매핑된 게 하나도 없으면 전체 활성으로 fallback
            active_pillars = set(_PILLAR_KEY_TO_NAME.values())
    else:
        active_pillars = set(_PILLAR_KEY_TO_NAME.values())

    all_checklists = db.query(Checklist).all()
    for cl in all_checklists:
        if cl.check_id in submitted_check_ids:
            continue
        if cl.check_id in disabled_ids:
            continue
        if cl.pillar not in active_pillars:
            continue
        is_manual = (cl.diagnosis_type or "").strip() == "수동" or (cl.tool or "").strip() == "수동"
        reason_code = "manual_not_submitted" if is_manual else "auto_not_collected"
        reason_label = "수동 진단 양식 미제출 — 양식 다운로드 후 작성·업로드 시 점수 산정" if is_manual \
                       else "자동 수집 결과 없음 — 도구 미연결 또는 진단 미실행"
        checklist_results.append({
            "id":             cl.item_id,
            "pillar":         cl.pillar,
            "category":       cl.category,
            "item":           cl.item_name,
            "maturity":       cl.maturity,
            "maturity_score": cl.maturity_score,
            "diagnosis_type": cl.diagnosis_type,
            "tool":           cl.tool,
            "result":         "평가불가",
            "score":          0.0,
            "question":       cl.question or "",
            "evidence":       cl.evidence or "",
            "criteria":       cl.criteria or "",
            "fields":         cl.fields or "",
            "logic":          cl.logic or "",
            "exceptions":     cl.exceptions or "",
            "recommendation": "",
            "unevaluable_reason_code":  reason_code,
            "unevaluable_reason_label": reason_label,
        })

    # SFR-EVAL-004: 전체 목표/gap 요약 (pillar 별 목표의 평균 대비 총점).
    present_targets = [ps["target"] for ps in pillar_scores if ps.get("target") is not None]
    overall_target = round(sum(present_targets) / len(present_targets), 4) if present_targets else None
    overall_gap = (
        round(overall_target - (session.total_score or 0.0), 4)
        if overall_target is not None else None
    )

    payload = {
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
            # MAR-017 소요시간/SLA
            **_session_duration(db, session),
        },
        "pillar_scores":     pillar_scores,
        "overall_score":     session.total_score or 0.0,
        "overall_level":     session.level or determine_maturity_level(session.total_score or 0.0),
        # SFR-EVAL-004 목표 대비
        "overall_target":    overall_target,
        "overall_gap":       overall_gap,
        "checklist_results": checklist_results,
        # SKT 가이드 §3 §4 §7 §9 — 보고서 머리 표기용 평가 메타
        "evaluation_meta":   build_evaluation_meta(session),
    }
    # MAR-016: 결과 캐시에 저장 (조직 커스터마이징/목표 변경 시 키가 바뀌어 자동 무효화).
    result_cache.set(cache_key, payload, ttl=config_store.get("result_cache_ttl", db))
    return payload


@router.get("/verify/{session_id}")
def verify_result_integrity(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """SER-010: 저장된 평가 결과의 무결성 검증.

    각 DiagnosisResult 의 (result, score) 로 row_hash 를 재계산해 저장값과 비교한다.
    DB 에서 결과를 몰래 수정하면 해시가 어긋나 tampered 로 탐지된다.
    """
    from services.integrity import result_row_hash
    session = _get_session_or_404(db, session_id)
    assert_session_access(current_user, session)
    rows = db.query(DiagnosisResult).filter(
        DiagnosisResult.session_id == session_id
    ).all()
    verified = 0
    unhashed = 0
    tampered: list[int] = []
    for r in rows:
        if not r.row_hash:
            unhashed += 1
            continue
        expected = result_row_hash(
            session_id=session_id, check_id=r.check_id,
            result=r.result, score=r.score,
        )
        if expected == r.row_hash:
            verified += 1
        else:
            tampered.append(r.check_id)
    return {
        "session_id":         session_id,
        "total":              len(rows),
        "verified":           verified,
        "unhashed":           unhashed,
        "tampered_count":     len(tampered),
        "tampered_check_ids": tampered[:50],
        "ok":                 len(tampered) == 0,
    }


@router.get("/ocsf/{session_id}")
def get_ocsf_events(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """세션의 수집 데이터를 OCSF 1.1.0 표준 이벤트로 변환해 반환.

    - 도구별 OCSF 클래스 매핑 (keycloak→Authentication, wazuh→Detection Finding,
      nmap→Network Activity, trivy→Vulnerability Finding)
    - 원본 raw_json 은 `raw_data` 필드에 손실 없이 보존
    - 별도 컬럼 추가 없이 조회 시점 변환 (read-side transformer)
    """
    session = _get_session_or_404(db, session_id)
    assert_session_access(current_user, session)

    rows = (
        db.query(CollectedData, Checklist, DiagnosisResult)
        .join(Checklist, CollectedData.check_id == Checklist.check_id)
        .outerjoin(
            DiagnosisResult,
            (DiagnosisResult.session_id == CollectedData.session_id)
            & (DiagnosisResult.check_id == CollectedData.check_id),
        )
        .filter(CollectedData.session_id == session_id)
        .order_by(CollectedData.tool, Checklist.item_id)
        .all()
    )
    return build_session_ocsf(session_id=session_id, rows=rows)


@router.get("/history")
def get_history(
    org_id: Optional[int] = None,
    org_name: Optional[str] = None,
    q: Optional[str] = None,           # SFR-IT-002 결과 검색 (조직/담당자/레벨/상태/ID)
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
            "duration_seconds": (
                round((s.completed_at - s.started_at).total_seconds(), 1)
                if s.started_at and s.completed_at else None
            ),
        })

    # SFR-IT-002: 검색어가 있으면 조직/담당자/레벨/상태/ID 전반에서 부분 일치 필터.
    if q and q.strip():
        needle = q.strip().lower()
        items = [
            it for it in items
            if needle in str(it["id"]).lower()
            or needle in (it["org"] or "").lower()
            or needle in (it["manager"] or "").lower()
            or needle in (it["level"] or "").lower()
            or needle in (it["status"] or "").lower()
        ]
        completed_count = sum(1 for it in items if it["status"] == "완료")

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


def _org_overrides(db: Session, org_id: Optional[int]) -> dict[int, dict]:
    """조직별 체크리스트 커스터마이징(SFR-CUS-001). check_id → {enabled, weight}.

    오버라이드가 없는 조직은 빈 dict → 기존 채점과 100% 동일.
    """
    if org_id is None:
        return {}
    from models import OrgChecklistOverride
    rows = db.query(OrgChecklistOverride).filter(
        OrgChecklistOverride.org_id == org_id
    ).all()
    return {r.check_id: {"enabled": bool(r.enabled), "weight": r.weight} for r in rows}


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
    # pillar 별 전체 체크리스트 항목 수 — scoring 의 커버리지 가드용.
    # (collected_results 에 없는 pillar 항목까지 분모에 포함해야 한 두 개만 충족돼도
    # 최적화로 잘못 잡히는 거짓 만점을 막을 수 있다.)
    # ★ pillar_scope 를 존중 — 사용자가 진단 범위에서 선택하지 않은 pillar 는 분모에 포함하지 않음.
    #   (그 pillar 는 아예 점수에서 제외되므로 커버리지 가드도 의미 없음.)
    extra_meta = session.extra if isinstance(session.extra, dict) else {}
    pillar_scope_dict = extra_meta.get("pillar_scope") if isinstance(extra_meta.get("pillar_scope"), dict) else {}
    _PILLAR_KEY_TO_NAME = {
        "identify":    "식별자 및 신원",
        "identity":    "식별자 및 신원",
        "device":      "기기 및 엔드포인트",
        "network":     "네트워크",
        "system":      "시스템",
        "application": "애플리케이션 및 워크로드",
        "data":        "데이터",
    }
    active_pillars_for_coverage: set[str] = set()
    if pillar_scope_dict:
        for k, v in pillar_scope_dict.items():
            if not v:
                continue
            nm = _PILLAR_KEY_TO_NAME.get(str(k).lower())
            if nm:
                active_pillars_for_coverage.add(nm)
    pillar_total_rows = db.query(Checklist.pillar, func.count(Checklist.check_id)).group_by(Checklist.pillar).all()
    if active_pillars_for_coverage:
        pillar_total_items = {p: int(c) for p, c in pillar_total_rows if p in active_pillars_for_coverage}
    else:
        pillar_total_items = {p: int(c) for p, c in pillar_total_rows}

    # SFR-CUS-001: 조직별 커스터마이징 적용 (비활성 항목 제외 + 가중치 오버라이드).
    overrides = _org_overrides(db, session.org_id)
    if overrides:
        disabled_ids = {cid for cid, o in overrides.items() if not o["enabled"]}
        if disabled_ids:
            collected_results = [
                r for r in collected_results if r.get("check_id") not in disabled_ids
            ]
            dis_rows = (
                db.query(Checklist.pillar, func.count(Checklist.check_id))
                .filter(Checklist.check_id.in_(disabled_ids))
                .group_by(Checklist.pillar)
                .all()
            )
            for p, c in dis_rows:
                if p in pillar_total_items:
                    pillar_total_items[p] = max(0, pillar_total_items[p] - int(c))
        for m in checklist_meta:
            ov = overrides.get(m.get("check_id"))
            if ov and ov.get("weight") is not None:
                m["maturity_score"] = ov["weight"]

    output = score_session(session_id, collected_results, checklist_meta,
                           pillar_total_items=pillar_total_items)

    from services.integrity import result_row_hash
    for cr in output["checklist_results"]:
        check_id = cr.get("check_id")
        if not check_id:
            continue
        # SER-010: 작성 시점 (result, score) 로 무결성 해시 고정.
        rh = result_row_hash(
            session_id=session_id, check_id=check_id,
            result=cr["result"], score=cr["score"],
        )
        existing = db.query(DiagnosisResult).filter(
            DiagnosisResult.session_id == session_id,
            DiagnosisResult.check_id == check_id,
        ).first()
        if existing:
            existing.result = cr["result"]
            existing.score = cr["score"]
            existing.recommendation = cr.get("recommendation", "")
            existing.row_hash = rh
        else:
            db.add(DiagnosisResult(
                session_id=session_id, check_id=check_id,
                result=cr["result"], score=cr["score"],
                recommendation=cr.get("recommendation", ""),
                row_hash=rh,
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
    # B-2 보완: 평가 가능 pillar + 전부 평가불가 pillar 모두 행 생성
    # (전부 평가불가는 score=0 + level="평가불가" 로 frontend 가 명시 표시 가능)
    pillar_unev = output.get("pillar_unevaluable", {})
    all_pillars = (
        set(output["pillar_scores"].keys())
        | set(pillar_unev.keys())
        | set(pillar_counts.keys())
    )
    for pillar in all_pillars:
        c = pillar_counts.get(pillar, {"pass": 0, "fail": 0, "na": 0})
        if pillar in output["pillar_scores"]:
            score = output["pillar_scores"][pillar]
            level = determine_maturity_level(score)
        else:
            score = 0.0
            level = "평가불가"
        db.add(MaturityScore(
            session_id=session_id, pillar=pillar, score=score, level=level,
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

    # MAR-016: 세션 결과가 바뀌었으니 캐시 무효화.
    try:
        from services import cache as _cache
        _cache.invalidate_prefix(f"result:{session_id}:")
    except Exception:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# Collector dispatcher
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
        # item_id 형식 X.X.X.{maturity_num}_N — 4번째 segment = 1(기존)/2(초기)/3(향상)/4(최적화)
        # 1.3.2.2_* 의 4번째 segment가 2 → maturity 는 "초기" (이전 "향상"은 매핑 버그)
        (collect_webauthn_users,            "1.3.2.2_1",  "초기"),
        (collect_context_policy,            "1.3.2.2_2",  "초기"),
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



def _wp_mapping():
    """web_probe base mapping. 모든 함수는 docstring autodiscover 로 자동 등록되므로
    base 는 빈 리스트로 두고 _autodiscover 가 collect_* 함수들을 찾아 추가한다."""
    return []


def _sb_mapping():
    """Supabase base mapping. Keycloak 과 같은 item_id 를 다중 매핑 — IdP 카테고리
    배타이므로 둘 다 동시에 활성화되지 않는다 (_resolve_supported_tools)."""
    from collectors.supabase_collector import (
        collect_user_inventory, collect_idp_inventory, collect_idp_registered,
        collect_active_idp_multi, collect_mfa_required, collect_otp_flow,
        collect_webauthn_status, collect_session_policy, collect_password_policy,
        collect_rbac_policy, collect_abac_policy, collect_data_abac_policy,
        collect_mfa_required_actions, collect_role_change_events,
    )
    return [
        (collect_user_inventory,         "1.1.1.2_1",  "초기"),
        (collect_idp_inventory,          "1.1.1.3_1",  "향상"),
        (collect_idp_registered,         "1.1.2.1_1",  "기존"),
        (collect_active_idp_multi,       "1.1.2.2_1",  "초기"),
        (collect_mfa_required,           "1.2.1.1_1",  "기존"),
        (collect_otp_flow,               "1.2.1.2_1",  "초기"),
        (collect_webauthn_status,        "1.2.1.2_2",  "초기"),
        (collect_session_policy,         "1.2.2.1_1",  "기존"),
        (collect_password_policy,        "1.4.2.2_1",  "초기"),
        (collect_role_change_events,     "1.4.2.2_2",  "초기"),
        (collect_rbac_policy,            "1.4.1.2_1",  "초기"),
        (collect_abac_policy,            "4.1.1.3_1",  "향상"),
        (collect_mfa_required_actions,   "4.2.2.2_2",  "초기"),
        (collect_data_abac_policy,       "6.2.1.3_1",  "향상"),
    ]


def _vc_mapping():
    """Vercel base mapping. web_probe/Trivy 와 일부 다중 매핑 (보강 증거)."""
    from collectors.vercel_collector import (
        collect_deployment_history, collect_env_separation, collect_team_rbac,
        collect_domain_ssl, collect_secrets_management, collect_audit_log_retention,
    )
    return [
        (collect_deployment_history,    "5.4.1.2_2",  "초기"),
        (collect_env_separation,        "5.5.1.3_2",  "향상"),
        (collect_team_rbac,             "4.1.1.4_2",  "최적화"),
        (collect_domain_ssl,            "3.3.1.1_1",  "기존"),
        (collect_secrets_management,    "5.5.1.2_3",  "초기"),
        (collect_audit_log_retention,   "5.2.1.1_2",  "기존"),
    ]


def _rw_mapping():
    """Railway base mapping. Trivy/Wazuh 와 일부 다중 매핑."""
    from collectors.railway_collector import (
        collect_deployment_status, collect_env_var_separation,
        collect_project_members, collect_service_uptime, collect_restart_policy,
    )
    return [
        (collect_deployment_status,     "5.4.1.2_4",  "초기"),
        (collect_env_var_separation,    "5.5.1.3_1",  "향상"),
        (collect_project_members,       "4.1.1.4_2",  "최적화"),
        (collect_service_uptime,        "3.5.1.3_1",  "향상"),
        (collect_restart_policy,        "3.5.1.1_2",  "기존"),
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
    "keycloak":  "collectors.keycloak_collector",
    "wazuh":     "collectors.wazuh_collector",
    "nmap":      "collectors.nmap_collector",
    "trivy":     "collectors.trivy_collector",
    "web_probe": "collectors.web_probe_collector",
    "supabase":  "collectors.supabase_collector",
    "vercel":    "collectors.vercel_collector",
    "railway":   "collectors.railway_collector",
}

# 명시 매핑 함수 캐시(원본 함수) — 4 오픈소스 도구 + web_probe + Supabase/Vercel/Railway
_BASE_MAPPING_FNS = {
    "keycloak":  _kc_mapping,
    "wazuh":     _wz_mapping,
    "nmap":      _nm_mapping,
    "trivy":     _tr_mapping,
    "web_probe": _wp_mapping,
    "supabase":  _sb_mapping,
    "vercel":    _vc_mapping,
    "railway":   _rw_mapping,
}


# B-1 회귀 방지: item_id 4번째 segment ↔ 매핑 maturity 일치 강제
_MATURITY_BY_NUM = {1: "기존", 2: "초기", 3: "향상", 4: "최적화"}


def _validate_mapping(tool: str, mapping: list) -> list:
    """매핑의 (item_id, maturity) 정합성 검증. 불일치 시 item_id 기준으로 자동 보정 + 경고."""
    fixed = []
    for entry in mapping:
        fn, item_id, maturity = entry
        try:
            mat_num = int(item_id.split(".")[3].split("_")[0])
            expected = _MATURITY_BY_NUM.get(mat_num)
        except (IndexError, ValueError):
            expected = None
        if expected and maturity != expected:
            logger.warning(
                "[mapping] %s/%s maturity 불일치 — 등록값=%r, item_id 기준=%r → 자동 보정",
                tool, item_id, maturity, expected,
            )
            fixed.append((fn, item_id, expected))
        else:
            fixed.append(entry)
    return fixed


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
    full = _autodiscover(module_name, base) if module_name else base
    return _validate_mapping(tool, full)


# 외부 노출용: 기존 _TOOL_DISPATCH 구조 유지 (mapping_fn, takes_args)
_TOOL_DISPATCH = {
    "keycloak":  (lambda: _full_mapping("keycloak"),  True),
    "wazuh":     (lambda: _full_mapping("wazuh"),     True),
    "nmap":      (lambda: _full_mapping("nmap"),      False),
    "trivy":     (lambda: _full_mapping("trivy"),     False),
    "web_probe": (lambda: _full_mapping("web_probe"), False),
    "supabase":  (lambda: _full_mapping("supabase"),  True),
    "vercel":    (lambda: _full_mapping("vercel"),    True),
    "railway":   (lambda: _full_mapping("railway"),   True),
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

    if tool == "web_probe":
        # 외부 공개 도메인 1개만 있으면 동작. 세션 단위 set_session_target 으로 주입.
        # 환경변수 fallback 없으면 미설정으로 본다 (run-time 에서 explicit target 우선).
        target = os.getenv("WEB_PROBE_TARGET", "").strip()
        if not target:
            return "web_probe 미연결: WEB_PROBE_TARGET 미설정 — 도메인 입력 필요"
        return None

    if tool == "supabase":
        ref = os.getenv("SUPABASE_PROJECT_REF", "").strip()
        pat = os.getenv("SUPABASE_MGMT_PAT", "").strip()
        anon = os.getenv("SUPABASE_ANON_KEY", "").strip()
        if not ref:
            return "Supabase 미연결: SUPABASE_PROJECT_REF 미설정 (대시보드 ref 또는 NewAssessment 입력 필요)"
        if not pat and not anon:
            return "Supabase 미연결: Management PAT 또는 anon key 중 하나는 필수"
        return None

    if tool == "vercel":
        token = os.getenv("VERCEL_TOKEN", "").strip()
        if not token:
            return "Vercel 미연결: VERCEL_TOKEN 미설정 — NewAssessment 에서 입력 필요"
        return None

    if tool == "railway":
        token = os.getenv("RAILWAY_TOKEN", "").strip()
        if not token:
            return "Railway 미연결: RAILWAY_TOKEN 미설정 — NewAssessment 에서 입력 필요"
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
    if tool == "web_probe":
        # web_probe 는 외부 도메인을 HTTPS 로 직접 조회 — backend egress 만 있으면 OK.
        # 별도 wrapper 가 없으므로 TCP probe 는 생략(_tool_configured 에서 target 확인).
        return None
    if tool == "supabase":
        return _probe_tcp("https://api.supabase.com")
    if tool == "vercel":
        return _probe_tcp("https://api.vercel.com")
    if tool == "railway":
        return _probe_tcp("https://backboard.railway.app")
    return f"unknown tool: {tool}"


UNAVAILABLE_REASONS = {
    "tool_not_connected":   "도구 미연결 (placeholder URL 또는 자격 미설정)",
    "tool_unreachable":     "도구 TCP 도달 실패",
    "collector_error":      "수집기 호출 중 예외",
    "audit_policy_disabled": "Windows Audit Policy 비활성 — Security 채널 이벤트 emit 안 됨",
    "sysmon_not_deployed":  "Sysmon 미설치 — 정밀 행위 탐지 룰 측정 불가",
    "ot_segment_excluded":  "OT 세그먼트 — 별도 트랙으로 분리",
    "unknown":              "기타/미분류",
}


def _classify_health_error(tool: str, error_msg: str) -> str:
    """_tool_health/_tool_configured 가 돌려준 메시지를 reason_code 로 분류.

    placeholder/자격 미설정 류 → tool_not_connected
    TCP 실패 류 → tool_unreachable
    그 외 → unknown
    """
    if not error_msg:
        return "unknown"
    msg = error_msg.lower()
    if "미연결" in error_msg or "미설정" in error_msg or "placeholder" in msg:
        return "tool_not_connected"
    if "timeout" in msg or "refused" in msg or "unreachable" in msg or "connection" in msg or "host" in msg:
        return "tool_unreachable"
    return "unknown"


def _unavailable_result(
    tool: str,
    item_id: str,
    maturity: str,
    error_msg: str,
    reason_code: Optional[str] = None,
) -> dict:
    """평가불가 항목의 표준 결과 dict.

    reason_code 가 명시되면 그대로 사용, 미명시면 error_msg 휴리스틱 분류.
    프론트는 raw_json['reason_code'] 와 raw_json['reason_label'] 를 읽어
    리포트/툴팁에 사람이 이해할 사유로 표시한다.
    """
    code = reason_code or _classify_health_error(tool, error_msg)
    label = UNAVAILABLE_REASONS.get(code, UNAVAILABLE_REASONS["unknown"])
    return {
        "item_id":      item_id,
        "maturity":     maturity,
        "tool":         tool,
        "result":       "평가불가",
        "metric_key":   "tool_unavailable",
        "metric_value": 0.0,
        "threshold":    1.0,
        "raw_json":     {
            "reason_code":  code,
            "reason_label": label,
        },
        "error":        error_msg,
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }


def _safe_call(fn, item_id: str, maturity: str, takes_args: bool, tool_name: str) -> dict:
    """collector 호출 + 일시적 에러 시 지수 백오프 재시도 (P1-12).

    재시도 횟수: ZTA_COLLECTOR_RETRY (기본 3). 1차 시도 + (N-1) 회 재시도.
    백오프: 1s, 2s, 4s ... (2 ** attempt 초)
    영구 에러로 판단되는 메시지(401/403/unauthorized/forbidden/invalid)는 즉시 중단.
    """
    import time  # 모듈 최상단 import 와 충돌 없이 명시 (테스트 친화).

    try:
        max_attempts = max(1, int(os.getenv("ZTA_COLLECTOR_RETRY", "3")))
    except ValueError:
        max_attempts = 3

    last_exc: Optional[Exception] = None
    for attempt in range(max_attempts):
        try:
            return fn(item_id, maturity) if takes_args else fn()
        except Exception as exc:
            last_exc = exc
            msg = str(exc).lower()
            # 영구 에러(권한/형식) 는 재시도 무의미.
            if any(k in msg for k in ("401", "403", "unauthorized", "forbidden", "invalid")):
                break
            if attempt < max_attempts - 1:
                backoff = 2 ** attempt
                logger.info(
                    "[collector] %s(%s) attempt %d/%d failed: %s — retry in %ds",
                    tool_name, item_id, attempt + 1, max_attempts, exc, backoff,
                )
                time.sleep(backoff)
    logger.warning(
        "[collector] %s(%s) failed after retries: %s",
        tool_name, item_id, last_exc,
    )
    return _unavailable_result(
        tool_name, item_id, maturity,
        str(last_exc) if last_exc else "unknown error",
        reason_code="collector_error",
    )


# 동시 세션이 nmap/trivy의 모듈-전역 _current_target을 덮어쓰지 않도록 직렬화.
# 시연용 환경 기준이며, 대규모 동시 진단이 필요해지면 collector 시그니처에 target
# 인자를 정식으로 추가하는 리팩터링이 필요하다.
_collector_lock = threading.Lock()


# 데모 시연 자연스러움용 — unavailable 항목당 sleep + 단건 commit.
# 0 (기본) 이면 운영 모드처럼 모아서 한 번에 commit.
# 시연 권장: 50~200ms (212 항목 기준 11~42초 progress).
DEMO_DELAY_MS = int(os.getenv("ZTA_DEMO_DELAY_MS", "0"))


# ──────────────────────────────────────────────────────────────────────────────
# 데모 모드(fake 결과) — scan_mode=="demo" 일 때 collector 실호출 대신 사용.
# 항목별로 충족/부분충족/미충족을 deterministic 하게 섞어 점수·차트·권고가 의미 있게.
# item_id 의 hash 로 분포를 결정 → 같은 item_id 는 항상 같은 결과.
# 비율: 충족 60% / 부분충족 25% / 미충족 15% (시연 시 적정 점수 ~2.5~3.0).
# 평가불가 0% — 데모는 모두 측정 가능.
# ──────────────────────────────────────────────────────────────────────────────

_DEMO_VERDICTS = (
    ("충족",   0.60, 1.00),
    ("부분충족", 0.85, 0.50),  # 누적 0.85 까지 → 25% 비중
    ("미충족",  1.00, 0.10),
)


def _demo_result(tool: str, item_id: str, maturity: str) -> dict:
    """항목별 deterministic fake 결과. scan_mode='demo' 전용.

    metric_value/threshold 는 verdict 와 일치하는 합리적 값으로 채운다.
    """
    h = abs(hash(f"{item_id}|{tool}")) % 1000 / 1000.0
    verdict = "미충족"
    value = 0.10
    for v, cutoff, val in _DEMO_VERDICTS:
        if h <= cutoff:
            verdict, value = v, val
            break
    return {
        "item_id":      item_id,
        "maturity":     maturity,
        "tool":         tool,
        "result":       verdict,
        "metric_key":   "demo_simulation",
        "metric_value": value,
        "threshold":    0.80,
        "raw_json":     {"demo": True, "deterministic_hash": h},
        "error":        None,
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }


def _run_demo_mode(session_id: int, tools: list[str]) -> None:
    """scan_mode='demo' 일 때의 _run_collectors 대체 경로.

    각 도구의 base+autodiscover 매핑을 순회하며 _demo_result 를 단건 persist.
    DEMO_DELAY_MS 가 있으면 점진 진행률 효과.
    """
    import time as _t
    for tool in tools:
        try:
            mapping = _full_mapping(tool)
        except Exception as exc:
            logger.warning("[demo] mapping load failed tool=%s: %s", tool, exc)
            continue
        for entry in mapping:
            if len(entry) < 3:
                continue
            _, item_id, maturity = entry[0], entry[1], entry[2]
            result = _demo_result(tool, item_id, maturity)
            _persist_one_result(session_id, result)
            if DEMO_DELAY_MS > 0:
                _t.sleep(DEMO_DELAY_MS / 1000.0)


def _persist_one_result(session_id: int, item: dict) -> bool:
    """단건 commit — 데모 모드에서 점진적 진행률용. True if persisted."""
    item_id_str = item.get("item_id")
    if not item_id_str:
        return False
    db = SessionLocal()
    try:
        checklist = db.query(Checklist).filter(Checklist.item_id == item_id_str).first()
        if not checklist:
            return False
        _upsert_collected(db, session_id, checklist.check_id, item)
        db.commit()
        return True
    except Exception as exc:
        db.rollback()
        logger.warning("[collector] persist failed item=%s: %s", item_id_str, exc)
        return False
    finally:
        db.close()


def _run_collectors(session_id: int, tools: list[str]):
    """선택된 도구들로 collector 실행 후 결과를 DB에 직접 저장 (httpx 자기호출 없음).

    각 도구는 호출 전 _tool_health로 가용성을 확인한다. 도구가 닫혀있으면
    그 도구의 모든 매핑을 '평가불가'로 일괄 표시하고 함수 호출은 스킵한다.
    사용자가 nmap/trivy 스캔 대상 또는 Keycloak/Wazuh 자격을 직접 입력한
    경우 session.extra 의 해당 키를 각 collector 모듈 전역에 주입한다.

    ZTA_DEMO_DELAY_MS > 0 이면 데모(unavailable) 항목을 단건 commit + sleep 하여
    InProgress 화면의 progress 가 자연스럽게 차오르게 한다.
    """
    if not tools:
        return

    # scan_mode=='demo' 이면 collector 실호출 없이 fake 결과 생성.
    # 자격·외부 호출 모두 불필요하므로 메모리 자격도 pop 해서 폐기만.
    db_mode = SessionLocal()
    try:
        sess_mode = db_mode.query(DiagnosisSession).filter(
            DiagnosisSession.session_id == session_id
        ).first()
        scan_mode = "demo"
        if sess_mode and isinstance(sess_mode.extra, dict):
            scan_mode = (sess_mode.extra.get("scan_mode") or "demo").strip().lower()
    except Exception:
        scan_mode = "demo"
    finally:
        db_mode.close()

    if scan_mode == "demo":
        # 메모리 자격 폐기 (보관된 게 있다면).
        _pop_session_secrets(session_id)
        with _collector_lock:
            _run_demo_mode(session_id, tools)
        # 채점 — finalize 별도 호출 없이 자동으로 점수 계산.
        db_score = SessionLocal()
        try:
            _trigger_scoring(session_id, db_score)
        except Exception as exc:
            logger.warning("[demo] scoring failed session=%s: %s", session_id, exc)
        finally:
            db_score.close()
        return

    # 세션의 사용자 입력 조회.
    # - scan_targets / IdP·SIEM URL·user 등 비민감 정보 → DB extra 에서 로드.
    # - 자격 비밀번호(admin_pass/api_pass) → 메모리 dict 에서 pop (DB 평문 저장 금지).
    # 자격은 로깅에 절대 포함하지 않는다.
    scan_targets: dict = {}
    keycloak_creds: dict = {}
    wazuh_creds: dict = {}
    supabase_creds: dict = {}
    vercel_creds: dict = {}
    railway_creds: dict = {}
    profile_select_runtime: dict = {}
    db_pre = SessionLocal()
    try:
        sess = db_pre.query(DiagnosisSession).filter(
            DiagnosisSession.session_id == session_id
        ).first()
        if sess and isinstance(sess.extra, dict):
            raw = sess.extra.get("scan_targets") or {}
            if isinstance(raw, dict):
                scan_targets = {k: (v or "").strip() for k, v in raw.items() if v}
            kc_meta = sess.extra.get("keycloak_creds") or {}
            if isinstance(kc_meta, dict):
                keycloak_creds = {k: v for k, v in kc_meta.items() if v}
            wz_meta = sess.extra.get("wazuh_creds") or {}
            if isinstance(wz_meta, dict):
                wazuh_creds = {k: v for k, v in wz_meta.items() if v}
            sb_meta = sess.extra.get("supabase_creds") or {}
            if isinstance(sb_meta, dict):
                supabase_creds = {k: v for k, v in sb_meta.items() if v}
            vc_meta = sess.extra.get("vercel_creds") or {}
            if isinstance(vc_meta, dict):
                vercel_creds = {k: v for k, v in vc_meta.items() if v}
            rw_meta = sess.extra.get("railway_creds") or {}
            if isinstance(rw_meta, dict):
                railway_creds = {k: v for k, v in rw_meta.items() if v}
            ps_meta = sess.extra.get("profile_select") or {}
            if isinstance(ps_meta, dict):
                profile_select_runtime = ps_meta
    except Exception as exc:
        logger.warning("[collector] session lookup failed: %s", exc)
    finally:
        db_pre.close()

    # 메모리에 보관된 자격 비번/토큰 합류 (사용 후 폐기 보장)
    secrets_blob = _pop_session_secrets(session_id)
    kc_secret = secrets_blob.get("keycloak") if isinstance(secrets_blob, dict) else None
    wz_secret = secrets_blob.get("wazuh") if isinstance(secrets_blob, dict) else None
    sb_secret = secrets_blob.get("supabase") if isinstance(secrets_blob, dict) else None
    vc_secret = secrets_blob.get("vercel") if isinstance(secrets_blob, dict) else None
    rw_secret = secrets_blob.get("railway") if isinstance(secrets_blob, dict) else None
    if isinstance(kc_secret, dict):
        for k, v in kc_secret.items():
            if v:
                keycloak_creds[k] = v
    if isinstance(wz_secret, dict):
        for k, v in wz_secret.items():
            if v:
                wazuh_creds[k] = v
    if isinstance(sb_secret, dict):
        for k, v in sb_secret.items():
            if v:
                supabase_creds[k] = v
    if isinstance(vc_secret, dict):
        for k, v in vc_secret.items():
            if v:
                vercel_creds[k] = v
    if isinstance(rw_secret, dict):
        for k, v in rw_secret.items():
            if v:
                railway_creds[k] = v

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
                # web_probe 는 별도 키가 있으면 우선, 없으면 nmap target 으로 폴백
                # (둘 다 도메인/URL 형식이라 호환).
                if tool == "web_probe":
                    explicit_target = scan_targets.get("web_probe") or scan_targets.get("nmap")
                elif tool in ("nmap", "trivy"):
                    explicit_target = scan_targets.get(tool)
                else:
                    explicit_target = None
                explicit_creds: Optional[dict] = None
                if tool == "nmap":
                    from collectors import nmap_collector as _nm
                    _nm.set_session_target(explicit_target)
                elif tool == "trivy":
                    from collectors import trivy_collector as _tr
                    _tr.set_session_target(explicit_target)
                elif tool == "web_probe":
                    from collectors import web_probe_collector as _wp
                    _wp.set_session_target(explicit_target)
                elif tool == "keycloak":
                    from collectors import keycloak_collector as _kc
                    explicit_creds = keycloak_creds or None
                    _kc.set_session_creds(explicit_creds)
                elif tool == "wazuh":
                    from collectors import wazuh_collector as _wz
                    explicit_creds = wazuh_creds or None
                    _wz.set_session_creds(explicit_creds)
                elif tool == "supabase":
                    from collectors import supabase_collector as _sb
                    explicit_creds = supabase_creds or None
                    _sb.set_session_creds(explicit_creds)
                elif tool == "vercel":
                    from collectors import vercel_collector as _vc
                    explicit_creds = vercel_creds or None
                    _vc.set_session_creds(explicit_creds)
                elif tool == "railway":
                    from collectors import railway_collector as _rw
                    explicit_creds = railway_creds or None
                    _rw.set_session_creds(explicit_creds)

                # 가용성 체크:
                # - nmap/trivy: 사용자가 target을 직접 줬으면 wrapper TCP 도달성만 확인.
                # - keycloak/wazuh: 사용자가 URL을 직접 줬으면 그 URL TCP probe만 확인
                #   (placeholder 가드는 .env 디폴트값에만 의미가 있으므로 우회).
                # - web_probe: 사용자가 target 을 줬으면 별도 health probe 불필요
                #   (외부 도메인 직접 호출이므로 .env placeholder 가드 우회).
                if tool in ("nmap", "trivy") and explicit_target:
                    wrapper_env = "NMAP_WRAPPER_URL" if tool == "nmap" else "TRIVY_WRAPPER_URL"
                    health_err = _probe_tcp(os.getenv(wrapper_env, ""))
                elif tool in ("keycloak", "wazuh") and explicit_creds and explicit_creds.get("url"):
                    health_err = _probe_tcp(explicit_creds["url"])
                elif tool == "web_probe" and explicit_target:
                    health_err = None
                elif tool == "supabase" and explicit_creds and explicit_creds.get("project_ref"):
                    # 자격 있으면 api.supabase.com 만 TCP probe.
                    health_err = _probe_tcp("https://api.supabase.com")
                elif tool == "vercel" and explicit_creds and explicit_creds.get("token"):
                    health_err = _probe_tcp("https://api.vercel.com")
                elif tool == "railway" and explicit_creds and explicit_creds.get("token"):
                    health_err = _probe_tcp("https://backboard.railway.app")
                else:
                    health_err = _tool_health(tool)

                if health_err:
                    logger.info("[collector] %s unavailable (%s) → %d items 평가불가 처리",
                                tool, health_err, len(mapping))
                    for _fn, item_id, maturity in mapping:
                        unavail = _unavailable_result(tool, item_id, maturity, health_err)
                        if DEMO_DELAY_MS > 0:
                            # 데모 모드: 단건 commit + sleep → InProgress 점진적 채움
                            if _persist_one_result(session_id, unavail):
                                logger.debug("[demo] %s/%s 평가불가", tool, item_id)
                            time.sleep(DEMO_DELAY_MS / 1000.0)
                        else:
                            results.append(unavail)
                    continue

                # Wazuh 한정: profile_select 의 audit_policy/sysmon 'no' 응답 시
                # 의존 item_id 들을 사전 평가불가 분류 (SKT XDR §6 흡수).
                # 그 외 항목은 정상 collector 호출 경로로 진입한다.
                wazuh_skip: dict[str, str] = {}
                if tool == "wazuh" and profile_select_runtime:
                    audit = (profile_select_runtime.get("windows_audit_policy_enabled") or "").lower()
                    sysmon = (profile_select_runtime.get("sysmon_deployed") or "").lower()
                    if audit == "no":
                        for iid in _wz.AUDIT_POLICY_DEPENDENT_ITEM_IDS:
                            wazuh_skip[iid] = "audit_policy_disabled"
                    if sysmon == "no":
                        for iid in _wz.SYSMON_DEPENDENT_ITEM_IDS:
                            # audit 사유가 먼저 잡혔으면 그대로 두고, 아니면 sysmon 사유 부여.
                            wazuh_skip.setdefault(iid, "sysmon_not_deployed")

                for fn, item_id, maturity in mapping:
                    skip_reason = wazuh_skip.get(item_id)
                    if skip_reason:
                        unavail = _unavailable_result(
                            tool, item_id, maturity,
                            UNAVAILABLE_REASONS.get(skip_reason, skip_reason),
                            reason_code=skip_reason,
                        )
                        if DEMO_DELAY_MS > 0:
                            _persist_one_result(session_id, unavail)
                            time.sleep(DEMO_DELAY_MS / 1000.0)
                        else:
                            results.append(unavail)
                        continue

                    result = _safe_call(fn, item_id, maturity, takes_args, tool)
                    if DEMO_DELAY_MS > 0:
                        # 실 collector 호출도 데모 모드면 단건 commit (자체 호출 시간이 sleep 역할)
                        _persist_one_result(session_id, result)
                    else:
                        results.append(result)
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
                from collectors import web_probe_collector as _wp
                _wp.set_session_target(None)
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
            try:
                from collectors import supabase_collector as _sb
                _sb.set_session_creds(None)
            except Exception:
                pass
            try:
                from collectors import vercel_collector as _vc
                _vc.set_session_creds(None)
            except Exception:
                pass
            try:
                from collectors import railway_collector as _rw
                _rw.set_session_creds(None)
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

    # live 모드 collector 가 끝나면 즉시 채점 트리거 (demo 모드와 동일한 흐름).
    # 이전: 사용자가 InProgress 에서 "완료" 누를 때 /finalize 가 호출되었으나, 다중 매핑으로
    # collected < expected 가 발생하면 영구히 409 → status 가 "진행 중"에 머무는 버그.
    # collector 가 한 번 루프를 완료했다는 것은 모든 도구 호출이 끝났다는 뜻이므로
    # 여기서 채점하는 게 안전하다.
    db_score = SessionLocal()
    try:
        _trigger_scoring(session_id, db_score)
    except Exception as exc:
        logger.warning("[live] scoring failed session=%s: %s", session_id, exc)
    finally:
        db_score.close()


# ──────────────────────────────────────────────────────────────────────────────
# P1-8: 진단 세션 비교 endpoint
# ──────────────────────────────────────────────────────────────────────────────

# DiagnosisResult.result 의 ordinal 매핑. 평가불가는 None 으로 두어 비교 제외.
_RESULT_ORDINAL: dict[str, Optional[int]] = {
    "미충족":   0,
    "부분충족": 1,
    "충족":     2,
    "평가불가": None,
}


def _result_ord(v: Optional[str]) -> Optional[int]:
    if v is None:
        return None
    return _RESULT_ORDINAL.get(v, None)


def _session_pillar_scores(db: Session, session_id: int) -> dict[str, float]:
    rows = db.query(MaturityScore).filter(MaturityScore.session_id == session_id).all()
    return {m.pillar: round(m.score, 4) for m in rows}


@router.get("/compare")
def compare_sessions(
    from_id: int,
    to_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """두 세션의 항목별 result 차이 + 점수 변화 반환 (P1-8)."""
    if from_id == to_id:
        raise HTTPException(status_code=400, detail="from_id 와 to_id 는 달라야 합니다.")

    from_session = _get_session_or_404(db, from_id)
    to_session   = _get_session_or_404(db, to_id)
    assert_session_access(current_user, from_session)
    assert_session_access(current_user, to_session)

    from_meta = {
        "session_id": from_session.session_id,
        "date":       from_session.started_at.isoformat() if from_session.started_at else "",
        "score":      from_session.total_score,
        "level":      from_session.level or determine_maturity_level(from_session.total_score or 0.0),
    }
    to_meta = {
        "session_id": to_session.session_id,
        "date":       to_session.started_at.isoformat() if to_session.started_at else "",
        "score":      to_session.total_score,
        "level":      to_session.level or determine_maturity_level(to_session.total_score or 0.0),
    }

    score_delta = round(
        (to_session.total_score or 0.0) - (from_session.total_score or 0.0), 4
    )
    level_changed = (from_meta["level"] or "") != (to_meta["level"] or "")

    from_pillars = _session_pillar_scores(db, from_id)
    to_pillars   = _session_pillar_scores(db, to_id)
    pillar_changes = []
    for pillar in sorted(set(from_pillars) | set(to_pillars)):
        f = from_pillars.get(pillar)
        t = to_pillars.get(pillar)
        pillar_changes.append({
            "pillar":     pillar,
            "from_score": f,
            "to_score":   t,
            "delta":      round((t or 0.0) - (f or 0.0), 4) if (f is not None or t is not None) else 0.0,
        })

    from_rows = (
        db.query(DiagnosisResult, Checklist)
        .join(Checklist, DiagnosisResult.check_id == Checklist.check_id)
        .filter(DiagnosisResult.session_id == from_id)
        .all()
    )
    to_rows = (
        db.query(DiagnosisResult, Checklist)
        .join(Checklist, DiagnosisResult.check_id == Checklist.check_id)
        .filter(DiagnosisResult.session_id == to_id)
        .all()
    )

    from_map: dict = {cl.item_id: (dr, cl) for dr, cl in from_rows}
    to_map:   dict = {cl.item_id: (dr, cl) for dr, cl in to_rows}

    improved: list[dict] = []
    regressed: list[dict] = []
    unchanged_cnt = 0
    new_in_to: list[dict] = []

    for item_id, (to_dr, to_cl) in to_map.items():
        if item_id not in from_map:
            new_in_to.append({
                "item_id":   item_id,
                "item_name": to_cl.item_name,
                "pillar":    to_cl.pillar,
                "to":        to_dr.result,
            })
            continue
        from_dr, _from_cl = from_map[item_id]
        f_ord = _result_ord(from_dr.result)
        t_ord = _result_ord(to_dr.result)
        # 평가불가 ↔ 다른 값은 unchanged (의미 변화 없음).
        if f_ord is None or t_ord is None:
            unchanged_cnt += 1
            continue
        if t_ord > f_ord:
            improved.append({
                "item_id":   item_id,
                "item_name": to_cl.item_name,
                "pillar":    to_cl.pillar,
                "from":      from_dr.result,
                "to":        to_dr.result,
            })
        elif t_ord < f_ord:
            regressed.append({
                "item_id":   item_id,
                "item_name": to_cl.item_name,
                "pillar":    to_cl.pillar,
                "from":      from_dr.result,
                "to":        to_dr.result,
            })
        else:
            unchanged_cnt += 1

    return {
        "from": from_meta,
        "to":   to_meta,
        "score_delta":    score_delta,
        "level_changed":  level_changed,
        "pillar_changes": pillar_changes,
        "item_changes": {
            "improved":  improved,
            "regressed": regressed,
            "unchanged": unchanged_cnt,
            "new_in_to": new_in_to,
        },
    }


# ──────────────────────────────────────────────────────────────────────────────
# P1-11: 외부 공유 링크
# ──────────────────────────────────────────────────────────────────────────────

import secrets as _secrets
import hashlib as _hashlib
from datetime import timedelta as _timedelta


def _hash_share_token(raw_token: str) -> str:
    return _hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _build_result_payload(db: Session, session: DiagnosisSession) -> dict:
    """/result 와 동일 구조 — 공유 endpoint 용 헬퍼."""
    session_id = session.session_id
    org = db.query(Organization).filter(Organization.org_id == session.org_id).first()
    user = db.query(User).filter(User.user_id == session.user_id).first()

    maturity_rows = db.query(MaturityScore).filter(
        MaturityScore.session_id == session_id
    ).all()
    pillar_scores = [
        {
            "pillar":   m.pillar,
            "score":    round(m.score, 4),
            "level":    determine_maturity_level(m.score),
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
            "question":       cl.question or "",
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
        # SKT 가이드 §3 §4 §7 §9 — 보고서 머리 표기용 평가 메타
        "evaluation_meta":   build_evaluation_meta(session),
    }


@router.post("/share/{session_id}")
def create_share_link(
    session_id: int,
    expires_days: int = 7,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """진단 결과 공유 토큰 발급 (기본 7일 만료). 본인/admin만 발급 가능."""
    session = _get_session_or_404(db, session_id)
    assert_session_access(current_user, session)

    # 발급 권한: 세션 소유자 본인 또는 admin
    if current_user.role != "admin" and session.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="공유 링크 발급 권한이 없습니다.")

    if expires_days < 1 or expires_days > 90:
        raise HTTPException(status_code=400, detail="만료 기간은 1~90일 사이여야 합니다.")

    raw_token = _secrets.token_urlsafe(32)
    token_hash = _hash_share_token(raw_token)
    expires_at = datetime.now(timezone.utc) + _timedelta(days=expires_days)

    share = SharedResult(
        session_id=session_id,
        token_hash=token_hash,
        created_by_user_id=current_user.user_id,
        expires_at=expires_at,
    )
    db.add(share)
    db.commit()
    db.refresh(share)

    return {
        "status":     "ok",
        "share_id":   share.share_id,
        "token":      raw_token,
        "expires_at": share.expires_at.isoformat() if share.expires_at else None,
    }


@router.get("/shared/{token}")
def get_shared_result(token: str, db: Session = Depends(get_db)):
    """토큰으로 진단 결과 조회. 인증 불필요(공유 링크), 만료/취소 검사."""
    if not token or len(token) < 8:
        raise HTTPException(status_code=400, detail="유효한 토큰이 아닙니다.")
    token_hash = _hash_share_token(token)
    share = db.query(SharedResult).filter(SharedResult.token_hash == token_hash).first()
    if not share:
        raise HTTPException(status_code=404, detail="공유 링크를 찾을 수 없습니다.")
    if share.revoked_at is not None:
        raise HTTPException(status_code=410, detail="이 공유 링크는 취소되었습니다.")

    now = datetime.now(timezone.utc)
    # MySQL DATETIME 은 tz 가 naive 로 돌아오므로 비교 위해 정규화.
    exp = share.expires_at
    if exp is not None and exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp is None or exp < now:
        raise HTTPException(status_code=410, detail="만료된 공유 링크입니다.")

    session = db.query(DiagnosisSession).filter(
        DiagnosisSession.session_id == share.session_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")

    payload = _build_result_payload(db, session)
    payload["shared"] = {
        "share_id":   share.share_id,
        "expires_at": share.expires_at.isoformat() if share.expires_at else None,
    }
    return payload


@router.delete("/share/{share_id}")
def revoke_share_link(
    share_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """공유 토큰 취소. 발급자 또는 admin."""
    share = db.query(SharedResult).filter(SharedResult.share_id == share_id).first()
    if not share:
        raise HTTPException(status_code=404, detail="공유 링크를 찾을 수 없습니다.")
    if current_user.role != "admin" and share.created_by_user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="공유 링크 취소 권한이 없습니다.")
    if share.revoked_at is not None:
        return {"status": "ok", "share_id": share.share_id, "already_revoked": True}
    share.revoked_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "ok", "share_id": share.share_id}


# ─── 진단 세션 수동 삭제 ───────────────────────────────────────────────────────
# History 페이지에서 사용자가 자기 세션을 정리하기 위한 endpoint.
# status 무관(진행중/완료/평가불가 모두) 삭제 가능. 본인 세션 또는 admin 만.
# 자식 5개 테이블(CollectedData/Evidence/DiagnosisResult/MaturityScore/ScoreHistory)
# 까지 cascade 삭제 — 90일 cleanup 과 동일 패턴.

@router.delete("/session/{session_id}")
def delete_assessment_session(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = _get_session_or_404(db, session_id)
    assert_session_access(current_user, session)

    # 진행 중인 세션의 메모리 자격이 남아있을 수 있으니 함께 폐기
    _pop_session_secrets(session_id)

    # 자식 cascade
    for model in (CollectedData, Evidence, DiagnosisResult, MaturityScore, ScoreHistory):
        db.query(model).filter(model.session_id == session_id).delete(synchronize_session=False)

    # 공유 토큰도 같이 삭제 (있으면)
    db.query(SharedResult).filter(SharedResult.session_id == session_id).delete(synchronize_session=False)

    db.delete(session)
    db.commit()

    logger.info("[assessment] session %s deleted by user_id=%s", session_id, current_user.user_id)
    return {"status": "ok", "session_id": session_id}


# ──────────────────────────────────────────────────────────────────────────────
# MAR-004 / SFR-AUTO-005: 주기적 평가 자동 실행 (스케줄러)
# ──────────────────────────────────────────────────────────────────────────────
# next_run_at 이 도래한 스케줄을 lifespan 주기 태스크가 데모 모드로 자동 실행한다.
# 자격(비밀번호)은 DB 에 저장하지 않으므로 스케줄은 데모 모드만 지원한다.

_SCHED_CONFIG_KEYS = (
    "org_name", "manager", "email", "department", "contact",
    "org_type", "infra_type", "employees", "servers", "applications", "note",
    "pillar_scope", "tool_scope", "profile_select",
)


def _sanitize_schedule_config(cfg: dict) -> dict:
    """스케줄 저장용 config 정제 — 자격/토큰 제거, 데모 모드 고정."""
    cfg = cfg or {}
    out: dict = {}
    for k in _SCHED_CONFIG_KEYS:
        if k in cfg and cfg[k] is not None:
            out[k] = cfg[k]
    out["scan_mode"] = "demo"
    return out


def _create_session_from_config(db: Session, sched: ScheduledAssessment) -> tuple[int, list[str]]:
    """스케줄 config 로 데모 진단 세션 생성. (session_id, selected_tools) 반환."""
    cfg = sched.config if isinstance(sched.config, dict) else {}
    profile_select = cfg.get("profile_select") if isinstance(cfg.get("profile_select"), dict) else {}
    tool_scope = cfg.get("tool_scope") if isinstance(cfg.get("tool_scope"), dict) else {}
    resolved = _resolve_supported_tools(profile_select, tool_scope)
    selected_tools = sorted(t for t in ALL_TOOLS if resolved.get(t))
    extra = {
        "department":   cfg.get("department"),
        "contact":      cfg.get("contact"),
        "employees":    cfg.get("employees"),
        "servers":      cfg.get("servers"),
        "applications": cfg.get("applications"),
        "note":         cfg.get("note"),
        "pillar_scope": cfg.get("pillar_scope") or {},
        "scan_mode":    "demo",
        "scan_targets": {},
        "profile_select": profile_select,
        "scheduled":    True,
        "schedule_id":  sched.schedule_id,
    }
    session = DiagnosisSession(
        org_id=sched.org_id,
        user_id=sched.user_id,
        status="진행 중",
        started_at=datetime.now(timezone.utc),
        selected_tools={t: True for t in selected_tools},
        extra=extra,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session.session_id, selected_tools


def run_due_schedules() -> int:
    """도래한 스케줄을 실행. lifespan 주기 태스크가 호출. 실행 건수 반환."""
    db = SessionLocal()
    fired = 0
    try:
        if not config_store.get("scheduler_enable", db):
            return 0
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        due = (
            db.query(ScheduledAssessment)
            .filter(
                ScheduledAssessment.enabled == 1,
                ScheduledAssessment.next_run_at.isnot(None),
                ScheduledAssessment.next_run_at <= now,
            )
            .all()
        )
        for sched in due:
            try:
                sid, tools = _create_session_from_config(db, sched)
                if sid and tools:
                    _run_collectors(sid, list(tools))  # demo 경로 — 동기 실행
                interval = max(1, int(sched.interval_hours or 24))
                sched.last_run_at = now
                sched.last_session_id = sid or None
                sched.next_run_at = now + _timedelta(hours=interval)
                db.commit()
                fired += 1
                logger.info("[scheduler] schedule=%s fired → session=%s", sched.schedule_id, sid)
            except Exception as exc:
                db.rollback()
                logger.warning("[scheduler] schedule=%s 실행 실패: %s", sched.schedule_id, exc)
        return fired
    finally:
        db.close()


class ScheduleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    interval_hours: int = Field(default=24, ge=1, le=8760)
    run_now: bool = False                       # True 면 다음 틱에 즉시 실행
    config: dict = Field(default_factory=dict)  # AssessmentRunRequest 형태 (자격 제외)


class ScheduleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=200)
    interval_hours: Optional[int] = Field(default=None, ge=1, le=8760)
    enabled: Optional[bool] = None


def _schedule_to_dict(s: ScheduledAssessment) -> dict:
    return {
        "schedule_id":     s.schedule_id,
        "org_id":          s.org_id,
        "name":            s.name,
        "interval_hours":  s.interval_hours,
        "enabled":         bool(s.enabled),
        "next_run_at":     s.next_run_at.isoformat() if s.next_run_at else None,
        "last_run_at":     s.last_run_at.isoformat() if s.last_run_at else None,
        "last_session_id": s.last_session_id,
        "config":          s.config or {},
    }


@router.post("/schedules")
def create_schedule(
    req: ScheduleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """주기 평가 스케줄 생성 (데모 모드). 본인 조직만."""
    cfg = _sanitize_schedule_config(req.config)
    # org_name 이 주어지면 본인 조직과 일치해야 함(일반 user). admin 은 자유.
    org = db.query(Organization).filter(Organization.org_id == current_user.org_id).first()
    if current_user.role != "admin":
        cfg["org_name"] = org.name if org else cfg.get("org_name")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    first_run = now if req.run_now else now + _timedelta(hours=req.interval_hours)
    sched = ScheduledAssessment(
        org_id=current_user.org_id,
        user_id=current_user.user_id,
        name=req.name.strip(),
        interval_hours=req.interval_hours,
        enabled=1,
        config=cfg,
        next_run_at=first_run,
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return {"status": "ok", **_schedule_to_dict(sched)}


@router.get("/schedules")
def list_schedules(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """본인 조직 스케줄 목록 (admin 은 전체)."""
    q = db.query(ScheduledAssessment)
    if current_user.role != "admin":
        q = q.filter(ScheduledAssessment.org_id == current_user.org_id)
    rows = q.order_by(ScheduledAssessment.schedule_id.desc()).all()
    return {"schedules": [_schedule_to_dict(s) for s in rows], "total": len(rows)}


@router.patch("/schedules/{schedule_id}")
def update_schedule(
    schedule_id: int,
    req: ScheduleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """스케줄 활성/주기/이름 수정."""
    sched = db.query(ScheduledAssessment).filter(
        ScheduledAssessment.schedule_id == schedule_id
    ).first()
    if not sched:
        raise HTTPException(status_code=404, detail="스케줄을 찾을 수 없습니다.")
    assert_org_access(current_user, sched.org_id)
    if req.name is not None:
        sched.name = req.name.strip()[:200] or sched.name
    if req.interval_hours is not None:
        sched.interval_hours = req.interval_hours
    if req.enabled is not None:
        sched.enabled = 1 if req.enabled else 0
        # 재활성화 시 next_run 이 과거면 다음 틱에 실행되도록 now 로 보정.
        if req.enabled and (sched.next_run_at is None):
            sched.next_run_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    db.refresh(sched)
    return {"status": "ok", **_schedule_to_dict(sched)}


@router.delete("/schedules/{schedule_id}")
def delete_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    sched = db.query(ScheduledAssessment).filter(
        ScheduledAssessment.schedule_id == schedule_id
    ).first()
    if not sched:
        raise HTTPException(status_code=404, detail="스케줄을 찾을 수 없습니다.")
    assert_org_access(current_user, sched.org_id)
    db.delete(sched)
    db.commit()
    return {"status": "ok", "schedule_id": schedule_id}
