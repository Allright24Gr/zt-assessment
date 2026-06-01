"""
admin/checklist — Checklist 테이블 관리 (admin 전용).

GET    /api/admin/checklist            : 전체 목록 (페이징 + pillar/diagnosis_type 필터)
POST   /api/admin/checklist            : 신규 항목 생성
PUT    /api/admin/checklist/{check_id} : 수정 (item_name, criteria, maturity_score, threshold 등)
DELETE /api/admin/checklist/{check_id} : 삭제 (참조하는 CollectedData/Result 있으면 거부)
"""
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models import AuthAuditLog, Checklist, CollectedData, DiagnosisResult, DiagnosisSession, User
from routers.auth import get_current_user
from services import config_store

router = APIRouter()


def _require_admin(user: User) -> None:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin 권한이 필요합니다.")


class ChecklistCreate(BaseModel):
    item_id: str = Field(min_length=5, max_length=30)
    pillar: str = Field(min_length=1, max_length=100)
    category: str = Field(min_length=1, max_length=100)
    item_name: str = Field(min_length=1, max_length=200)
    maturity: str = Field(min_length=1, max_length=20)
    maturity_score: int = Field(ge=1, le=4)
    diagnosis_type: str = Field(min_length=1, max_length=20)
    tool: str = Field(min_length=1, max_length=100)
    evidence: Optional[str] = None
    criteria: Optional[str] = None
    fields: Optional[str] = None
    logic: Optional[str] = None
    exceptions: Optional[str] = None
    weight: float = Field(default=0.1, ge=0.0, le=10.0)


class ChecklistUpdate(BaseModel):
    pillar: Optional[str] = None
    category: Optional[str] = None
    item_name: Optional[str] = None
    maturity: Optional[str] = None
    maturity_score: Optional[int] = Field(default=None, ge=1, le=4)
    diagnosis_type: Optional[str] = None
    tool: Optional[str] = None
    evidence: Optional[str] = None
    criteria: Optional[str] = None
    fields: Optional[str] = None
    logic: Optional[str] = None
    exceptions: Optional[str] = None
    weight: Optional[float] = Field(default=None, ge=0.0, le=10.0)


@router.get("/checklist")
def list_checklist(
    pillar: Optional[str] = None,
    diagnosis_type: Optional[str] = None,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    q = db.query(Checklist)
    if pillar:
        q = q.filter(Checklist.pillar == pillar)
    if diagnosis_type:
        q = q.filter(Checklist.diagnosis_type == diagnosis_type)
    total = q.count()
    rows = q.order_by(Checklist.item_id).offset(offset).limit(limit).all()
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "check_id": r.check_id,
                "item_id": r.item_id,
                "pillar": r.pillar,
                "category": r.category,
                "item_name": r.item_name,
                "maturity": r.maturity,
                "maturity_score": r.maturity_score,
                "diagnosis_type": r.diagnosis_type,
                "tool": r.tool,
                "weight": r.weight,
                "evidence": r.evidence,
                "criteria": r.criteria,
                "fields": r.fields,
                "logic": r.logic,
                "exceptions": r.exceptions,
            }
            for r in rows
        ],
    }


@router.post("/checklist")
def create_checklist(
    req: ChecklistCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    if db.query(Checklist).filter(Checklist.item_id == req.item_id).first():
        raise HTTPException(status_code=409, detail="이미 존재하는 item_id 입니다.")
    row = Checklist(**req.model_dump())
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"status": "ok", "check_id": row.check_id, "item_id": row.item_id}


@router.put("/checklist/{check_id}")
def update_checklist(
    check_id: int,
    req: ChecklistUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    row = db.query(Checklist).filter(Checklist.check_id == check_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="체크리스트 항목을 찾을 수 없습니다.")
    patch = req.model_dump(exclude_none=True)
    for k, v in patch.items():
        setattr(row, k, v)
    db.commit()
    return {"status": "ok", "check_id": check_id, "updated_fields": list(patch.keys())}


@router.delete("/checklist/{check_id}")
def delete_checklist(
    check_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    row = db.query(Checklist).filter(Checklist.check_id == check_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="체크리스트 항목을 찾을 수 없습니다.")
    # 참조 무결성 가드 — CollectedData / DiagnosisResult 가 있으면 차단.
    cd_cnt = db.query(CollectedData).filter(CollectedData.check_id == check_id).count()
    dr_cnt = db.query(DiagnosisResult).filter(DiagnosisResult.check_id == check_id).count()
    if cd_cnt or dr_cnt:
        raise HTTPException(
            status_code=409,
            detail=f"이 항목을 참조하는 데이터가 있어 삭제 불가 (collected={cd_cnt}, results={dr_cnt})",
        )
    db.delete(row)
    db.commit()
    return {"status": "ok", "check_id": check_id}


# ──────────────────────────────────────────────────────────────────────────────
# SER-009 감사 로그 조회 / SER-006 해시 체인 검증
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/audit")
def list_audit_logs(
    event_type: Optional[str] = None,
    login_id: Optional[str] = None,
    success: Optional[int] = None,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """감사 로그 목록 (admin 전용). event_type/login_id/success 필터 + 페이지네이션."""
    _require_admin(current_user)
    q = db.query(AuthAuditLog)
    if event_type:
        q = q.filter(AuthAuditLog.event_type == event_type)
    if login_id:
        q = q.filter(AuthAuditLog.login_id == login_id)
    if success is not None:
        q = q.filter(AuthAuditLog.success == success)
    total = q.count()
    rows = q.order_by(AuthAuditLog.audit_id.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "audit_id":   r.audit_id,
                "event_type": r.event_type,
                "user_id":    r.user_id,
                "login_id":   r.login_id,
                "source_ip":  r.source_ip,
                "user_agent": r.user_agent,
                "success":    r.success,
                "detail":     r.detail,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "row_hash":   r.row_hash,
            }
            for r in rows
        ],
    }


@router.get("/audit/verify")
def verify_audit_chain(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """SER-006: 감사 로그 해시 체인 무결성 검증.

    audit_id 오름차순으로 각 행의 row_hash 를 재계산하고, prev_hash 가 직전 행의
    row_hash 와 일치하는지 확인한다. 중간 행 변조/삭제 시 그 지점부터 깨진다.
    SER-006 도입 전 평문 행(row_hash IS NULL)은 체인 시작점으로 리셋한다.
    """
    _require_admin(current_user)
    from services.integrity import audit_row_hash
    rows = db.query(AuthAuditLog).order_by(AuthAuditLog.audit_id.asc()).all()
    prev: Optional[str] = None
    checked = 0
    verified = 0
    broken: list[int] = []
    for r in rows:
        if not r.row_hash:
            prev = None
            continue
        expected = audit_row_hash(
            r.prev_hash,
            event_type=r.event_type,
            user_id=r.user_id,
            login_id=r.login_id,
            source_ip=r.source_ip,
            success=r.success,
            created_at=r.created_at.isoformat() if r.created_at else None,
        )
        link_ok = (prev is None) or (r.prev_hash == prev)
        checked += 1
        if expected == r.row_hash and link_ok:
            verified += 1
        else:
            broken.append(r.audit_id)
        prev = r.row_hash
    return {
        "total":        len(rows),
        "checked":      checked,
        "verified":     verified,
        "broken_count": len(broken),
        "broken_ids":   broken[:50],
        "ok":           len(broken) == 0,
    }


# ──────────────────────────────────────────────────────────────────────────────
# MAR-009 시스템 모니터링 / MAR-010 동적 설정 / MAR-014 백업
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/metrics")
def admin_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """시스템 상태/운영 지표 (JSON). admin 대시보드용."""
    _require_admin(current_user)
    from services.metrics import collect_metrics
    return collect_metrics(db)


@router.get("/config")
def get_runtime_config(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """동적 운영 설정 목록 (현재값 + 기본값 + env)."""
    _require_admin(current_user)
    return {"config": config_store.get_all(db)}


class ConfigUpdate(BaseModel):
    key: str = Field(min_length=1, max_length=100)
    value: Any


@router.put("/config")
def set_runtime_config(
    req: ConfigUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """동적 운영 설정 변경 — 재시작 없이 즉시 반영 (다음 조회부터)."""
    _require_admin(current_user)
    try:
        val = config_store.set_value(db, req.key, req.value, updated_by=current_user.login_id)
    except KeyError:
        raise HTTPException(status_code=400, detail=f"알 수 없는 설정 키: {req.key}")
    return {"status": "ok", "key": req.key, "value": val}


@router.post("/backup")
def trigger_backup(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """DB 논리 백업 생성 (gzip JSON). 최신 14개만 보존."""
    _require_admin(current_user)
    from scripts.backup_db import create_backup, prune_backups
    meta = create_backup()
    pruned = prune_backups(keep=14)
    return {"status": "ok", "pruned": pruned, **meta}


@router.get("/backups")
def get_backups(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """백업 파일 목록."""
    _require_admin(current_user)
    from scripts.backup_db import list_backups
    return {"backups": list_backups()}


@router.get("/alerts")
def operational_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """관리자 운영 알림용 실시간 신호 (서버 계산).

    Settings의 '운영 알림 설정' 토글이 이 신호를 구독한다. 모두 실데이터 기반:
      - audit       : 감사 로그 해시 체인 무결성 (위변조 탐지)
      - backup      : 최근 백업 경과/누락 (7일 초과 또는 0건 → overdue)
      - tools       : 최근 24h 수집 오류 건수 (도구 연결 실패 추정)
      - assessments : 완료 진단 누계 (클라이언트가 직전 값과 비교해 '신규' 판단)
    """
    _require_admin(current_user)
    from datetime import datetime, timezone, timedelta
    from services.integrity import audit_row_hash
    from scripts.backup_db import list_backups

    # 1) 감사 로그 무결성 (해시 체인 재계산)
    rows = db.query(AuthAuditLog).order_by(AuthAuditLog.audit_id.asc()).all()
    prev = None
    broken = 0
    for r in rows:
        if not r.row_hash:
            prev = None
            continue
        expected = audit_row_hash(
            r.prev_hash, event_type=r.event_type, user_id=r.user_id,
            login_id=r.login_id, source_ip=r.source_ip, success=r.success,
            created_at=r.created_at.isoformat() if r.created_at else None,
        )
        link_ok = (prev is None) or (r.prev_hash == prev)
        if expected != r.row_hash or not link_ok:
            broken += 1
        prev = r.row_hash

    # 2) 백업 경과/누락
    backups = list_backups()
    last_at = backups[0]["modified_at"] if backups else None
    overdue = len(backups) == 0
    if last_at:
        try:
            dt = datetime.fromisoformat(last_at)
            overdue = (datetime.now(timezone.utc) - dt) > timedelta(days=7)
        except Exception:
            pass

    # 3) 최근 24h 수집 오류 (도구 연결 실패 추정)
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
    tool_failures = db.query(func.count(CollectedData.data_id)).filter(
        CollectedData.collected_at >= since,
        CollectedData.error.isnot(None),
    ).scalar() or 0

    # 4) 완료 진단 누계
    completed = db.query(func.count(DiagnosisSession.session_id)).filter(
        DiagnosisSession.status == "완료"
    ).scalar() or 0

    return {
        "checked_at":  datetime.now(timezone.utc).isoformat(),
        "audit":       {"ok": broken == 0, "broken_count": broken},
        "backup":      {"overdue": overdue, "last_at": last_at, "count": len(backups)},
        "tools":       {"recent_failures": int(tool_failures)},
        "assessments": {"completed_total": int(completed)},
    }
