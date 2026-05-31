"""settings.py — 조직별 진단 설정.

SFR-EVAL-004 목표 성숙도(pillar 별 목표 점수) + SFR-CUS-001 체크리스트 커스터마이징
(항목 enable/disable + 가중치 오버라이드)을 백엔드에 영속화한다. 기존엔 목표값이
프론트 localStorage 에만 있었으나, 이제 조직 단위로 저장되어 결과/리포트의 gap
계산과 채점에 실제로 반영된다.

권한: 본인 조직만(admin 은 org_id 로 임의 조직). get_current_user + assert_org_access.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import (
    Checklist, OrgChecklistOverride, OrgTargetScore, User,
)
from routers.auth import get_current_user, assert_org_access

router = APIRouter()

# 6대 Pillar 정식 명칭 — 목표 점수 키 검증용.
_VALID_PILLARS = {
    "식별자 및 신원",
    "기기 및 엔드포인트",
    "네트워크",
    "시스템",
    "애플리케이션 및 워크로드",
    "데이터",
}

_DEFAULT_TARGETS = {
    "식별자 및 신원":          3.5,
    "기기 및 엔드포인트":       3.5,
    "네트워크":                3.0,
    "시스템":                  3.5,
    "애플리케이션 및 워크로드":  3.5,
    "데이터":                  3.0,
}


def _resolve_org_id(current_user: User, org_id: Optional[int]) -> int:
    """대상 조직 결정. 일반 user 는 자기 조직 강제, admin 은 org_id 지정 가능."""
    if current_user.role == "admin" and org_id is not None:
        return org_id
    return current_user.org_id


# ─── 목표 성숙도 (SFR-EVAL-004) ────────────────────────────────────────────────

class TargetUpdate(BaseModel):
    org_id: Optional[int] = None
    targets: dict = Field(default_factory=dict)   # {pillar: score(0~4)}


@router.get("/targets")
def get_targets(
    org_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target_org = _resolve_org_id(current_user, org_id)
    assert_org_access(current_user, target_org)
    out = dict(_DEFAULT_TARGETS)
    rows = db.query(OrgTargetScore).filter(OrgTargetScore.org_id == target_org).all()
    for r in rows:
        out[r.pillar] = r.target_score
    return {"org_id": target_org, "targets": out, "defaults": _DEFAULT_TARGETS}


@router.put("/targets")
def put_targets(
    req: TargetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target_org = _resolve_org_id(current_user, req.org_id)
    assert_org_access(current_user, target_org)
    if not req.targets:
        raise HTTPException(status_code=400, detail="targets 가 비어 있습니다.")
    updated = 0
    for pillar, score in req.targets.items():
        if pillar not in _VALID_PILLARS:
            raise HTTPException(status_code=400, detail=f"알 수 없는 pillar: {pillar}")
        try:
            val = float(score)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail=f"{pillar} 목표값이 숫자가 아닙니다.")
        if not (0.0 <= val <= 4.0):
            raise HTTPException(status_code=400, detail=f"{pillar} 목표값은 0~4 범위여야 합니다.")
        row = db.query(OrgTargetScore).filter(
            OrgTargetScore.org_id == target_org, OrgTargetScore.pillar == pillar
        ).first()
        if row:
            row.target_score = val
        else:
            db.add(OrgTargetScore(org_id=target_org, pillar=pillar, target_score=val))
        updated += 1
    db.commit()
    return {"status": "ok", "org_id": target_org, "updated": updated}


# ─── 체크리스트 커스터마이징 (SFR-CUS-001) ─────────────────────────────────────

class OverrideRow(BaseModel):
    check_id: int
    enabled: bool = True
    weight: Optional[float] = Field(default=None, ge=0.1, le=10.0)


class OverrideUpdate(BaseModel):
    org_id: Optional[int] = None
    overrides: list[OverrideRow] = Field(default_factory=list)


@router.get("/checklist-overrides")
def get_overrides(
    org_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target_org = _resolve_org_id(current_user, org_id)
    assert_org_access(current_user, target_org)
    rows = db.query(OrgChecklistOverride).filter(
        OrgChecklistOverride.org_id == target_org
    ).all()
    by_check = {r.check_id: r for r in rows}
    # 오버라이드가 걸린 항목의 체크리스트 메타도 함께 반환 (UI 표시용).
    meta = {}
    if by_check:
        cls = db.query(Checklist).filter(Checklist.check_id.in_(list(by_check.keys()))).all()
        meta = {c.check_id: c for c in cls}
    return {
        "org_id": target_org,
        "overrides": [
            {
                "check_id": r.check_id,
                "enabled": bool(r.enabled),
                "weight": r.weight,
                "item_id": meta[r.check_id].item_id if r.check_id in meta else None,
                "item_name": meta[r.check_id].item_name if r.check_id in meta else None,
                "pillar": meta[r.check_id].pillar if r.check_id in meta else None,
            }
            for r in rows
        ],
    }


@router.put("/checklist-overrides")
def put_overrides(
    req: OverrideUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target_org = _resolve_org_id(current_user, req.org_id)
    assert_org_access(current_user, target_org)
    if not req.overrides:
        raise HTTPException(status_code=400, detail="overrides 가 비어 있습니다.")

    valid_check_ids = {
        c.check_id for c in db.query(Checklist.check_id).filter(
            Checklist.check_id.in_([o.check_id for o in req.overrides])
        ).all()
    }
    upserted = 0
    for o in req.overrides:
        if o.check_id not in valid_check_ids:
            raise HTTPException(status_code=400, detail=f"존재하지 않는 check_id: {o.check_id}")
        row = db.query(OrgChecklistOverride).filter(
            OrgChecklistOverride.org_id == target_org,
            OrgChecklistOverride.check_id == o.check_id,
        ).first()
        # enabled=True + weight=None 인 항목(=기본값과 동일)은 오버라이드 행 제거로 정리.
        is_noop = o.enabled and o.weight is None
        if row:
            if is_noop:
                db.delete(row)
            else:
                row.enabled = 1 if o.enabled else 0
                row.weight = o.weight
        elif not is_noop:
            db.add(OrgChecklistOverride(
                org_id=target_org, check_id=o.check_id,
                enabled=1 if o.enabled else 0, weight=o.weight,
            ))
        upserted += 1
    db.commit()
    return {"status": "ok", "org_id": target_org, "applied": upserted}
