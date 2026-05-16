"""cleanup_old_sessions — retention 정책 + 시드 보호 검증."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest


def _mk_session(db, org_id: int, user_id: int, started_at: datetime, status: str = "완료"):
    from models import DiagnosisSession
    s = DiagnosisSession(
        org_id=org_id, user_id=user_id, status=status,
        started_at=started_at, level="초기", total_score=10.0,
        selected_tools={}, extra={},
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def _setup_orgs_and_user(db):
    from models import Organization, User
    seed = Organization(name="세종대학교")
    normal = Organization(name="일반조직")
    db.add_all([seed, normal])
    db.flush()
    u = User(
        org_id=normal.org_id, name="tester", email="t@local", role="user",
        login_id="tester", password_hash="pbkdf2$1$00$00",
    )
    db.add(u)
    db.commit()
    db.refresh(seed)
    db.refresh(normal)
    db.refresh(u)
    return seed, normal, u


def test_dry_run_counts_only(db_session):
    from scripts.cleanup_old_sessions import cleanup_old_sessions
    seed, normal, u = _setup_orgs_and_user(db_session)
    old = datetime.now(timezone.utc) - timedelta(days=200)
    _mk_session(db_session, normal.org_id, u.user_id, started_at=old)

    result = cleanup_old_sessions(days=90, dry_run=True)
    assert result["dry_run"] is True
    assert result["checked"] >= 1
    assert result["deleted"] == 0


def test_demo_protected_when_flag_true(db_session, monkeypatch):
    from scripts.cleanup_old_sessions import cleanup_old_sessions
    monkeypatch.setenv("ZTA_PROTECT_DEMO_DATA", "true")
    seed, normal, u = _setup_orgs_and_user(db_session)
    old = datetime.now(timezone.utc) - timedelta(days=200)
    _mk_session(db_session, seed.org_id, u.user_id, started_at=old)         # 시드
    _mk_session(db_session, normal.org_id, u.user_id, started_at=old)       # 일반

    result = cleanup_old_sessions(days=0, dry_run=False)
    assert result["deleted"] >= 1
    assert result["preserved_demo"] >= 1


def test_demo_not_protected_when_flag_false(db_session, monkeypatch):
    from scripts.cleanup_old_sessions import cleanup_old_sessions
    monkeypatch.setenv("ZTA_PROTECT_DEMO_DATA", "false")
    seed, normal, u = _setup_orgs_and_user(db_session)
    old = datetime.now(timezone.utc) - timedelta(days=200)
    _mk_session(db_session, seed.org_id, u.user_id, started_at=old)
    _mk_session(db_session, normal.org_id, u.user_id, started_at=old)

    result = cleanup_old_sessions(days=0, dry_run=False)
    # ZTA_PROTECT_DEMO_DATA=false 시 시드 포함 모두 삭제 시도
    assert result["preserved_demo"] == 0
    assert result["deleted"] >= 2


def test_child_tables_cascade(db_session, monkeypatch):
    """세션 삭제 시 자식 5개 테이블(CD/EV/DR/MS/SH)도 함께 삭제된다."""
    from scripts.cleanup_old_sessions import cleanup_old_sessions
    from models import (
        Checklist, CollectedData, Evidence, DiagnosisResult,
        MaturityScore, ScoreHistory,
    )
    monkeypatch.setenv("ZTA_PROTECT_DEMO_DATA", "false")
    seed, normal, u = _setup_orgs_and_user(db_session)
    old = datetime.now(timezone.utc) - timedelta(days=200)
    s = _mk_session(db_session, normal.org_id, u.user_id, started_at=old)
    cl = db_session.query(Checklist).first()
    assert cl is not None  # 시드 체크리스트가 있음

    db_session.add(CollectedData(
        session_id=s.session_id, check_id=cl.check_id, tool="keycloak",
        metric_key="x", metric_value=1.0,
    ))
    db_session.add(Evidence(
        session_id=s.session_id, check_id=cl.check_id, source="kc",
    ))
    db_session.add(DiagnosisResult(
        session_id=s.session_id, check_id=cl.check_id, result="pass", score=1.0,
    ))
    db_session.add(MaturityScore(
        session_id=s.session_id, pillar="사용자(Identity)", score=1.0,
    ))
    db_session.add(ScoreHistory(
        session_id=s.session_id, org_id=normal.org_id, total_score=1.0, maturity_level="기존",
    ))
    db_session.commit()

    result = cleanup_old_sessions(days=0, dry_run=False)
    assert result["deleted"] >= 1

    # 자식 행 0건
    for Model in (CollectedData, Evidence, DiagnosisResult, MaturityScore, ScoreHistory):
        remaining = db_session.query(Model).filter(Model.session_id == s.session_id).count()
        assert remaining == 0, f"{Model.__name__} 가 정리되지 않음"
