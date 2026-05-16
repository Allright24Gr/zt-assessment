"""pytest fixtures — backend 자체 검증(회귀 방지, multi-tenant 격리).

운영 MySQL 대신 sqlite in-memory DB를 사용한다. FastAPI 앱 import 시점에
database.py 가 SessionLocal/engine 을 만들어두므로, 테스트 시작 시점에 그
모듈 전역을 sqlite engine으로 monkeypatch 한 뒤 `get_db` 의존성을 override 한다.

원칙:
- 외부 도구(Keycloak/Wazuh 등) collector 호출은 하지 않는다. /run 백그라운드 태스크는
  `_run_collectors` 가 직접 트리거되지만 TestClient는 background task 를 실행한 뒤
  응답을 반환하므로 외부 호출이 실패해도 응답 자체는 정상이다. 그래도 안정성을 위해
  관련 의존 외부 자원(MySQL, HTTP)이 없으므로 sqlite로 한정.
- 보안 감사 로그 / cleanup 등 부수 효과는 sqlite에서 동작하도록 만들어졌다.
"""
from __future__ import annotations

import os
import sys
import importlib
from datetime import datetime, timezone
from typing import Iterator, Optional

# 테스트가 import 되기 전에 환경 변수 설정 — auth.py의 JWT_SECRET 임시 키 경고를 막고,
# 동일 키로 토큰 재사용이 가능하게 한다.
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-pytest-only-do-not-use-in-prod")
os.environ.setdefault("ZTA_CLEANUP_DISABLE", "true")
os.environ.setdefault("INTERNAL_API_TOKEN", "test-internal-token")

# backend 패키지를 import 가능하게.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# database 먼저 import해서 engine/SessionLocal을 swap한 뒤 models를 import 한다.
import database as _database

# sqlite 메모리 DB. StaticPool + check_same_thread=False 로 멀티 스레드(BackgroundTasks)
# 환경에서도 같은 in-memory DB가 보이도록.
_TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_TestSession = sessionmaker(autocommit=False, autoflush=False, bind=_TEST_ENGINE)

# 모듈 전역 SessionLocal/engine 도 swap — 일부 함수(cleanup_old_sessions 등)가
# database.SessionLocal() 을 직접 호출한다.
_database.engine = _TEST_ENGINE
_database.SessionLocal = _TestSession

# 이제 모델/앱 모듈 import. Base.metadata 도 swap된 engine 으로 create_all.
from database import Base  # noqa: E402
import models as _models  # noqa: E402 — 모델 클래스 로드
from main import app  # noqa: E402
from database import get_db  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

Base.metadata.create_all(bind=_TEST_ENGINE)


# ─── 시드 체크리스트 ────────────────────────────────────────────────────────
# pillar 별 1~2개씩만. 채점/이력 흐름을 굳이 검증하지 않는 케이스 대부분이 통과.
_SEED_CHECKLISTS = [
    # (item_id, pillar, category, item_name, maturity, score, dx_type, tool)
    ("1.1.1.1_1", "사용자(Identity)",   "신원관리",   "사용자 인벤토리",   "기존",   1, "수동", "수동"),
    ("1.1.1.2_1", "사용자(Identity)",   "신원관리",   "사용자/역할 비율", "초기",   2, "자동", "keycloak"),
    ("2.1.1.1_1", "기기(Device)",       "기기관리",   "기기 인벤토리",     "기존",   1, "수동", "수동"),
    ("2.3.1.1_2", "기기(Device)",       "기기관리",   "에이전트 등록",    "기존",   1, "자동", "wazuh"),
    ("3.1.1.1_1", "네트워크(Network)",  "네트워크",   "서브넷 토폴로지",  "기존",   1, "자동", "nmap"),
    ("4.1.1.2_1", "애플리케이션",        "접근통제",   "중앙 인가 정책",   "초기",   2, "자동", "keycloak"),
    ("5.4.1.2_2", "데이터(Data)",        "이미지검사", "컨테이너 이미지 스캔", "초기", 2, "자동", "trivy"),
    ("6.1.1.2_1", "가시성·분석",         "FIM",        "FIM 상태",         "초기",   2, "자동", "wazuh"),
]


def _seed_checklists(db) -> None:
    from models import Checklist
    if db.query(Checklist).count() > 0:
        return
    for item_id, pillar, category, item_name, maturity, score, dx, tool in _SEED_CHECKLISTS:
        db.add(Checklist(
            item_id=item_id, item_num=item_id.split("_")[0], pillar=pillar,
            category=category, item_name=item_name, maturity=maturity,
            maturity_score=score, diagnosis_type=dx, tool=tool,
            evidence="", criteria="", weight=0.1,
        ))
    db.commit()


# ─── pytest fixtures ────────────────────────────────────────────────────────


@pytest.fixture()
def db_session() -> Iterator:
    """각 테스트마다 깨끗한 sqlite 메모리 DB. metadata drop_all → create_all 로 격리."""
    # 깨끗한 상태로 시작
    Base.metadata.drop_all(bind=_TEST_ENGINE)
    Base.metadata.create_all(bind=_TEST_ENGINE)
    db = _TestSession()
    try:
        _seed_checklists(db)
        yield db
    finally:
        db.close()


@pytest.fixture()
def client(db_session) -> Iterator[TestClient]:
    """FastAPI TestClient — get_db 의존성을 sqlite session으로 override."""

    def _override_get_db():
        # 매 요청마다 새 session. 같은 engine(StaticPool)이므로 동일 DB.
        db = _TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture()
def make_user(db_session):
    """DB에 User + Organization 을 만들고 JWT 토큰까지 반환하는 헬퍼.

    사용 예:
        access, refresh, user = make_user("alice")
        access, _, _ = make_user("admin1", role="admin")
    """
    from routers.auth import _hash_password, _issue_token_pair
    from models import Organization, User

    def _factory(
        login_id: str,
        role: str = "user",
        org_name: Optional[str] = None,
        password: str = "Passw0rd!",
    ):
        org_name = org_name or f"{login_id}_개인"
        org = db_session.query(Organization).filter(Organization.name == org_name).first()
        if not org:
            org = Organization(name=org_name)
            db_session.add(org)
            db_session.flush()
        user = db_session.query(User).filter(User.login_id == login_id).first()
        if not user:
            now = datetime.now(timezone.utc)
            user = User(
                org_id=org.org_id,
                name=login_id,
                email=f"{login_id}@local",
                role=role,
                login_id=login_id,
                password_hash=_hash_password(password),
                tos_agreed_at=now,
                privacy_agreed_at=now,
            )
            db_session.add(user)
            db_session.commit()
            db_session.refresh(user)
        tokens = _issue_token_pair(user)
        return tokens.access_token, tokens.refresh_token, user

    return _factory


@pytest.fixture()
def auth_headers():
    """JWT 토큰을 Authorization 헤더로 감싸는 헬퍼."""
    def _make(token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}
    return _make
