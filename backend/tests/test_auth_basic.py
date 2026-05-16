"""회원가입/로그인/토큰 회귀 방지 — auth.py 본문은 손대지 않고 흐름만 검증."""
from __future__ import annotations

import time

import pytest

from routers import auth as _auth


@pytest.fixture(autouse=True)
def _reset_login_state():
    """테스트 간 in-memory 잠금 카운터가 교차 오염되지 않도록 매번 리셋."""
    with _auth._login_state_lock:
        _auth._login_state.clear()
        _auth._login_ip_state.clear()
    yield
    with _auth._login_state_lock:
        _auth._login_state.clear()
        _auth._login_ip_state.clear()


def _register_body(login_id: str = "alice", password: str = "Passw0rd!", **kw):
    body = {
        "login_id": login_id,
        "password": password,
        "name": login_id,
        "tos_agreed": True,
        "privacy_agreed": True,
    }
    body.update(kw)
    return body


def test_register_ok(client):
    r = client.post("/api/auth/register", json=_register_body())
    assert r.status_code == 200, r.text
    body = r.json()
    assert "user" in body and "tokens" in body
    assert body["user"]["login_id"] == "alice"
    assert body["user"]["role"] == "user"
    assert body["tokens"]["access_token"]
    assert body["tokens"]["refresh_token"]


def test_register_requires_tos(client):
    r = client.post("/api/auth/register", json=_register_body(tos_agreed=False))
    assert r.status_code == 400


def test_register_requires_privacy(client):
    r = client.post("/api/auth/register", json=_register_body(privacy_agreed=False))
    assert r.status_code == 400


def test_register_password_too_short(client):
    r = client.post("/api/auth/register", json=_register_body(password="Ab1!"))
    # Pydantic validator 또는 본문 검증으로 422 또는 400.
    assert r.status_code in (400, 422), r.text


def test_register_password_letters_only(client):
    r = client.post("/api/auth/register", json=_register_body(password="OnlyLetters"))
    assert r.status_code in (400, 422), r.text


def test_register_password_digits_only(client):
    r = client.post("/api/auth/register", json=_register_body(password="12345678"))
    assert r.status_code in (400, 422), r.text


def test_register_blocks_seed_org_join(client):
    # _PROTECTED_ORG_NAMES 안에 있는 조직명으로 가입 시도 → 400
    r = client.post(
        "/api/auth/register",
        json=_register_body(
            login_id="seedjoiner",
            profile={"org_name": "세종대학교"},
        ),
    )
    assert r.status_code == 400


def test_register_personal_org_key(client, db_session):
    from models import Organization, User
    r = client.post("/api/auth/register", json=_register_body(login_id="solo"))
    assert r.status_code == 200, r.text
    db_session.expire_all()
    user = db_session.query(User).filter(User.login_id == "solo").first()
    assert user is not None
    org = db_session.query(Organization).filter(Organization.org_id == user.org_id).first()
    assert org is not None and org.name == "solo_개인"


def test_login_ok_records_audit(client, db_session):
    client.post("/api/auth/register", json=_register_body(login_id="bob"))
    r = client.post("/api/auth/login", json={"login_id": "bob", "password": "Passw0rd!"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tokens"]["access_token"]
    # audit_db에 login_ok 행이 있어야 함
    from models import AuthAuditLog
    db_session.expire_all()
    rows = db_session.query(AuthAuditLog).filter(AuthAuditLog.event_type == "login_ok").all()
    assert len(rows) >= 1


def test_login_bad_password(client, db_session):
    client.post("/api/auth/register", json=_register_body(login_id="carol"))
    r = client.post("/api/auth/login", json={"login_id": "carol", "password": "WrongPass1"})
    assert r.status_code == 401
    from models import AuthAuditLog
    db_session.expire_all()
    rows = db_session.query(AuthAuditLog).filter(AuthAuditLog.event_type == "login_fail").all()
    assert len(rows) >= 1


def test_login_lock_after_5_failures(client):
    client.post("/api/auth/register", json=_register_body(login_id="dave"))
    # 5번 실패 → 6번째는 423
    for _ in range(_auth.LOGIN_MAX_ATTEMPTS):
        r = client.post("/api/auth/login", json={"login_id": "dave", "password": "WrongPass1"})
        assert r.status_code == 401
    r = client.post("/api/auth/login", json={"login_id": "dave", "password": "Passw0rd!"})
    assert r.status_code == 423, r.text


def test_login_lock_not_bypassed_by_ip_change(client):
    """같은 login_id 에 대한 잠금은 IP를 바꿔도 풀리지 않는다."""
    client.post("/api/auth/register", json=_register_body(login_id="eve"))
    # 첫 IP에서 5회 실패
    for _ in range(_auth.LOGIN_MAX_ATTEMPTS):
        client.post(
            "/api/auth/login",
            json={"login_id": "eve", "password": "WrongPass1"},
            headers={"X-Forwarded-For": "10.0.0.1"},
        )
    # 다른 IP에서 정답 시도 → 여전히 423 (login_id 잠금)
    r = client.post(
        "/api/auth/login",
        json={"login_id": "eve", "password": "Passw0rd!"},
        headers={"X-Forwarded-For": "10.0.0.99"},
    )
    assert r.status_code == 423


def test_refresh_ok(client):
    rr = client.post("/api/auth/register", json=_register_body(login_id="frank"))
    refresh = rr.json()["tokens"]["refresh_token"]
    r = client.post("/api/auth/refresh", json={"refresh_token": refresh})
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"]
    assert body["refresh_token"]


def test_refresh_with_access_token_rejected(client):
    """access 토큰을 refresh로 쓰면 401."""
    rr = client.post("/api/auth/register", json=_register_body(login_id="gina"))
    access = rr.json()["tokens"]["access_token"]
    r = client.post("/api/auth/refresh", json={"refresh_token": access})
    assert r.status_code == 401


def test_delete_account_self(client, db_session, make_user, auth_headers):
    access, _refresh, user = make_user("henry", password="Passw0rd!")
    uid = user.user_id
    r = client.request(
        "DELETE",
        "/api/auth/me",
        json={"current_password": "Passw0rd!"},
        headers=auth_headers(access),
    )
    assert r.status_code == 200, r.text
    from models import User
    db_session.expire_all()
    assert db_session.query(User).filter(User.user_id == uid).first() is None
