"""multi-tenant 격리 — 일반 user 가 타 조직 세션 접근 시 403."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest


def _create_session_for(db_session, user, status: str = "완료") -> int:
    """직접 DB에 진단 세션을 만들고 session_id 반환."""
    from models import DiagnosisSession
    s = DiagnosisSession(
        org_id=user.org_id,
        user_id=user.user_id,
        status=status,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc) if status == "완료" else None,
        level="초기",
        total_score=42.0,
        selected_tools={"keycloak": True},
        extra={},
    )
    db_session.add(s)
    db_session.commit()
    db_session.refresh(s)
    return s.session_id


@pytest.fixture()
def two_users_and_admin(db_session, make_user):
    """user1(org_A), user2(org_B), admin(org_C) — 격리 검증의 기본 세팅."""
    a1, _, u1 = make_user("u1", role="user", org_name="org-A")
    a2, _, u2 = make_user("u2", role="user", org_name="org-B")
    a3, _, ua = make_user("admin1", role="admin", org_name="org-admin")
    return {
        "u1": (a1, u1),
        "u2": (a2, u2),
        "admin": (a3, ua),
    }


def test_idor_get_result_blocked(client, db_session, two_users_and_admin, auth_headers):
    a1, u1 = two_users_and_admin["u1"]
    a2, _u2 = two_users_and_admin["u2"]
    sid = _create_session_for(db_session, u1)
    r = client.get(f"/api/assessment/result?session_id={sid}", headers=auth_headers(a2))
    assert r.status_code == 403


def test_idor_status_blocked(client, db_session, two_users_and_admin, auth_headers):
    a1, u1 = two_users_and_admin["u1"]
    a2, _u2 = two_users_and_admin["u2"]
    sid = _create_session_for(db_session, u1, status="진행 중")
    r = client.get(f"/api/assessment/status/{sid}", headers=auth_headers(a2))
    assert r.status_code == 403


def test_idor_finalize_blocked(client, db_session, two_users_and_admin, auth_headers):
    a1, u1 = two_users_and_admin["u1"]
    a2, _u2 = two_users_and_admin["u2"]
    sid = _create_session_for(db_session, u1, status="진행 중")
    r = client.post(f"/api/assessment/finalize/{sid}", headers=auth_headers(a2))
    assert r.status_code == 403


def test_idor_report_generate_blocked(client, db_session, two_users_and_admin, auth_headers):
    a1, u1 = two_users_and_admin["u1"]
    a2, _u2 = two_users_and_admin["u2"]
    sid = _create_session_for(db_session, u1)
    r = client.get(f"/api/report/generate?session_id={sid}", headers=auth_headers(a2))
    assert r.status_code == 403


def test_idor_compare_blocked(client, db_session, two_users_and_admin, auth_headers):
    a1, u1 = two_users_and_admin["u1"]
    a2, u2 = two_users_and_admin["u2"]
    sid1 = _create_session_for(db_session, u1)
    sid2 = _create_session_for(db_session, u2)
    # u2 토큰으로 u2->u1 비교 시도 (to_id=sid1 은 u1 소유) → 403
    r = client.get(
        f"/api/assessment/compare?from_id={sid2}&to_id={sid1}",
        headers=auth_headers(a2),
    )
    assert r.status_code == 403


def test_admin_can_access_any_session(client, db_session, two_users_and_admin, auth_headers):
    a1, u1 = two_users_and_admin["u1"]
    a2, u2 = two_users_and_admin["u2"]
    a_admin, _ = two_users_and_admin["admin"]
    sid1 = _create_session_for(db_session, u1)
    sid2 = _create_session_for(db_session, u2)
    for sid in (sid1, sid2):
        r = client.get(f"/api/assessment/result?session_id={sid}", headers=auth_headers(a_admin))
        assert r.status_code == 200, f"admin should access session {sid}: {r.text}"


def test_run_other_org_blocked(client, db_session, two_users_and_admin, auth_headers):
    """user1 이 user2 조직 이름으로 /run 시도 → 403."""
    a1, u1 = two_users_and_admin["u1"]
    # u1 이 자기 org가 아닌 'org-B' 로 진단 시도
    r = client.post(
        "/api/assessment/run",
        json={
            "org_name": "org-B",  # u2의 조직
            "manager": "u1",
            "email": "u1@local",
            "tool_scope": {"keycloak": True},
        },
        headers=auth_headers(a1),
    )
    assert r.status_code == 403, r.text


def test_history_user_scoped(client, db_session, two_users_and_admin, auth_headers):
    """일반 user는 자기 조직 세션만, admin은 전체."""
    a1, u1 = two_users_and_admin["u1"]
    a2, u2 = two_users_and_admin["u2"]
    a_admin, _ = two_users_and_admin["admin"]
    sid1 = _create_session_for(db_session, u1)
    sid2 = _create_session_for(db_session, u2)

    r1 = client.get("/api/assessment/history", headers=auth_headers(a1))
    assert r1.status_code == 200
    ids1 = {s["id"] for s in r1.json()["sessions"]}
    assert sid1 in ids1 and sid2 not in ids1

    ra = client.get("/api/assessment/history", headers=auth_headers(a_admin))
    assert ra.status_code == 200
    ids_admin = {s["id"] for s in ra.json()["sessions"]}
    assert sid1 in ids_admin and sid2 in ids_admin


def test_me_missing_header_401(client):
    r = client.get("/api/auth/me")
    assert r.status_code == 401


def test_expired_token_401(client, make_user):
    """만료된 토큰으로 보호 엔드포인트 호출 시 401."""
    from datetime import timedelta
    from routers.auth import _create_token, JWT_ALG, JWT_SECRET
    import jwt as pyjwt
    from datetime import datetime, timezone

    _access, _refresh, user = make_user("zoe")
    # 직접 만료 토큰 생성
    now = datetime.now(timezone.utc) - timedelta(hours=10)
    payload = {
        "sub": user.login_id, "uid": user.user_id, "role": user.role,
        "kind": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=1)).timestamp()),
        "jti": "test",
    }
    expired = pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401
