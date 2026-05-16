"""auth.py — 회원가입/로그인. 비밀번호는 PBKDF2-SHA256 (stdlib)로 해싱.

엔드포인트:
- POST /api/auth/register         : 신규 사용자 + (선택) 조직 등록 + profile 저장
- POST /api/auth/login            : login_id + password 검증 (실패 잠금 적용). 성공 시 lazy upgrade
- GET  /api/auth/me               : X-Login-Id 헤더로 사용자 정보 조회 (간이 세션용)
- PUT  /api/auth/profile          : X-Login-Id 헤더 + current_password 재확인 후 profile 갱신
- POST /api/auth/change-password  : X-Login-Id 헤더 + current_password 검증 후 새 비번 적용

보안 정책:
- 비밀번호: 최소 8자, 영문+숫자 혼합. RegisterRequest/ChangePasswordRequest에서 validator로 검증.
- PBKDF2: 600,000 라운드 (OWASP 2023). 저장 형식 `pbkdf2$<iters>$<salt>$<hash>` 로 역호환.
- Lazy upgrade: login 성공 시 저장된 라운드 < 600,000 이면 새 해시로 자동 재저장.
- 로그인 실패 잠금: login_id별 in-memory 카운터, 5회 실패 후 60초 잠금 (423 Locked).
- audit log: 로그인 성공/실패/잠금, 프로필 변경, 비번 변경을 stdlib logger로 기록.
"""
import hashlib
import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt as pyjwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

from database import get_db
from models import AuthAuditLog, Organization, PasswordResetToken, User

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("zt.audit")  # 별도 채널 — 운영 시 별도 파일/SIEM 라우팅 가능

# ─── JWT 세션 (P0-1) ──────────────────────────────────────────────────────────
# access 8h / refresh 30d. SECRET_KEY 미설정 시 부팅 시 임시 키(경고). 운영엔 .env 필수.
JWT_ALG = "HS256"
JWT_ACCESS_TTL = timedelta(hours=int(os.getenv("ZTA_JWT_ACCESS_HOURS", "8")))
JWT_REFRESH_TTL = timedelta(days=int(os.getenv("ZTA_JWT_REFRESH_DAYS", "30")))
JWT_SECRET = os.getenv("SECRET_KEY", "") or os.getenv("JWT_SECRET", "")
if not JWT_SECRET:
    # 부팅마다 새 키 — 모든 기존 토큰 무효. 개발 편의용. 운영 경고.
    JWT_SECRET = secrets.token_urlsafe(48)
    logger.warning("[auth] SECRET_KEY 미설정 — 임시 JWT 키 사용. 부팅마다 토큰 만료됨.")


def _create_token(user: User, kind: str, ttl: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.login_id or str(user.user_id),
        "uid": user.user_id,
        "role": user.role,
        "kind": kind,             # "access" | "refresh"
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
        "jti": secrets.token_hex(8),
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def _decode_token(token: str) -> dict:
    """검증 통과 시 payload dict 반환. 실패 시 HTTPException(401)."""
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="토큰이 만료되었습니다.")
    except pyjwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")


# ─── audit log DB 영속화 (P0-3) ───────────────────────────────────────────────
# stdlib audit_logger와 병행. DB insert는 best-effort — 실패해도 본 흐름 차단 X.

def _audit_db(
    db: Optional[Session],
    event_type: str,
    *,
    user: Optional[User] = None,
    login_id: Optional[str] = None,
    success: bool = True,
    source_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    detail: Optional[dict] = None,
):
    if db is None:
        return
    try:
        row = AuthAuditLog(
            event_type=event_type,
            user_id=user.user_id if user else None,
            login_id=login_id or (user.login_id if user else None),
            source_ip=source_ip,
            user_agent=(user_agent or "")[:500] or None,
            success=1 if success else 0,
            detail=detail or None,
        )
        db.add(row)
        db.commit()
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        logger.warning("[audit] DB insert failed: %s", exc)


def _client_meta(request: Optional[Request]) -> tuple[Optional[str], Optional[str]]:
    if request is None:
        return None, None
    # X-Forwarded-For 우선 (nginx 통과 IP)
    fwd = request.headers.get("X-Forwarded-For", "")
    ip = (fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else None))
    ua = request.headers.get("User-Agent", "")[:500] or None
    return ip, ua
router = APIRouter()

# OWASP 2023 Password Storage Cheat Sheet 권장치(PBKDF2-SHA256 600k 이상).
# 저장 형식이 라운드 수를 포함하므로 기존 200k 해시도 _verify_password에서 그대로 검증 가능.
PBKDF2_ITERS = 600_000

# 로그인 실패 잠금 정책 (in-memory). 다중 프로세스 환경에서는 Redis 권장.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_SECONDS = 60

# 비밀번호 정책: 8자 이상 + 영문 1글자 + 숫자 1글자 (특수문자는 허용하되 강제 안 함)
_PASSWORD_LETTER_RE = re.compile(r"[A-Za-z]")
_PASSWORD_DIGIT_RE = re.compile(r"\d")


def _hash_password(password: str, salt: Optional[str] = None) -> str:
    """반환 형식: 'pbkdf2$<iters>$<hex_salt>$<hex_hash>'"""
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERS)
    return f"pbkdf2${PBKDF2_ITERS}${salt}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt, expected = stored.split("$", 3)
        if scheme != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iters))
        return secrets.compare_digest(dk.hex(), expected)
    except Exception:
        return False


def _stored_iters(stored: str) -> int:
    """저장 해시의 라운드 수. 파싱 실패 시 0."""
    try:
        scheme, iters, _, _ = stored.split("$", 3)
        if scheme != "pbkdf2":
            return 0
        return int(iters)
    except Exception:
        return 0


def _validate_password_policy(password: str) -> None:
    """RegisterRequest/ChangePasswordRequest 양쪽에서 사용. 위배 시 ValueError."""
    if len(password) < 8:
        raise ValueError("비밀번호는 8자 이상이어야 합니다.")
    if len(password) > 200:
        raise ValueError("비밀번호는 200자 이하여야 합니다.")
    if not _PASSWORD_LETTER_RE.search(password):
        raise ValueError("비밀번호에는 영문이 1자 이상 포함되어야 합니다.")
    if not _PASSWORD_DIGIT_RE.search(password):
        raise ValueError("비밀번호에는 숫자가 1자 이상 포함되어야 합니다.")


# ─── 로그인 실패 잠금 (in-memory) ─────────────────────────────────────────────
# P0-4: login_id 단위 + source IP 단위 양쪽 잠금. 다중 ID 폭격(IP 1개에서 여러 ID 시도) 차단.
# 다중 프로세스 환경에서는 Redis 권장 (PLAN.md P2-14).

# IP별 잠금 정책 — login_id별보다 헐겁게 (오용 방지). 30분 내 50회 실패 시 30분 잠금.
LOGIN_IP_MAX_ATTEMPTS = int(os.getenv("ZTA_LOGIN_IP_MAX", "50"))
LOGIN_IP_WINDOW_SECONDS = int(os.getenv("ZTA_LOGIN_IP_WINDOW", "1800"))
LOGIN_IP_LOCK_SECONDS = int(os.getenv("ZTA_LOGIN_IP_LOCK", "1800"))

_login_state_lock = threading.Lock()
# login_id → {"fails": int, "locked_until": float}
_login_state: dict[str, dict] = {}
# ip → {"fails": int, "window_start": float, "locked_until": float}
_login_ip_state: dict[str, dict] = {}


def _check_lock(login_id: str, source_ip: Optional[str] = None) -> None:
    """login_id 또는 source_ip 가 잠금 상태면 HTTPException 423."""
    now = time.time()
    with _login_state_lock:
        # login_id 잠금
        st = _login_state.get(login_id)
        if st and st.get("locked_until", 0) > now:
            retry_after = int(st["locked_until"] - now) + 1
            raise HTTPException(
                status_code=423,
                detail=f"로그인 실패 횟수 초과. {retry_after}초 후 다시 시도하세요.",
                headers={"Retry-After": str(retry_after)},
            )
        if st and st.get("locked_until", 0) and st["locked_until"] <= now:
            _login_state.pop(login_id, None)

        # IP 잠금
        if source_ip:
            ip_st = _login_ip_state.get(source_ip)
            if ip_st and ip_st.get("locked_until", 0) > now:
                retry_after = int(ip_st["locked_until"] - now) + 1
                raise HTTPException(
                    status_code=423,
                    detail=f"IP 차단 — {retry_after}초 후 다시 시도하세요.",
                    headers={"Retry-After": str(retry_after)},
                )
            if ip_st and ip_st.get("locked_until", 0) and ip_st["locked_until"] <= now:
                _login_ip_state.pop(source_ip, None)


def _record_login_failure(login_id: str, source_ip: Optional[str] = None) -> None:
    now = time.time()
    with _login_state_lock:
        # login_id 카운터
        st = _login_state.setdefault(login_id, {"fails": 0, "locked_until": 0.0})
        st["fails"] += 1
        if st["fails"] >= LOGIN_MAX_ATTEMPTS:
            st["locked_until"] = now + LOGIN_LOCK_SECONDS
            audit_logger.warning(
                "[auth] login_id=%s 잠금 적용: %d회 실패 → %ds 잠금",
                login_id, st["fails"], LOGIN_LOCK_SECONDS,
            )

        # IP 카운터 (sliding window)
        if source_ip:
            ip_st = _login_ip_state.setdefault(
                source_ip, {"fails": 0, "window_start": now, "locked_until": 0.0},
            )
            if now - ip_st["window_start"] > LOGIN_IP_WINDOW_SECONDS:
                ip_st["fails"] = 0
                ip_st["window_start"] = now
            ip_st["fails"] += 1
            if ip_st["fails"] >= LOGIN_IP_MAX_ATTEMPTS:
                ip_st["locked_until"] = now + LOGIN_IP_LOCK_SECONDS
                audit_logger.warning(
                    "[auth] IP=%s 잠금 적용: %d회 실패(%ds 윈도우) → %ds 잠금",
                    source_ip, ip_st["fails"], LOGIN_IP_WINDOW_SECONDS, LOGIN_IP_LOCK_SECONDS,
                )


def _record_login_success(login_id: str, source_ip: Optional[str] = None) -> None:
    with _login_state_lock:
        _login_state.pop(login_id, None)
        # IP는 성공 시 카운터 리셋하지 않음 (한 IP에서 여러 ID 시도 방지)


# ─── Pydantic schemas ────────────────────────────────────────────────────────

class ProfileFields(BaseModel):
    """진단 시 자동 prefill되는 사용자 프로필 (모두 선택)."""
    org_name: Optional[str] = None
    department: Optional[str] = None
    contact: Optional[str] = None
    org_type: Optional[str] = None        # 산업군
    infra_type: Optional[str] = None      # 인프라 유형
    employees: Optional[int] = None
    servers: Optional[int] = None
    applications: Optional[int] = None
    note: Optional[str] = None


class RegisterRequest(BaseModel):
    login_id: str = Field(min_length=2, max_length=100)
    password: str = Field(min_length=8, max_length=200)
    name: str = Field(min_length=1, max_length=100)
    email: Optional[str] = None
    profile: Optional[ProfileFields] = None
    # P0-5: 약관·개인정보 처리방침 동의 (정보통신망법·개인정보보호법 의무)
    tos_agreed: bool = False
    privacy_agreed: bool = False

    @field_validator("password")
    @classmethod
    def _password_policy(cls, v: str) -> str:
        _validate_password_policy(v)
        return v


class LoginRequest(BaseModel):
    login_id: str
    password: str


class UserResponse(BaseModel):
    user_id: int
    login_id: str
    name: str
    email: Optional[str]
    role: str
    org_id: int
    org_name: str
    profile: Optional[dict] = None


# AuthEnvelope: login/register/refresh 가 반환하는 envelope. 별도 BaseModel 없이 dict 응답.
# 형태: { "user": UserResponse, "tokens": TokenPair }


class ProfileUpdateRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    profile: ProfileFields


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=8, max_length=200)

    @field_validator("new_password")
    @classmethod
    def _password_policy(cls, v: str) -> str:
        _validate_password_policy(v)
        return v


# 시드/관리자가 생성한 조직 — 신규 가입자가 임의로 join 못 하도록 차단.
# seed_demo_examples.py에서 생성하는 시드 조직 이름과 일치해야 한다.
_PROTECTED_ORG_NAMES = {
    "시스템관리", "세종대학교",
    "ABC 핀테크", "XYZ 메디컬", "국가데이터센터", "스타트업 K",
}


def _resolve_user_or_401(db: Session, login_id: Optional[str]) -> User:
    """X-Login-Id 헤더로 사용자 식별. 누락/미존재 시 401."""
    if not login_id:
        raise HTTPException(status_code=401, detail="X-Login-Id 헤더가 필요합니다.")
    user = db.query(User).filter(User.login_id == login_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="인증되지 않은 사용자입니다.")
    return user


def get_current_user(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_login_id: Optional[str] = Header(None, alias="X-Login-Id"),
    db: Session = Depends(get_db),
) -> User:
    """FastAPI 의존성 — 보호 엔드포인트 인증 진입점.

    우선순위:
      1. Authorization: Bearer <JWT>  (P0-1 권장)
      2. X-Login-Id 헤더 (간이 호환. 추후 deprecation 예정)

    JWT 검증 실패 시 X-Login-Id로 fallback 하지 않고 401 반환 (혼선 방지).
    """
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        payload = _decode_token(token)
        if payload.get("kind") != "access":
            raise HTTPException(status_code=401, detail="access 토큰이 아닙니다.")
        login_id = payload.get("sub")
        return _resolve_user_or_401(db, login_id)
    return _resolve_user_or_401(db, x_login_id)


# ─── JWT 토큰 응답 + refresh 엔드포인트 (P0-1) ────────────────────────────────

class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int  # access_token 만료까지 남은 초


def _issue_token_pair(user: User) -> TokenPair:
    return TokenPair(
        access_token=_create_token(user, "access", JWT_ACCESS_TTL),
        refresh_token=_create_token(user, "refresh", JWT_REFRESH_TTL),
        expires_in=int(JWT_ACCESS_TTL.total_seconds()),
    )


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/refresh", response_model=TokenPair)
def refresh_token(req: RefreshRequest, db: Session = Depends(get_db)):
    """refresh_token으로 새 access(+refresh) 발급. 만료/무효 시 401."""
    payload = _decode_token(req.refresh_token)
    if payload.get("kind") != "refresh":
        raise HTTPException(status_code=401, detail="refresh 토큰이 아닙니다.")
    user = db.query(User).filter(User.login_id == payload.get("sub")).first()
    if not user:
        raise HTTPException(status_code=401, detail="사용자가 존재하지 않습니다.")
    return _issue_token_pair(user)


def assert_session_access(user: User, session_obj) -> None:
    """진단 세션 단위 권한 검증.

    - admin role: 모든 세션 접근 허용.
    - 일반 user: 같은 조직(org_id) 또는 본인(user_id) 세션만.
    위배 시 403.
    """
    if user.role == "admin":
        return
    if session_obj is None:
        raise HTTPException(status_code=404, detail="세션을 찾을 수 없습니다.")
    if session_obj.user_id == user.user_id:
        return
    if getattr(session_obj, "org_id", None) == user.org_id:
        return
    raise HTTPException(status_code=403, detail="해당 세션에 대한 권한이 없습니다.")


def assert_org_access(user: User, org_id: Optional[int]) -> None:
    """조직 단위 권한 검증 (점수 요약/이력 등)."""
    if user.role == "admin":
        return
    if org_id is not None and org_id != user.org_id:
        raise HTTPException(status_code=403, detail="해당 조직에 대한 권한이 없습니다.")


def _to_response(u: User, org: Optional[Organization]) -> UserResponse:
    return UserResponse(
        user_id=u.user_id,
        login_id=u.login_id or "",
        name=u.name,
        email=u.email,
        role=u.role,
        org_id=u.org_id,
        org_name=org.name if org else "",
        profile=u.profile or None,
    )


# ─── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/register")
def register(req: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    # P0-5: 약관·방침 동의 필수
    if not (req.tos_agreed and req.privacy_agreed):
        raise HTTPException(
            status_code=400,
            detail="이용약관과 개인정보 처리방침에 동의해야 가입할 수 있습니다.",
        )

    if db.query(User).filter(User.login_id == req.login_id).first():
        ip, ua = _client_meta(request)
        _audit_db(db, "register_fail", login_id=req.login_id,
                  source_ip=ip, user_agent=ua, success=False,
                  detail={"reason": "duplicate_login_id"})
        raise HTTPException(status_code=409, detail="이미 사용 중인 아이디입니다.")

    profile_dict = req.profile.model_dump(exclude_none=True) if req.profile else {}

    # 조직 upsert 규칙
    # - profile.org_name 미제공: "{login_id}_개인" 유일 키로 개인 조직 생성 (동명이인 충돌 방지)
    # - profile.org_name 제공: 동일 이름 기존 조직에 join. 단 시드/관리 조직(시스템관리, 세종대학교 등)에
    #   임의 사용자가 자동 편입되는 것을 막기 위해 _PROTECTED_ORG_NAMES에 포함된 이름은 차단.
    user_org_name = (profile_dict.get("org_name") or "").strip()
    if user_org_name:
        if user_org_name in _PROTECTED_ORG_NAMES:
            raise HTTPException(
                status_code=400,
                detail=f"'{user_org_name}'은(는) 시드 조직 이름과 충돌합니다. 다른 조직명을 사용하세요.",
            )
        org_name = user_org_name
    else:
        org_name = f"{req.login_id}_개인"
    org = db.query(Organization).filter(Organization.name == org_name).first()
    if not org:
        org = Organization(
            name=org_name,
            industry=profile_dict.get("org_type"),
            cloud_type=profile_dict.get("infra_type"),
        )
        db.add(org)
        db.flush()

    # email은 unique이라 비어있으면 login_id 기반 placeholder를 만들어 충돌 회피
    email = (req.email or f"{req.login_id}@local").strip()
    if db.query(User).filter(User.email == email).first():
        email = f"{req.login_id}+{secrets.token_hex(3)}@local"

    now = datetime.now(timezone.utc)
    user = User(
        org_id=org.org_id,
        name=req.name,
        email=email,
        role="user",
        login_id=req.login_id,
        password_hash=_hash_password(req.password),
        profile=profile_dict or None,
        tos_agreed_at=now,
        privacy_agreed_at=now,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    ip, ua = _client_meta(request)
    audit_logger.info("[auth] register login_id=%s org=%s", req.login_id, org_name)
    _audit_db(db, "register", user=user, source_ip=ip, user_agent=ua,
              detail={"org_name": org_name})
    return {
        "user":   _to_response(user, org).model_dump(),
        "tokens": _issue_token_pair(user).model_dump(),
    }


@router.post("/login")
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip, ua = _client_meta(request)
    _check_lock(req.login_id, source_ip=ip)

    user = db.query(User).filter(User.login_id == req.login_id).first()
    if not user or not user.password_hash:
        _record_login_failure(req.login_id, source_ip=ip)
        audit_logger.info("[auth] login fail login_id=%s reason=no_user", req.login_id)
        _audit_db(db, "login_fail", login_id=req.login_id, source_ip=ip, user_agent=ua,
                  success=False, detail={"reason": "no_user"})
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")
    if not _verify_password(req.password, user.password_hash):
        _record_login_failure(req.login_id, source_ip=ip)
        audit_logger.info("[auth] login fail login_id=%s reason=bad_password", req.login_id)
        _audit_db(db, "login_fail", user=user, source_ip=ip, user_agent=ua,
                  success=False, detail={"reason": "bad_password"})
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")

    _record_login_success(req.login_id, source_ip=ip)
    audit_logger.info("[auth] login ok login_id=%s user_id=%s", req.login_id, user.user_id)
    _audit_db(db, "login_ok", user=user, source_ip=ip, user_agent=ua)

    # PBKDF2 lazy upgrade: 저장된 라운드가 현재 권장치 미만이면 새 해시로 재저장.
    if _stored_iters(user.password_hash) < PBKDF2_ITERS:
        try:
            user.password_hash = _hash_password(req.password)
            db.commit()
            db.refresh(user)
            audit_logger.info("[auth] pbkdf2 lazy upgrade login_id=%s → %d iters",
                              req.login_id, PBKDF2_ITERS)
        except Exception as exc:
            db.rollback()
            logger.warning("[auth] lazy upgrade 실패 login_id=%s: %s", req.login_id, exc)

    org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
    return {
        "user":   _to_response(user, org).model_dump(),
        "tokens": _issue_token_pair(user).model_dump(),
    }

    org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
    return _to_response(user, org)


@router.get("/me", response_model=UserResponse)
def me(
    x_login_id: Optional[str] = Header(None, alias="X-Login-Id"),
    db: Session = Depends(get_db),
):
    """간이 세션 — 클라이언트가 보관한 login_id를 X-Login-Id 헤더로 전달.

    query param 방식은 시연 URL 노출 시 IDOR 위험이 있어 폐기. 헤더는 표준
    크로스오리진 요청에서 자동으로 캐싱·로깅에 노출되지 않는다.
    """
    user = _resolve_user_or_401(db, x_login_id)
    org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
    return _to_response(user, org)


@router.put("/profile", response_model=UserResponse)
def update_profile(
    req: ProfileUpdateRequest,
    x_login_id: Optional[str] = Header(None, alias="X-Login-Id"),
    db: Session = Depends(get_db),
):
    """프로필 수정 — X-Login-Id로 식별 + current_password로 본인 재확인.

    body의 current_password가 저장된 해시와 일치하지 않으면 401. 별도 세션
    토큰이 없는 간이 인증 구조에서 IDOR(타인 프로필 덮어쓰기)을 막는 1차 방어선.
    """
    user = _resolve_user_or_401(db, x_login_id)
    if not user.password_hash or not _verify_password(req.current_password, user.password_hash):
        audit_logger.warning("[auth] profile update fail login_id=%s reason=bad_password", x_login_id)
        raise HTTPException(status_code=401, detail="비밀번호가 일치하지 않습니다.")
    user.profile = req.profile.model_dump(exclude_none=True)
    db.commit()
    db.refresh(user)
    audit_logger.info("[auth] profile update ok login_id=%s", x_login_id)
    org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
    return _to_response(user, org)


@router.post("/change-password")
def change_password(
    req: ChangePasswordRequest,
    x_login_id: Optional[str] = Header(None, alias="X-Login-Id"),
    db: Session = Depends(get_db),
):
    """비밀번호 변경 — current_password 검증 후 new_password 정책 통과 시 적용.

    동일 비번 재설정은 차단 (의미 없는 변경 방지).
    변경 성공 시 로그인 잠금 카운터도 리셋한다.
    """
    user = _resolve_user_or_401(db, x_login_id)
    if not user.password_hash or not _verify_password(req.current_password, user.password_hash):
        audit_logger.warning("[auth] change-password fail login_id=%s reason=bad_password", x_login_id)
        raise HTTPException(status_code=401, detail="현재 비밀번호가 일치하지 않습니다.")
    if _verify_password(req.new_password, user.password_hash):
        raise HTTPException(status_code=400, detail="새 비밀번호가 기존 비밀번호와 동일합니다.")
    user.password_hash = _hash_password(req.new_password)
    db.commit()
    _record_login_success(user.login_id or "")  # 잠금 카운터 리셋
    audit_logger.info("[auth] change-password ok login_id=%s", x_login_id)
    return {"status": "ok", "message": "비밀번호가 변경되었습니다."}


# ─── 비밀번호 재설정 (이메일 발송) ───────────────────────────────────────────────
# /request-password-reset : login_id 로 사용자 조회 → SHA-256 해시 토큰 발급 + 이메일 전송
# /reset-password         : 토큰 + new_password 로 실제 재설정 수행
#
# 보안 고려:
# - 사용자 존재 여부를 응답에서 노출하지 않는다 (enumeration 방지). 항상 200 + 동일 메시지.
# - 토큰은 평문(URL-safe 32바이트)을 메일로만 전달하고 DB에는 SHA-256 해시만 저장.
# - 새 요청 발급 시 기존 미사용 토큰은 used_at으로 무효화 (only-1-active 정책).
# - 만료 1시간 (timedelta(hours=1)). 만료/사용 토큰은 400.

class PasswordResetRequest(BaseModel):
    login_id: str = Field(min_length=1, max_length=100)


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=10, max_length=500)
    new_password: str = Field(min_length=8, max_length=200)

    @field_validator("new_password")
    @classmethod
    def _password_policy(cls, v: str) -> str:
        _validate_password_policy(v)
        return v


@router.post("/request-password-reset")
def request_password_reset(req: PasswordResetRequest, db: Session = Depends(get_db)):
    """비밀번호 재설정 토큰 발급 + 이메일 발송.

    응답은 항상 동일하게 200 + "재설정 메일을 발송했습니다(계정이 존재할 경우)." 를 반환한다.
    이를 통해 외부에서 login_id 존재 여부를 추측할 수 없도록 한다 (user enumeration 방지).
    """
    user = db.query(User).filter(User.login_id == req.login_id).first()
    if user and user.email:
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        # 기존 미사용 토큰을 모두 무효화 — 신규 요청 시 이전 메일의 링크는 동작하지 않게.
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.user_id,
            PasswordResetToken.used_at.is_(None),
        ).update({"used_at": func.now()})
        db.add(PasswordResetToken(
            user_id=user.user_id,
            token_hash=token_hash,
            expires_at=expires,
        ))
        db.commit()
        # 메일 발송은 best-effort — 실패해도 응답은 동일하게 200을 유지한다.
        try:
            from services.email_sender import send_email
            frontend_base = os.getenv("FRONTEND_BASE_URL", "http://localhost:8080")
            reset_url = f"{frontend_base}/auth/reset-password?token={raw_token}"
            send_email(user.email, "[Readyz-T] 비밀번호 재설정 안내", "password_reset", {
                "user_name": user.name,
                "reset_url": reset_url,
                "expires_at": expires.isoformat(),
            })
        except Exception as exc:  # noqa: BLE001 — 메일 실패가 사용자 흐름을 중단시키면 안 됨
            audit_logger.warning(
                "[auth] reset email failed login_id=%s err=%s", req.login_id, exc
            )
        audit_logger.info("[auth] password reset requested login_id=%s", req.login_id)
    else:
        # 존재하지 않는 사용자에 대해서도 동일 응답. 타이밍 차이를 최소화하기 위해
        # 무거운 작업(DB write, mail send)은 생략하지만 로그는 남긴다.
        audit_logger.info(
            "[auth] password reset requested for unknown login_id=%s", req.login_id
        )
    return {
        "status": "ok",
        "message": "재설정 메일을 발송했습니다(계정이 존재할 경우).",
    }


@router.post("/reset-password")
def reset_password(req: PasswordResetConfirm, db: Session = Depends(get_db)):
    """토큰으로 비밀번호 재설정. 성공 시 토큰을 즉시 used_at으로 마킹."""
    token_hash = hashlib.sha256(req.token.encode()).hexdigest()
    record = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == token_hash,
        PasswordResetToken.used_at.is_(None),
    ).first()
    if not record:
        audit_logger.warning("[auth] reset-password fail reason=invalid_token")
        raise HTTPException(status_code=400, detail="유효하지 않은 토큰입니다.")

    # MySQL DATETIME은 timezone-naive로 저장되므로 비교 전에 tz를 벗긴다.
    now = datetime.now(timezone.utc)
    expires = record.expires_at
    expires_naive = expires.replace(tzinfo=None) if expires.tzinfo else expires
    if expires_naive < now.replace(tzinfo=None):
        audit_logger.warning(
            "[auth] reset-password fail reason=expired token_id=%s", record.token_id
        )
        raise HTTPException(status_code=400, detail="만료된 토큰입니다.")

    user = db.query(User).filter(User.user_id == record.user_id).first()
    if not user:
        raise HTTPException(status_code=400, detail="사용자를 찾을 수 없습니다.")

    user.password_hash = _hash_password(req.new_password)
    record.used_at = now.replace(tzinfo=None)
    db.commit()
    _record_login_success(user.login_id or "")  # 잠금 카운터 리셋 — 사용자가 정상 복귀 가능
    audit_logger.info("[auth] password reset completed login_id=%s", user.login_id)
    return {"status": "ok", "message": "비밀번호가 재설정되었습니다."}


# ─── 회원 탈퇴 (P0-6) ─────────────────────────────────────────────────────────
# 본인 인증(current_password) 후 User 행 + 본인 진단 세션 + 자식 데이터 cascade 삭제.
# 개인 조직("{login_id}_개인") 이면 Organization 도 함께 삭제. 공유 조직이면 보존.
# 이메일 발송은 best-effort.

class AccountDeleteRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)


@router.delete("/me")
def delete_account(
    req: AccountDeleteRequest,
    request: Request,
    x_login_id: Optional[str] = Header(None, alias="X-Login-Id"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    db: Session = Depends(get_db),
):
    """회원 탈퇴 — 본인 비밀번호 재확인 후 즉시 삭제 (P0-6).

    삭제 대상:
      - 본인이 만든 DiagnosisSession + 자식(CollectedData/Evidence/DiagnosisResult/MaturityScore/ScoreHistory)
      - PasswordResetToken, AuthAuditLog 의 user_id 는 ON DELETE SET NULL (기록 보존)
      - User 행
      - 개인 조직(이름이 "{login_id}_개인")이면 Organization 도 함께
    """
    # 인증: JWT Bearer 우선, X-Login-Id fallback
    if authorization and authorization.lower().startswith("bearer "):
        payload = _decode_token(authorization.split(" ", 1)[1].strip())
        if payload.get("kind") != "access":
            raise HTTPException(status_code=401, detail="access 토큰이 아닙니다.")
        login_id = payload.get("sub")
    else:
        login_id = x_login_id
    user = _resolve_user_or_401(db, login_id)
    if not user.password_hash or not _verify_password(req.current_password, user.password_hash):
        audit_logger.warning("[auth] delete-account fail login_id=%s reason=bad_password", login_id)
        raise HTTPException(status_code=401, detail="비밀번호가 일치하지 않습니다.")

    ip, ua = _client_meta(request)
    user_id_snapshot = user.user_id
    login_id_snapshot = user.login_id
    email_snapshot = user.email
    name_snapshot = user.name
    org_id_snapshot = user.org_id

    # 본인이 만든 세션 + 자식 cascade
    from sqlalchemy import text as _sql_text
    from models import (
        DiagnosisSession as _DS, CollectedData as _CD, Evidence as _EV,
        DiagnosisResult as _DR, MaturityScore as _MS, ScoreHistory as _SH,
    )
    sids = [s.session_id for s in db.query(_DS).filter(_DS.user_id == user_id_snapshot).all()]
    if sids:
        for model in (_CD, _EV, _DR, _MS, _SH):
            db.query(model).filter(model.session_id.in_(sids)).delete(synchronize_session=False)
        db.query(_DS).filter(_DS.session_id.in_(sids)).delete(synchronize_session=False)

    # 개인 조직이면 Organization 도 삭제
    delete_org = False
    org = db.query(Organization).filter(Organization.org_id == org_id_snapshot).first()
    if org and org.name == f"{login_id_snapshot}_개인":
        # 같은 조직 다른 사용자가 없을 때만 삭제
        other_users = db.query(User).filter(
            User.org_id == org_id_snapshot, User.user_id != user_id_snapshot
        ).count()
        if other_users == 0:
            delete_org = True

    db.delete(user)
    if delete_org and org:
        db.delete(org)
    db.commit()

    audit_logger.info(
        "[auth] account deleted login_id=%s user_id=%s sessions=%d org_deleted=%s",
        login_id_snapshot, user_id_snapshot, len(sids), delete_org,
    )
    _audit_db(db, "account_deleted", login_id=login_id_snapshot,
              source_ip=ip, user_agent=ua,
              detail={"sessions_deleted": len(sids), "org_deleted": delete_org})

    # 탈퇴 확인 메일 — best-effort
    try:
        if email_snapshot and not email_snapshot.endswith("@local"):
            from services.email_sender import send_email
            send_email(email_snapshot, "[Readyz-T] 회원 탈퇴 처리 안내", "account_deleted", {
                "user_name": name_snapshot,
            })
    except Exception as exc:
        audit_logger.warning("[auth] delete email failed login_id=%s err=%s", login_id_snapshot, exc)

    return {"status": "ok", "message": "회원 탈퇴가 처리되었습니다."}
