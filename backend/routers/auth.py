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
import re
import secrets
import threading
import time
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from database import get_db
from models import Organization, User

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("zt.audit")  # 별도 채널 — 운영 시 별도 파일/SIEM 라우팅 가능
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

_login_state_lock = threading.Lock()
# login_id → {"fails": int, "locked_until": float}
_login_state: dict[str, dict] = {}


def _check_lock(login_id: str) -> None:
    """잠금 상태면 HTTPException 423. 잠금 만료된 경우 카운터 리셋."""
    now = time.time()
    with _login_state_lock:
        st = _login_state.get(login_id)
        if not st:
            return
        if st.get("locked_until", 0) > now:
            retry_after = int(st["locked_until"] - now) + 1
            raise HTTPException(
                status_code=423,
                detail=f"로그인 실패 횟수 초과. {retry_after}초 후 다시 시도하세요.",
                headers={"Retry-After": str(retry_after)},
            )
        if st.get("locked_until", 0) and st["locked_until"] <= now:
            _login_state.pop(login_id, None)


def _record_login_failure(login_id: str) -> None:
    now = time.time()
    with _login_state_lock:
        st = _login_state.setdefault(login_id, {"fails": 0, "locked_until": 0.0})
        st["fails"] += 1
        if st["fails"] >= LOGIN_MAX_ATTEMPTS:
            st["locked_until"] = now + LOGIN_LOCK_SECONDS
            audit_logger.warning(
                "[auth] login_id=%s 잠금 적용: %d회 실패 → %ds 잠금",
                login_id, st["fails"], LOGIN_LOCK_SECONDS,
            )


def _record_login_success(login_id: str) -> None:
    with _login_state_lock:
        _login_state.pop(login_id, None)


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
    x_login_id: Optional[str] = Header(None, alias="X-Login-Id"),
    db: Session = Depends(get_db),
) -> User:
    """FastAPI 의존성 — 다른 router 들이 보호 엔드포인트에서 import 해 쓴다.

    사용 예:
        from routers.auth import get_current_user
        @router.get("/protected")
        def view(current_user: User = Depends(get_current_user)): ...
    """
    return _resolve_user_or_401(db, x_login_id)


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

@router.post("/register", response_model=UserResponse)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.login_id == req.login_id).first():
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

    user = User(
        org_id=org.org_id,
        name=req.name,
        email=email,
        role="user",
        login_id=req.login_id,
        password_hash=_hash_password(req.password),
        profile=profile_dict or None,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    audit_logger.info("[auth] register login_id=%s org=%s", req.login_id, org_name)
    return _to_response(user, org)


@router.post("/login", response_model=UserResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    _check_lock(req.login_id)

    user = db.query(User).filter(User.login_id == req.login_id).first()
    if not user or not user.password_hash:
        _record_login_failure(req.login_id)
        audit_logger.info("[auth] login fail login_id=%s reason=no_user", req.login_id)
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")
    if not _verify_password(req.password, user.password_hash):
        _record_login_failure(req.login_id)
        audit_logger.info("[auth] login fail login_id=%s reason=bad_password", req.login_id)
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")

    _record_login_success(req.login_id)
    audit_logger.info("[auth] login ok login_id=%s user_id=%s", req.login_id, user.user_id)

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
