"""auth.py — 회원가입/로그인. 비밀번호는 PBKDF2-SHA256 (stdlib)로 해싱.

엔드포인트:
- POST /api/auth/register  : 신규 사용자 + (선택) 조직 등록 + profile 저장
- POST /api/auth/login     : login_id + password 검증, user 정보 + profile 반환
- GET  /api/auth/me        : X-Login-Id 헤더로 사용자 정보 조회 (간이 세션용)
- PUT  /api/auth/profile   : X-Login-Id 헤더 + current_password 재확인 후 profile 갱신
"""
import hashlib
import logging
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import Organization, User

logger = logging.getLogger(__name__)
router = APIRouter()

# OWASP 2023 Password Storage Cheat Sheet 권장치(PBKDF2-SHA256 600k 이상).
# 저장 형식이 라운드 수를 포함하므로 기존 200k 해시도 _verify_password에서 그대로 검증 가능.
PBKDF2_ITERS = 600_000


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
    password: str = Field(min_length=4, max_length=200)
    name: str = Field(min_length=1, max_length=100)
    email: Optional[str] = None
    profile: Optional[ProfileFields] = None


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
    return _to_response(user, org)


@router.post("/login", response_model=UserResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.login_id == req.login_id).first()
    if not user or not user.password_hash:
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")
    if not _verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")
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


class ProfileUpdateRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    profile: ProfileFields


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
        logger.warning("[auth] profile update password mismatch for login_id=%s", x_login_id)
        raise HTTPException(status_code=401, detail="비밀번호가 일치하지 않습니다.")
    user.profile = req.profile.model_dump(exclude_none=True)
    db.commit()
    db.refresh(user)
    org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
    return _to_response(user, org)
