"""auth.py — 회원가입/로그인. 비밀번호는 PBKDF2-SHA256 (stdlib)로 해싱.

엔드포인트:
- POST /api/auth/register  : 신규 사용자 + (선택) 조직 등록 + profile 저장
- POST /api/auth/login     : login_id + password 검증, user 정보 + profile 반환
- GET  /api/auth/me        : login_id로 사용자 정보 조회 (간이 세션용)
"""
import hashlib
import os
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import Organization, User

router = APIRouter()

PBKDF2_ITERS = 200_000


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

    profile_dict = req.profile.dict(exclude_none=True) if req.profile else {}

    # 조직 upsert (profile.org_name이 있으면 그 이름으로, 없으면 사용자 이름의 개인 조직)
    org_name = (profile_dict.get("org_name") or f"{req.name} (개인)").strip()
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
def me(login_id: str, db: Session = Depends(get_db)):
    """간이 세션 — 클라이언트가 보관한 login_id로 최신 user 정보 재조회."""
    user = db.query(User).filter(User.login_id == login_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")
    org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
    return _to_response(user, org)


class ProfileUpdateRequest(BaseModel):
    profile: ProfileFields


@router.put("/profile", response_model=UserResponse)
def update_profile(login_id: str, req: ProfileUpdateRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.login_id == login_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")
    user.profile = req.profile.dict(exclude_none=True)
    db.commit()
    db.refresh(user)
    org = db.query(Organization).filter(Organization.org_id == user.org_id).first()
    return _to_response(user, org)
