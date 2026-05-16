from sqlalchemy import (
    Column, Integer, String, Float, Text, JSON,
    DateTime, ForeignKey, Index, Enum
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base


class Organization(Base):
    __tablename__ = "Organization"

    org_id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    industry   = Column(String(50),  nullable=True)
    size       = Column(String(20),  nullable=True)
    cloud_type = Column(String(30),  nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    users = relationship("User", back_populates="org")
    sessions = relationship("DiagnosisSession", back_populates="org")
    score_histories = relationship("ScoreHistory", back_populates="org")


class User(Base):
    __tablename__ = "User"

    user_id = Column(Integer, primary_key=True, autoincrement=True)
    org_id = Column(Integer, ForeignKey("Organization.org_id"), nullable=False)
    name = Column(String(100), nullable=False)
    email = Column(String(200), unique=True, nullable=False)
    role = Column(String(50), nullable=False, default="analyst")
    mfa_enabled = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, server_default=func.now())
    # 회원가입 / 로그인용
    login_id = Column(String(100), unique=True, nullable=True)
    password_hash = Column(String(200), nullable=True)
    # 진단 시 자동 prefill용 사용자 프로필 (org_name/dept/employees/servers 등)
    profile = Column(JSON, nullable=True)
    # 이용약관 / 개인정보 처리방침 동의 시점 (정보통신망법·개인정보보호법)
    tos_agreed_at = Column(DateTime, nullable=True)
    privacy_agreed_at = Column(DateTime, nullable=True)

    org = relationship("Organization", back_populates="users")
    sessions = relationship("DiagnosisSession", back_populates="manager")


class DiagnosisSession(Base):
    __tablename__ = "DiagnosisSession"

    session_id = Column(Integer, primary_key=True, autoincrement=True)
    org_id = Column(Integer, ForeignKey("Organization.org_id"), nullable=False)
    user_id = Column(Integer, ForeignKey("User.user_id"), nullable=False)
    status = Column(String(20), nullable=False, default="진행 중")
    level = Column(String(20), nullable=True)
    total_score = Column(Float, nullable=True)
    started_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)
    selected_tools = Column(JSON, nullable=True)   # {"keycloak": true, ...}
    extra = Column(JSON, nullable=True)            # employees, servers, note, pillar_scope, errors

    org = relationship("Organization", back_populates="sessions")
    manager = relationship("User", back_populates="sessions")
    collected_data = relationship("CollectedData", back_populates="session")
    evidences = relationship("Evidence", back_populates="session")
    results = relationship("DiagnosisResult", back_populates="session")
    maturity_scores = relationship("MaturityScore", back_populates="session")
    score_histories = relationship("ScoreHistory", back_populates="session")


class Checklist(Base):
    __tablename__ = "Checklist"

    check_id = Column(Integer, primary_key=True, autoincrement=True)
    item_id = Column(String(30), nullable=False, unique=True)
    item_num = Column(String(20), nullable=True)
    pillar = Column(String(100), nullable=False)
    category = Column(String(100), nullable=False)
    item_name = Column(String(200), nullable=False)
    maturity = Column(String(20), nullable=False)
    maturity_score = Column(Integer, nullable=False)
    diagnosis_type = Column(String(20), nullable=False)
    tool = Column(String(100), nullable=False)
    evidence = Column(Text, nullable=True)
    criteria = Column(Text, nullable=True)
    fields = Column(Text, nullable=True)
    logic = Column(Text, nullable=True)
    exceptions = Column(Text, nullable=True)
    weight = Column(Float, nullable=False, default=0.1)

    collected_data = relationship("CollectedData", back_populates="checklist")
    evidences = relationship("Evidence", back_populates="checklist")
    results = relationship("DiagnosisResult", back_populates="checklist")
    improvement_guides = relationship("ImprovementGuide", back_populates="checklist")


class CollectedData(Base):
    __tablename__ = "CollectedData"

    data_id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("DiagnosisSession.session_id"), nullable=False)
    check_id = Column(Integer, ForeignKey("Checklist.check_id"), nullable=False)
    tool = Column(String(100), nullable=False)
    metric_key = Column(String(200), nullable=False)
    metric_value = Column(Float, nullable=True)
    threshold = Column(Float, nullable=True)
    raw_json = Column(JSON, nullable=True)
    collected_at = Column(DateTime, server_default=func.now())
    error = Column(Text, nullable=True)

    session = relationship("DiagnosisSession", back_populates="collected_data")
    checklist = relationship("Checklist", back_populates="collected_data")

    __table_args__ = (
        Index("idx_collected_data_session", "session_id"),
        Index("idx_collected_data_check", "check_id"),
    )


class Evidence(Base):
    __tablename__ = "Evidence"

    evidence_id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("DiagnosisSession.session_id"), nullable=False)
    check_id = Column(Integer, ForeignKey("Checklist.check_id"), nullable=False)
    source = Column(String(200), nullable=True)
    observed = Column(Text, nullable=True)
    location = Column(String(500), nullable=True)
    reason = Column(Text, nullable=True)
    impact = Column(Float, nullable=True)
    # P1-7: 수동 증적 파일 업로드용 컬럼
    file_path = Column(String(500), nullable=True)
    mime_type = Column(String(120), nullable=True)
    file_size = Column(Integer, nullable=True)
    original_filename = Column(String(255), nullable=True)

    session = relationship("DiagnosisSession", back_populates="evidences")
    checklist = relationship("Checklist", back_populates="evidences")


class DiagnosisResult(Base):
    __tablename__ = "DiagnosisResult"

    result_id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("DiagnosisSession.session_id"), nullable=False)
    check_id = Column(Integer, ForeignKey("Checklist.check_id"), nullable=False)
    result = Column(String(10), nullable=False)
    score = Column(Float, nullable=True)
    recommendation = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    session = relationship("DiagnosisSession", back_populates="results")
    checklist = relationship("Checklist", back_populates="results")


class MaturityScore(Base):
    __tablename__ = "MaturityScore"

    score_id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("DiagnosisSession.session_id"), nullable=False)
    pillar = Column(String(100), nullable=False)
    score = Column(Float, nullable=False)
    level    = Column(String(10), nullable=False, default="기존")
    pass_cnt = Column(Integer,    nullable=False, default=0)
    fail_cnt = Column(Integer,    nullable=False, default=0)
    na_cnt   = Column(Integer,    nullable=False, default=0)
    created_at = Column(DateTime, server_default=func.now())

    session = relationship("DiagnosisSession", back_populates="maturity_scores")


class ImprovementGuide(Base):
    __tablename__ = "ImprovementGuide"

    guide_id = Column(Integer, primary_key=True, autoincrement=True)
    check_id = Column(Integer, ForeignKey("Checklist.check_id"), nullable=True)
    current_level    = Column(String(10),  nullable=True)
    next_level       = Column(String(10),  nullable=True)
    recommended_tool = Column(String(100), nullable=True)
    pillar = Column(String(100), nullable=False)
    task = Column(Text, nullable=False)
    priority = Column(
        Enum("Critical", "High", "Medium", "Low", name="priority_level"),
        nullable=False,
    )
    term = Column(String(10), nullable=False)
    duration = Column(String(100), nullable=True)
    difficulty = Column(String(50), nullable=True)
    owner = Column(String(100), nullable=True)
    expected_gain = Column(Text, nullable=True)
    related_item = Column(String(200), nullable=True)
    steps = Column(JSON, nullable=True)
    expected_effect = Column(Text, nullable=True)

    checklist = relationship("Checklist", back_populates="improvement_guides")


class ScoreHistory(Base):
    __tablename__ = "ScoreHistory"

    history_id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("DiagnosisSession.session_id"), nullable=False)
    org_id = Column(Integer, ForeignKey("Organization.org_id"), nullable=False)
    pillar_scores = Column(JSON, nullable=True)
    total_score = Column(Float, nullable=False)
    maturity_level = Column(String(20), nullable=False)
    assessed_at = Column(DateTime, server_default=func.now())

    session = relationship("DiagnosisSession", back_populates="score_histories")
    org = relationship("Organization", back_populates="score_histories")

    __table_args__ = (
        Index("idx_score_history_assessed_at", "assessed_at"),
    )



# ─── 보안 감사 로그 (P0-3) ─────────────────────────────────────────────────────
# auth.py 의 audit_logger 채널에 더해 DB 영속화. 컨테이너 재시작 후에도 감사 추적 가능.

class AuthAuditLog(Base):
    __tablename__ = "AuthAuditLog"

    audit_id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(50), nullable=False)
    # register | login_ok | login_fail | login_locked | profile_update |
    # change_password | password_reset_requested | password_reset_completed |
    # account_deleted | etc.
    user_id = Column(Integer, ForeignKey("User.user_id"), nullable=True)
    login_id = Column(String(100), nullable=True)
    source_ip = Column(String(64), nullable=True)
    user_agent = Column(String(500), nullable=True)
    success = Column(Integer, nullable=False, default=1)
    detail = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    __table_args__ = (
        Index("idx_audit_event_type", "event_type"),
        Index("idx_audit_user_id", "user_id"),
        Index("idx_audit_created_at", "created_at"),
    )


# ─── 외부 공유 링크 (P1-11) ────────────────────────────────────────────────────
# 진단 결과를 인증 없이 조회 가능한 토큰 기반 공유 링크.
# 토큰은 SHA-256 해시로만 저장한다 (원본 토큰 유출 시 추적성 확보 + DB 노출 위험 최소화).

class SharedResult(Base):
    __tablename__ = "SharedResult"

    share_id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("DiagnosisSession.session_id"), nullable=False)
    token_hash = Column(String(128), nullable=False, unique=True)
    created_by_user_id = Column(Integer, ForeignKey("User.user_id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    __table_args__ = (
        Index("idx_shared_result_session", "session_id"),
        Index("idx_shared_result_token", "token_hash"),
    )


class PasswordResetToken(Base):
    """비밀번호 재설정 토큰. 평문 토큰은 메일로만 발송, DB에는 SHA-256 해시만 보관.

    회수 정책: 사용자가 새 요청을 보내면 기존 미사용 토큰을 모두 used_at으로 무효화.
    검증 시 used_at IS NULL + expires_at > now 두 조건 모두 충족해야 한다.
    """
    __tablename__ = "PasswordResetToken"

    token_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("User.user_id"), nullable=False)
    token_hash = Column(String(128), nullable=False, unique=True)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    __table_args__ = (
        Index("idx_password_reset_user", "user_id"),
    )
