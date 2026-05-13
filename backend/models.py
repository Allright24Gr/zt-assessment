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

    org = relationship("Organization", back_populates="users")
    sessions = relationship("DiagnosisSession", back_populates="manager")


class DiagnosisSession(Base):
    __tablename__ = "DiagnosisSession"

    session_id = Column(Integer, primary_key=True, autoincrement=True)
    org_id = Column(Integer, ForeignKey("Organization.org_id"), nullable=False)
    user_id = Column(Integer, ForeignKey("User.user_id"), nullable=False)
    status = Column(
        Enum("진행 중", "완료", "오류", name="session_status"),
        nullable=False,
        default="진행 중",
    )
    level = Column(String(20), nullable=True)
    total_score = Column(Float, nullable=True)
    started_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)

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

    session = relationship("DiagnosisSession", back_populates="evidences")
    checklist = relationship("Checklist", back_populates="evidences")


class DiagnosisResult(Base):
    __tablename__ = "DiagnosisResult"

    result_id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("DiagnosisSession.session_id"), nullable=False)
    check_id = Column(Integer, ForeignKey("Checklist.check_id"), nullable=False)
    result = Column(
        Enum("충족", "부분충족", "미충족", "평가불가", name="diagnosis_result"),
        nullable=False,
    )
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
    term = Column(
        Enum("단기", "중기", "장기", name="improvement_term"),
        nullable=False,
    )
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
