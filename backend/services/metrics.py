"""metrics.py — 시스템 상태/운영 지표 수집 (MAR-009).

admin JSON 대시보드(/api/admin/metrics)와 Prometheus 텍스트(/metrics) 양쪽에서
재사용한다. 집계는 모두 읽기 전용 카운트라 민감정보가 없다.
"""
from __future__ import annotations

import time

from sqlalchemy import func
from sqlalchemy.orm import Session

# 프로세스 부팅 시각 — uptime 계산용.
START_TS = time.time()


def collect_metrics(db: Session) -> dict:
    from models import (
        AuthAuditLog, CollectedData, DiagnosisResult, DiagnosisSession,
        Evidence, Organization, ScheduledAssessment, User,
    )
    from services import cache, crypto

    def _count(model, *filters):
        q = db.query(func.count()).select_from(model)
        for f in filters:
            q = q.filter(f)
        return int(q.scalar() or 0)

    sessions_total = _count(DiagnosisSession)
    sessions_done = _count(DiagnosisSession, DiagnosisSession.status == "완료")
    sessions_running = _count(DiagnosisSession, DiagnosisSession.status == "진행 중")
    sessions_prepared = _count(DiagnosisSession, DiagnosisSession.status == "준비중")

    audit_total = _count(AuthAuditLog)
    audit_fail = _count(AuthAuditLog, AuthAuditLog.success == 0)

    return {
        "uptime_seconds": round(time.time() - START_TS, 1),
        "db_ok": True,  # 이 함수가 실행됐다는 것 자체가 DB 연결 성공
        "counts": {
            "users":          _count(User),
            "organizations":  _count(Organization),
            "sessions_total": sessions_total,
            "sessions_done":  sessions_done,
            "sessions_running": sessions_running,
            "sessions_prepared": sessions_prepared,
            "results":        _count(DiagnosisResult),
            "collected_data": _count(CollectedData),
            "evidence_files": _count(Evidence, Evidence.file_path.isnot(None)),
            "audit_logs":     audit_total,
            "audit_failures": audit_fail,
            "schedules_enabled": _count(ScheduledAssessment, ScheduledAssessment.enabled == 1),
        },
        "cache": cache.stats(),
        "encryption_enabled": crypto.is_enabled(),
        "encryption_key_source": crypto.key_source(),
    }


def render_prometheus(metrics: dict) -> str:
    """dict → Prometheus text exposition format."""
    lines: list[str] = []

    def _emit(name: str, value, help_text: str, mtype: str = "gauge"):
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {mtype}")
        lines.append(f"{name} {value}")

    _emit("zt_uptime_seconds", metrics.get("uptime_seconds", 0), "Process uptime in seconds")
    _emit("zt_db_up", 1 if metrics.get("db_ok") else 0, "Database reachable (1=ok)")
    _emit("zt_encryption_enabled", 1 if metrics.get("encryption_enabled") else 0,
          "At-rest encryption active (1=on)")
    for k, v in metrics.get("counts", {}).items():
        _emit(f"zt_{k}", v, f"Count of {k}", mtype="gauge")
    cache = metrics.get("cache", {})
    _emit("zt_cache_hits", cache.get("hits", 0), "Result cache hits", mtype="counter")
    _emit("zt_cache_misses", cache.get("misses", 0), "Result cache misses", mtype="counter")
    _emit("zt_cache_hit_rate", cache.get("hit_rate", 0), "Result cache hit rate (0~1)")
    _emit("zt_cache_size", cache.get("size", 0), "Result cache entry count")
    return "\n".join(lines) + "\n"
