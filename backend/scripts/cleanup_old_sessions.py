"""cleanup_old_sessions.py — 진단 세션 90일 자동 삭제.

호출:
  - 스탠드얼론: `python backend/scripts/cleanup_old_sessions.py [--days N] [--dry-run]`
  - FastAPI lifespan task: backend/main.py 에서 24시간 주기로 자동 호출.

정책:
  - DiagnosisSession.started_at < (now - N일) 인 세션 + 자식 테이블 일괄 삭제.
  - 자식 테이블: CollectedData / Evidence / DiagnosisResult / MaturityScore / ScoreHistory.
  - 시드 보호: ZTA_PROTECT_DEMO_DATA=true (기본 true) 시 시드 조직 세션은 보존.
    시드 조직 이름 = auth._PROTECTED_ORG_NAMES.
  - audit 로그(zt.audit) 에 삭제 건수 기록.
"""
import argparse
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from database import SessionLocal
from models import (
    DiagnosisSession, CollectedData, Evidence,
    DiagnosisResult, MaturityScore, ScoreHistory,
    Organization,
)

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("zt.audit")

DEFAULT_DAYS = int(os.getenv("ZTA_SESSION_RETENTION_DAYS", "90"))


# auth.py 의 _PROTECTED_ORG_NAMES 와 동일해야 한다.
_DEMO_ORG_NAMES = {
    "시스템관리", "세종대학교",
    "ABC 핀테크", "XYZ 메디컬", "국가데이터센터", "스타트업 K",
}


def cleanup_old_sessions(days: int = DEFAULT_DAYS, dry_run: bool = False) -> dict:
    """retention 기간 초과 세션을 삭제하고 결과 dict 반환.

    반환: {"checked": N, "deleted": M, "preserved_demo": K, "cutoff": "..."}
    """
    protect_demo = os.getenv("ZTA_PROTECT_DEMO_DATA", "true").lower() == "true"
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    db = SessionLocal()
    try:
        candidates = db.query(DiagnosisSession).filter(
            DiagnosisSession.started_at < cutoff
        ).all()
        checked = len(candidates)

        if protect_demo:
            demo_org_ids = {
                o.org_id for o in
                db.query(Organization).filter(Organization.name.in_(_DEMO_ORG_NAMES)).all()
            }
            targets = [s for s in candidates if s.org_id not in demo_org_ids]
            preserved_demo = checked - len(targets)
        else:
            targets = candidates
            preserved_demo = 0

        if dry_run:
            audit_logger.info(
                "[cleanup] dry-run cutoff=%s checked=%d would_delete=%d demo_preserved=%d",
                cutoff.isoformat(), checked, len(targets), preserved_demo,
            )
            return {
                "checked": checked, "deleted": 0,
                "preserved_demo": preserved_demo,
                "cutoff": cutoff.isoformat(), "dry_run": True,
            }

        deleted = 0
        for session in targets:
            sid = session.session_id
            for model in (CollectedData, Evidence, DiagnosisResult, MaturityScore, ScoreHistory):
                db.query(model).filter(model.session_id == sid).delete(synchronize_session=False)
            db.delete(session)
            deleted += 1
        db.commit()

        audit_logger.info(
            "[cleanup] cutoff=%s checked=%d deleted=%d demo_preserved=%d",
            cutoff.isoformat(), checked, deleted, preserved_demo,
        )
        return {
            "checked": checked, "deleted": deleted,
            "preserved_demo": preserved_demo,
            "cutoff": cutoff.isoformat(), "dry_run": False,
        }
    except Exception as exc:
        db.rollback()
        logger.error("[cleanup] failed: %s", exc, exc_info=True)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS,
                        help="보관 일수 (기본: ZTA_SESSION_RETENTION_DAYS 또는 90)")
    parser.add_argument("--dry-run", action="store_true", help="삭제하지 않고 대상만 확인")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
    )
    result = cleanup_old_sessions(days=args.days, dry_run=args.dry_run)
    print(f"[cleanup] {result}")
