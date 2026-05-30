import asyncio
import logging
import os
import warnings
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from dotenv import load_dotenv

load_dotenv()

# 로깅: 기본 콘솔 + zt.audit 채널 INFO 보장.
# 운영 시 별도 핸들러를 붙여 파일/SIEM으로 라우팅하기 쉽도록 별도 logger명을 사용.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
)
logging.getLogger("zt.audit").setLevel(logging.INFO)
logger = logging.getLogger(__name__)

from routers import (
    assessment, score, improvement, report, manual, checklist, auth, admin, settings,
)
from scripts.cleanup_old_sessions import cleanup_old_sessions
from services import config_store
from services.metrics import collect_metrics, render_prometheus
from database import SessionLocal

# 세션 보관 정책: 24시간 주기로 cleanup_old_sessions 실행 (기본 90일 retention).
# 첫 실행은 부팅 30초 후 (DB 초기화 여유). 환경변수로 비활성 가능.
_CLEANUP_INTERVAL_HOURS = float(os.getenv("ZTA_CLEANUP_INTERVAL_HOURS", "24"))
_CLEANUP_FIRST_DELAY_SEC = float(os.getenv("ZTA_CLEANUP_FIRST_DELAY_SEC", "30"))
# MAR-004: 주기 평가 스케줄러 폴링 간격 (기본 60초).
_SCHEDULER_INTERVAL_SEC = float(os.getenv("ZTA_SCHEDULER_INTERVAL_SEC", "60"))


async def _periodic_cleanup():
    if os.getenv("ZTA_CLEANUP_DISABLE", "").lower() == "true":
        logger.info("[cleanup] ZTA_CLEANUP_DISABLE=true — 자동 세션 삭제 비활성화")
        return
    await asyncio.sleep(_CLEANUP_FIRST_DELAY_SEC)
    while True:
        try:
            # cleanup_old_sessions 는 동기 함수라 to_thread 로 우회.
            result = await asyncio.to_thread(cleanup_old_sessions)
            logger.info("[cleanup] periodic run: %s", result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("[cleanup] periodic run failed: %s", exc)
        await asyncio.sleep(_CLEANUP_INTERVAL_HOURS * 3600)


async def _periodic_scheduler():
    """MAR-004 / SFR-AUTO-005: 도래한 주기 평가 스케줄을 실행."""
    await asyncio.sleep(_CLEANUP_FIRST_DELAY_SEC)
    while True:
        try:
            fired = await asyncio.to_thread(assessment.run_due_schedules)
            if fired:
                logger.info("[scheduler] %d schedule(s) fired", fired)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("[scheduler] run failed: %s", exc)
        await asyncio.sleep(_SCHEDULER_INTERVAL_SEC)


async def _periodic_backup():
    """MAR-014: backup_interval_hours > 0 이면 주기 자동 백업 (최신 14개 보존)."""
    await asyncio.sleep(_CLEANUP_FIRST_DELAY_SEC + 10)
    while True:
        interval = 0
        db = SessionLocal()
        try:
            interval = int(config_store.get("backup_interval_hours", db))
        except Exception:
            interval = 0
        finally:
            db.close()
        if interval > 0:
            try:
                from scripts.backup_db import create_backup, prune_backups
                meta = await asyncio.to_thread(create_backup)
                await asyncio.to_thread(prune_backups, 14)
                logger.info("[backup] auto backup 완료: %s", meta.get("filename"))
            except Exception as exc:
                logger.warning("[backup] auto backup 실패: %s", exc)
            await asyncio.sleep(max(1, interval) * 3600)
        else:
            await asyncio.sleep(3600)  # 비활성 — 1시간마다 설정 재확인


@asynccontextmanager
async def lifespan(app: FastAPI):
    tasks = [
        asyncio.create_task(_periodic_cleanup()),
        asyncio.create_task(_periodic_scheduler()),
        asyncio.create_task(_periodic_backup()),
    ]
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            try:
                await task
            except asyncio.CancelledError:
                pass


# SER-004: 전송 구간 보안. nginx(운영)가 80→443 강제 + HSTS 를 이미 처리하지만,
# 백엔드 직접 접근/프록시 미경유 경우까지 방어하도록 앱 레벨에서도 보안 헤더를 항상
# 부착하고, ZTA_FORCE_HTTPS=true 면 http 요청을 https 로 리다이렉트한다(프록시 뒤
# X-Forwarded-Proto 존중).
_FORCE_HTTPS = os.getenv("ZTA_FORCE_HTTPS", "").lower() == "true"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if _FORCE_HTTPS:
            proto = request.headers.get("X-Forwarded-Proto", request.url.scheme)
            if proto == "http" and request.url.path not in ("/health", "/metrics"):
                return RedirectResponse(str(request.url.replace(scheme="https")), status_code=307)
        response = await call_next(request)
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer-when-downgrade")
        return response


app = FastAPI(title="ZT Assessment API", version="1.0.0", lifespan=lifespan)

ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:8080").split(",")
if "*" in ALLOWED_ORIGINS:
    warnings.warn(
        "CORS wildcard(*) + allow_credentials=True 조합은 브라우저에서 자체 차단됩니다. "
        "운영 배포 시 CORS_ORIGINS를 명시적 도메인 목록으로 설정하세요.",
        RuntimeWarning,
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(assessment.router, prefix="/api/assessment", tags=["assessment"])
app.include_router(score.router,      prefix="/api/score",      tags=["score"])
app.include_router(improvement.router,prefix="/api/improvement",tags=["improvement"])
app.include_router(report.router,     prefix="/api/report",     tags=["report"])
app.include_router(manual.router,     prefix="/api/manual",     tags=["manual"])
app.include_router(checklist.router,  prefix="/api/checklist",  tags=["checklist"])
app.include_router(auth.router,       prefix="/api/auth",       tags=["auth"])
app.include_router(admin.router,      prefix="/api/admin",      tags=["admin"])
app.include_router(settings.router,   prefix="/api/settings",   tags=["settings"])


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/metrics")
def prometheus_metrics():
    """MAR-009: Prometheus 텍스트 메트릭. 집계 카운트만 노출(민감정보 없음)."""
    db = SessionLocal()
    try:
        data = collect_metrics(db)
    except Exception as exc:
        logger.warning("[metrics] collect failed: %s", exc)
        return PlainTextResponse("zt_db_up 0\n", media_type="text/plain")
    finally:
        db.close()
    return PlainTextResponse(render_prometheus(data), media_type="text/plain; version=0.0.4")
