import asyncio
import logging
import os
import warnings
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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

from routers import assessment, score, improvement, report, manual, checklist, auth
from scripts.cleanup_old_sessions import cleanup_old_sessions

# 세션 보관 정책: 24시간 주기로 cleanup_old_sessions 실행 (기본 90일 retention).
# 첫 실행은 부팅 30초 후 (DB 초기화 여유). 환경변수로 비활성 가능.
_CLEANUP_INTERVAL_HOURS = float(os.getenv("ZTA_CLEANUP_INTERVAL_HOURS", "24"))
_CLEANUP_FIRST_DELAY_SEC = float(os.getenv("ZTA_CLEANUP_FIRST_DELAY_SEC", "30"))


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


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_periodic_cleanup())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


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

app.include_router(assessment.router, prefix="/api/assessment", tags=["assessment"])
app.include_router(score.router,      prefix="/api/score",      tags=["score"])
app.include_router(improvement.router,prefix="/api/improvement",tags=["improvement"])
app.include_router(report.router,     prefix="/api/report",     tags=["report"])
app.include_router(manual.router,     prefix="/api/manual",     tags=["manual"])
app.include_router(checklist.router,  prefix="/api/checklist",  tags=["checklist"])
app.include_router(auth.router,       prefix="/api/auth",       tags=["auth"])


@app.get("/health")
def health_check():
    return {"status": "ok"}
