from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import logging
import os
import warnings

load_dotenv()

# 로깅: 기본 콘솔 + zt.audit 채널 INFO 보장.
# 운영 시 별도 핸들러를 붙여 파일/SIEM으로 라우팅하기 쉽도록 별도 logger명을 사용.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
)
logging.getLogger("zt.audit").setLevel(logging.INFO)

from routers import assessment, score, improvement, report, manual, checklist, auth

app = FastAPI(title="ZT Assessment API", version="1.0.0")

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
