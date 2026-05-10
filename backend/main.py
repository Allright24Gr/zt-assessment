from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

load_dotenv()

from routers import assessment, score, improvement, report, manual, checklist

app = FastAPI(title="ZT Assessment API", version="1.0.0")

_origins = os.environ.get("CORS_ORIGINS", "*")
origins = _origins.split(",") if _origins != "*" else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
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


@app.get("/health")
def health_check():
    return {"status": "ok"}
