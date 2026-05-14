#!/bin/bash
set -e
echo "체크리스트 seed 실행..."
python3 /app/scripts/seed_checklist.py
echo "개선권고 seed 실행..."
python3 /app/scripts/seed_improvement.py || echo "[seed_improvement] 개선권고 seed 실패 (무시)"
echo "서버 시작..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
