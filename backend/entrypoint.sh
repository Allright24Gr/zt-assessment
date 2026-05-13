#!/bin/bash
set -e
echo "체크리스트 seed 실행..."
python3 /app/scripts/seed_checklist.py
echo "서버 시작..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
