#!/bin/bash
set -e

echo "MySQL 준비 대기 중..."
until python3 -c "
import os, pymysql
pymysql.connect(
    host=os.getenv('DB_HOST','mysql'),
    port=int(os.getenv('DB_PORT',3306)),
    user=os.getenv('DB_USER','readyz'),
    password=os.getenv('DB_PASSWORD',''),
    database=os.getenv('DB_NAME','zt_assessment'),
)" 2>/dev/null; do
  echo "  MySQL 미준비 — 3초 후 재시도..."
  sleep 3
done
echo "MySQL 연결 확인."

echo "스키마 마이그레이션..."
python3 /app/scripts/migrate_schema.py || echo "[migrate] 마이그레이션 실패 (무시)"

echo "체크리스트 seed 실행..."
python3 /app/scripts/seed_checklist.py
echo "개선권고 seed 실행..."
python3 /app/scripts/seed_improvement.py || echo "[seed_improvement] 개선권고 seed 실패 (무시)"
echo "데모 예시 seed 실행 (idempotent — admin/user1이 있으면 스킵)..."
python3 /app/scripts/seed_demo_examples.py || echo "[seed_demo_examples] 시드 실패 (무시)"
echo "서버 시작..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
