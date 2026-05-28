#!/usr/bin/env bash
#
# bootstrap.sh — 새 환경(EC2·로컬)에 한 번에 셋업.
#
# 사용:
#   ./scripts/bootstrap.sh                  # 기본 모드
#   FORCE_REINIT=true ./scripts/bootstrap.sh # .env 재생성 + 기존 secret 덮어쓰기
#
# 흐름:
#   0. .env 없으면 .env.example 복사 + SECRET_KEY/DB_PASSWORD 자동 발급
#   1. docker compose up -d --build
#   2. 헬스 대기 (backend/frontend)
#   3. 결과 요약

set -euo pipefail

cd "$(dirname "$0")/.."

# ─── 색상 ──────────────────────────────────────────────────────────────────────
red()   { printf "\033[31m%s\033[0m\n" "$*"; }
green() { printf "\033[32m%s\033[0m\n" "$*"; }
yel()   { printf "\033[33m%s\033[0m\n" "$*"; }
bold()  { printf "\033[1m%s\033[0m\n" "$*"; }
step()  { bold ""; bold "────── $1 ──────"; }

require() {
    command -v "$1" >/dev/null 2>&1 || { red "'$1' 필요"; exit 99; }
}

require docker
require curl
require python3

ENV_FILE=".env"
FORCE_REINIT="${FORCE_REINIT:-false}"

# ─── 0. .env 자동 생성 ───────────────────────────────────────────────────────
step "0. .env 셋업"

if [ ! -f "$ENV_FILE" ] || [ "$FORCE_REINIT" = "true" ]; then
    if [ ! -f .env.example ]; then
        red ".env.example 없음 — git pull 또는 저장소 무결성 확인"; exit 1
    fi
    cp .env.example "$ENV_FILE"
    SECRET=$(openssl rand -hex 48 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(48))")
    DB_PW=$(openssl rand -hex 16 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(16))")
    sed -i "s|^SECRET_KEY=.*|SECRET_KEY=$SECRET|" "$ENV_FILE"
    sed -i "s|^DB_PASSWORD=.*|DB_PASSWORD=$DB_PW|" "$ENV_FILE"
    sed -i "s|^MYSQL_ROOT_PASSWORD=.*|MYSQL_ROOT_PASSWORD=$DB_PW|" "$ENV_FILE"
    sed -i "s|^EMAIL_DRY_RUN=.*|EMAIL_DRY_RUN=true|" "$ENV_FILE"
    green "  ✓ .env 새로 생성. SECRET_KEY/DB_PASSWORD 자동 발급."
    yel  "  ⚠ 운영 시 다음 값을 직접 채워야 함:"
    yel  "      VITE_API_BASE  (예: https://readyz-t.example.com)"
    yel  "      CORS_ORIGINS   (예: https://readyz-t.example.com)"
    yel  "      EMAIL_FROM, AWS_REGION (실 이메일 발송 시)"
else
    green "  ✓ 기존 $ENV_FILE 유지"
fi

# 환경변수 로드
set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

# ─── 1. docker compose 기동 ────────────────────────────────────────────────────
step "1. 컨테이너 기동"

docker compose up -d --build 2>&1 | tail -3

# ─── 2. 헬스 대기 ──────────────────────────────────────────────────────────────
step "2. 서비스 헬스 대기"

wait_for() {
    local desc="$1" url="$2" max="${3:-60}"
    printf "  %s " "$desc"
    for _ in $(seq 1 "$max"); do
        if curl -fsS "$url" >/dev/null 2>&1; then green "OK"; return 0; fi
        printf "."
        sleep 2
    done
    red "TIMEOUT"
    return 1
}

wait_for "backend          " "http://localhost:8000/health" 60
wait_for "frontend(nginx)  " "http://localhost:8080/" 30

# ─── 3. 최종 요약 ──────────────────────────────────────────────────────────────
step "3. 부트스트랩 완료"

green "  ✓ frontend  : http://localhost:8080"
green "  ✓ backend   : http://localhost:8000"
green ""
green "  시드 데이터(체크리스트/개선가이드/데모세션)는 backend entrypoint 에서 자동 적재됨."
green "  진단 흐름 검증: ./scripts/e2e_smoke.sh"
green ""
green "  기본 진단 계정 (시드):"
green "    admin / admin"
green "    user1 / user1"
