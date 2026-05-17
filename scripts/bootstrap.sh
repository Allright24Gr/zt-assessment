#!/usr/bin/env bash
#
# bootstrap.sh — 새 환경(EC2·로컬)에 한 번에 셋업.
#
# 사용:
#   ./scripts/bootstrap.sh                  # 기본 모드
#   FORCE_REINIT=true ./scripts/bootstrap.sh # .env 재생성 + 기존 secret 덮어쓰기
#
# 흐름:
#   0. .env 없으면 .env.example 복사 + SECRET_KEY/INTERNAL_API_TOKEN 자동 발급
#   1. docker swarm init (idempotent — Shuffle Orborus 필수)
#   2. shuffle_swarm_executions 네트워크 (idempotent)
#   3. docker compose --profile shuffle up -d --build
#   4. Shuffle backend healthy 대기
#   5. Shuffle 첫 admin 자동 가입 + apikey 추출 → .env 주입
#      (이미 사용자 있으면 .env의 SHUFFLE_API_KEY 그대로 사용)
#   6. scripts/shuffle_import.sh 자동 호출 → 워크플로우 7개 복원
#   7. backend 재기동(.env 재로드)
#   8. 헬스 체크 + 결과 요약

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
    TOKEN=$(openssl rand -hex 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(32))")
    DB_PW=$(openssl rand -hex 16 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(16))")
    sed -i "s|^SECRET_KEY=.*|SECRET_KEY=$SECRET|" "$ENV_FILE"
    sed -i "s|^INTERNAL_API_TOKEN=.*|INTERNAL_API_TOKEN=$TOKEN|" "$ENV_FILE"
    sed -i "s|^DB_PASSWORD=.*|DB_PASSWORD=$DB_PW|" "$ENV_FILE"
    sed -i "s|^MYSQL_ROOT_PASSWORD=.*|MYSQL_ROOT_PASSWORD=$DB_PW|" "$ENV_FILE"
    sed -i "s|^EMAIL_DRY_RUN=.*|EMAIL_DRY_RUN=true|" "$ENV_FILE"
    green "  ✓ .env 새로 생성. SECRET_KEY/INTERNAL_API_TOKEN/DB_PASSWORD 자동 발급."
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

# ─── 1. docker swarm init ──────────────────────────────────────────────────────
step "1. Docker Swarm 초기화 (Shuffle Orborus 필수)"

SWARM_STATE=$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || echo "inactive")
if [ "$SWARM_STATE" = "active" ]; then
    green "  ✓ 이미 swarm active"
else
    # eth0(또는 ens) IP 추출 (다중 NIC 환경 대응)
    ADV_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="src")print $(i+1)}' | head -1)
    if [ -z "$ADV_IP" ]; then
        red "  ✗ 광고 IP 추출 실패 — 'docker swarm init --advertise-addr <IP>' 수동 실행"
        exit 2
    fi
    docker swarm init --advertise-addr "$ADV_IP" > /dev/null
    green "  ✓ swarm init --advertise-addr $ADV_IP"
fi

# ─── 2. shuffle_swarm_executions overlay 네트워크 ────────────────────────────
step "2. shuffle_swarm_executions overlay 네트워크"

if docker network ls --format '{{.Name}}' | grep -q '^shuffle_swarm_executions$'; then
    green "  ✓ 이미 존재"
else
    docker network create --driver overlay --attachable shuffle_swarm_executions > /dev/null
    green "  ✓ 생성"
fi

# ─── 3. docker compose 기동 ────────────────────────────────────────────────────
step "3. 컨테이너 기동 (Shuffle 포함 빌드)"

docker compose --profile shuffle up -d --build 2>&1 | tail -3

# ─── 4. 헬스 대기 ──────────────────────────────────────────────────────────────
step "4. 서비스 헬스 대기"

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
wait_for "shuffle frontend " "http://localhost:3001/" 60
# Shuffle backend register API는 OpenSearch 인덱싱 시간 필요 — 60초까지 대기
wait_for "shuffle backend  " "http://localhost:3001/api/v1/users/register" 90 || true

# ─── 5. Shuffle 첫 admin 자동 가입 + apikey 추출 ──────────────────────────────
step "5. Shuffle admin 부트스트랩"

SHUFFLE_ADMIN_USER="${SHUFFLE_ADMIN_USER:-zt-admin}"
SHUFFLE_ADMIN_PASS="${SHUFFLE_ADMIN_PASS:-$(openssl rand -hex 16 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(16))')}"
SHUFFLE_ADMIN_EMAIL="${SHUFFLE_ADMIN_EMAIL:-admin@local}"

# 이미 사용자 있는지 확인
REG_RESP=$(curl -s -X POST http://localhost:3001/api/v1/users/register \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$SHUFFLE_ADMIN_USER\",\"password\":\"$SHUFFLE_ADMIN_PASS\",\"email\":\"$SHUFFLE_ADMIN_EMAIL\"}" \
    || echo '{}')

REG_OK=$(echo "$REG_RESP" | python3 -c "import json,sys; d=json.loads(sys.stdin.read() or '{}'); print('true' if d.get('success') else 'false')" 2>/dev/null || echo "false")
REG_REASON=$(echo "$REG_RESP" | python3 -c "import json,sys; d=json.loads(sys.stdin.read() or '{}'); print(d.get('reason',''))" 2>/dev/null || echo "")

if [ "$REG_OK" = "true" ]; then
    green "  ✓ admin 자동 가입: $SHUFFLE_ADMIN_USER"
    # 가입 응답에서 apikey가 들어있을 수도 있고 별도 호출이 필요할 수도. 둘 다 시도.
    NEW_KEY=$(echo "$REG_RESP" | python3 -c "import json,sys; d=json.loads(sys.stdin.read() or '{}'); print(d.get('apikey') or d.get('id','') or '')" 2>/dev/null || echo "")
    if [ -z "$NEW_KEY" ] || [ ${#NEW_KEY} -lt 30 ]; then
        # /users/getinfo 로 apikey 조회 (쿠키 세션 필요할 수 있음)
        LOGIN_RESP=$(curl -s -c /tmp/shuffle-cookies.txt -X POST http://localhost:3001/api/v1/login \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"$SHUFFLE_ADMIN_USER\",\"password\":\"$SHUFFLE_ADMIN_PASS\"}" || echo '{}')
        NEW_KEY=$(echo "$LOGIN_RESP" | python3 -c "import json,sys; d=json.loads(sys.stdin.read() or '{}'); print(d.get('apikey') or '')" 2>/dev/null || echo "")
        if [ -z "$NEW_KEY" ]; then
            # 마지막 시도 — cookie 기반으로 getinfo
            INFO=$(curl -s -b /tmp/shuffle-cookies.txt http://localhost:3001/api/v1/users/getinfo || echo '{}')
            NEW_KEY=$(echo "$INFO" | python3 -c "import json,sys; d=json.loads(sys.stdin.read() or '{}'); print(d.get('apikey') or '')" 2>/dev/null || echo "")
        fi
    fi

    if [ -n "$NEW_KEY" ] && [ ${#NEW_KEY} -ge 30 ]; then
        sed -i "s|^SHUFFLE_URL=.*|SHUFFLE_URL=http://shuffle-backend:5001|" "$ENV_FILE"
        sed -i "s|^SHUFFLE_API_KEY=.*|SHUFFLE_API_KEY=$NEW_KEY|" "$ENV_FILE"
        green "  ✓ SHUFFLE_API_KEY 자동 추출 → .env 주입 (${NEW_KEY:0:8}…)"
        SHUFFLE_API_KEY="$NEW_KEY"
        # 자동 생성된 admin 비밀번호 안내
        yel  "  ⚠ Shuffle admin 자격 (분실하지 말 것):"
        yel  "      username: $SHUFFLE_ADMIN_USER"
        yel  "      password: $SHUFFLE_ADMIN_PASS"
        yel  "      url:      http://localhost:3001/admin"
    else
        red  "  ✗ apikey 자동 추출 실패. 수동으로 Shuffle UI 가입 + Manage API 발급 후"
        red  "    .env 의 SHUFFLE_API_KEY 채우고 다시 ./scripts/bootstrap.sh 재실행"
        exit 3
    fi
elif echo "$REG_REASON" | grep -q "already exist"; then
    yel "  ! Shuffle 이미 부트스트랩됨 — .env 의 SHUFFLE_API_KEY 사용"
    if [ -z "${SHUFFLE_API_KEY:-}" ]; then
        red "  ✗ .env 의 SHUFFLE_API_KEY 가 비어있음. Shuffle UI 에서 발급해서 채우고 재실행"
        exit 4
    fi
    green "  ✓ 기존 SHUFFLE_API_KEY 사용 (${SHUFFLE_API_KEY:0:8}…)"
else
    red "  ✗ register 응답 비정상: $REG_RESP"
    exit 5
fi

# ─── 6. 워크플로우 자동 복원 ──────────────────────────────────────────────────
step "6. Shuffle 워크플로우 7개 import"

if ls shuffle/workflows/zt-*.json >/dev/null 2>&1; then
    SHUFFLE_URL=http://localhost:3001 SHUFFLE_API_KEY="$SHUFFLE_API_KEY" \
        ./scripts/shuffle_import.sh || yel "  ! 일부 import 실패. Shuffle UI 에서 확인"
else
    yel "  ! shuffle/workflows/*.json 없음 — 워크플로우 수동 생성 필요 (DEPLOY.md 참조)"
fi

# ─── 7. backend 재기동 (.env 재로드) ──────────────────────────────────────────
step "7. backend 재기동 (.env 재로드)"

docker compose up -d --force-recreate zt-backend 2>&1 | tail -2
wait_for "backend          " "http://localhost:8000/health" 30

# ─── 8. 최종 요약 ──────────────────────────────────────────────────────────────
step "8. 부트스트랩 완료"

green "  ✓ frontend  : http://localhost:8080"
green "  ✓ backend   : http://localhost:8000"
green "  ✓ shuffle UI: http://localhost:3001"
green ""
green "  시드 데이터(체크리스트/개선가이드/데모세션)는 backend entrypoint 에서 자동 적재됨."
green "  진단 흐름 검증: ./scripts/e2e_smoke.sh"
green ""
green "  기본 진단 계정 (시드):"
green "    admin / admin"
green "    user1 / user1"
