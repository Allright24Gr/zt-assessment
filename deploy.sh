#!/bin/bash
set -e

# 사용법:
#   ./deploy.sh                      → 프롬프트 (엔터 = 로컬: localhost)
#   ./deploy.sh local                → 로컬 (localhost)                   · 볼륨 보존
#   ./deploy.sh 1.2.3.4              → EC2 퍼블릭 IP                       · 볼륨 보존
#   ./deploy.sh local reset          → 로컬 + 볼륨/이미지 초기화
#   ./deploy.sh 1.2.3.4 reset        → EC2  + 볼륨/이미지 초기화
#   ./deploy.sh 1.2.3.4 no-shuffle   → Shuffle SOAR 제외
#
# 기본은 **데이터 + 외부 이미지 보존** 모드 + **Shuffle 포함**.
#   - 우리 빌드 이미지(zt-backend / zt-frontend / *-wrapper)만 새로 빌드
#   - 외부 베이스 이미지(mysql / keycloak / wazuh / elasticsearch / shuffle)는 재사용
#     → 재다운로드 없음, 재시작이 **수십 초** 안에 끝남
#
# `reset` 인자를 주면 볼륨(DB)·외부 이미지까지 통째로 삭제 (시드 자동 재실행).
# `no-shuffle` 인자를 주면 Shuffle SOAR 컨테이너 4개를 제외.
#
# 사전 조건:
#   - 프로젝트 루트에 .env 파일 존재 (없으면 .env.example 복사 후 값 채우기)
#   - Docker / Docker Compose 설치
#   - (EC2) 보안그룹에 8080, 8000 포트 0.0.0.0/0 인바운드 허용

# ─── 인자 파싱 ───────────────────────────────────────────────────────────────
RESET_MODE=0
SHUFFLE_MODE=1   # 기본 ON

parse_flag() {
  case "$1" in
    reset)      RESET_MODE=1 ;;
    no-shuffle) SHUFFLE_MODE=0 ;;
  esac
}

if [ -n "$1" ]; then
  case "$1" in
    local|localhost)
      EC2_IP="localhost"
      ;;
    reset)
      EC2_IP="localhost"; RESET_MODE=1
      ;;
    no-shuffle)
      EC2_IP="localhost"; SHUFFLE_MODE=0
      ;;
    *)
      EC2_IP="$1"
      ;;
  esac
  parse_flag "$2"
  parse_flag "$3"
else
  read -rp "배포 대상 IP를 입력하세요 [엔터=로컬(localhost), 예: 1.2.3.4]: " INPUT
  EC2_IP="${INPUT:-localhost}"
fi

# ─── .env 존재 확인 (모든 컨테이너의 자격이 여기서 옴) ─────────────────────
if [ ! -f .env ]; then
  echo "❌ .env 파일이 프로젝트 루트에 없습니다."
  echo "   .env.example 을 복사해서 값을 채우거나, 팀에서 받은 .env 를 두세요:"
  echo "     cp .env.example .env"
  exit 1
fi

# Compose profile 인자
if [ $SHUFFLE_MODE -eq 1 ]; then
  PROFILE_ARGS=(--profile shuffle)
else
  PROFILE_ARGS=()
fi

echo "배포 대상: $EC2_IP"
[ $RESET_MODE -eq 1 ] && echo "⚠️  RESET 모드: 볼륨 + 외부 이미지 초기화" \
                     || echo "💾 보존 모드: 우리 이미지만 재빌드"
[ $SHUFFLE_MODE -eq 1 ] && echo "🔄 Shuffle SOAR: 포함" \
                       || echo "🚫 Shuffle SOAR: 제외 (no-shuffle)"

export VITE_API_BASE="http://${EC2_IP}:8000"
export CORS_ORIGINS="http://${EC2_IP}:8080"

echo "VITE_API_BASE=${VITE_API_BASE}"
echo "CORS_ORIGINS=${CORS_ORIGINS}"

# ─── 정리 ────────────────────────────────────────────────────────────────────
echo ""
if [ $RESET_MODE -eq 1 ]; then
  echo "🧹 풀 클린 (컨테이너·이미지·볼륨 모두 삭제)..."
  docker compose --profile shuffle down -v --remove-orphans --rmi all 2>/dev/null || true
else
  echo "🧹 컨테이너만 정리 (이미지·볼륨·캐시 보존)..."
  # --profile shuffle 도 같이 정리 — 이전에 띄운 게 남아있어도 깨끗이
  docker compose --profile shuffle down --remove-orphans 2>/dev/null || true
fi

# ─── 기동 ────────────────────────────────────────────────────────────────────
echo ""
echo "🏗️  이미지 빌드 + 컨테이너 기동..."
docker compose "${PROFILE_ARGS[@]}" up -d --build --remove-orphans

# ─── 헬스체크 (최대 90초) ──────────────────────────────────────────────────
echo ""
echo "⏳ Backend 헬스체크..."
HEALTHY=0
for i in $(seq 1 30); do
  if curl -fsS "http://localhost:8000/health" >/dev/null 2>&1; then
    HEALTHY=1
    echo "   ✅ Backend OK ($i회 시도)"
    break
  fi
  sleep 3
done

if [ $HEALTHY -eq 0 ]; then
  echo "   ❌ Backend 헬스체크 실패 (90초 초과)"
  echo ""
  echo "── docker compose ps ───────────────────────────────────────────"
  docker compose ps
  echo ""
  echo "── zt-backend 최근 로그 (마지막 60줄) ─────────────────────────"
  docker compose logs --tail=60 zt-backend || true
  echo ""
  echo "💡 흔한 원인:"
  echo "   - .env 의 DB_USER/DB_PASSWORD/MYSQL_ROOT_PASSWORD 불일치"
  echo "   - 기존 mysql 볼륨이 옛 비번을 쥐고 있음 → './deploy.sh $EC2_IP reset' 으로 볼륨 새로"
  echo "   - 스키마 드리프트 → 위 로그에 'Unknown column' 있으면 migrate_schema 확인"
  exit 1
fi

echo ""
echo "✅ 배포 완료"
echo "   메인:    http://${EC2_IP}:8080"
echo "   API:     http://${EC2_IP}:8000/health"
[ $SHUFFLE_MODE -eq 1 ] && echo "   Shuffle: http://${EC2_IP}:3001"
echo ""
if [ $RESET_MODE -eq 1 ]; then
  echo "시드 계정 (자동 재시드됨): admin / admin   ·   user1 / user1"
else
  echo "사용자 데이터 유지됨. 시드 계정 변경 안 했다면: admin / admin   ·   user1 / user1"
fi
