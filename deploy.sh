#!/bin/bash
set -e

# 사용법:
#   ./deploy.sh                      → 프롬프트 (엔터 = 로컬: localhost)  · 볼륨 보존
#   ./deploy.sh local                → 로컬 (localhost)                   · 볼륨 보존
#   ./deploy.sh 1.2.3.4              → EC2 퍼블릭 IP                       · 볼륨 보존
#   ./deploy.sh 1.2.3.4 reset        → 위와 동일하지만 mysql·shuffle 볼륨까지 초기화
#
# 기본 동작은 **데이터 보존** — 코드만 새로 빌드하고 이미지·컨테이너는 재기동, 볼륨(DB)은 유지.
# `reset` 인자를 주면 DB 까지 통째로 초기화 (시드 자동 재실행).

RESET_MODE=0
if [ -n "$1" ]; then
  if [ "$1" = "local" ] || [ "$1" = "localhost" ]; then
    EC2_IP="localhost"
  else
    EC2_IP="$1"
  fi
  if [ "$2" = "reset" ] || [ "$1" = "reset" ]; then
    RESET_MODE=1
    if [ "$1" = "reset" ]; then
      EC2_IP="localhost"
    fi
  fi
else
  read -rp "배포 대상 IP를 입력하세요 [엔터=로컬(localhost), 예: 1.2.3.4]: " INPUT
  EC2_IP="${INPUT:-localhost}"
fi

echo "배포 대상: $EC2_IP"
if [ $RESET_MODE -eq 1 ]; then
  echo "⚠️  RESET 모드: mysql·shuffle 볼륨까지 모두 초기화합니다."
else
  echo "💾 데이터 보존 모드: 코드만 새로 빌드. 진단 세션·사용자 데이터 유지."
fi

export VITE_API_BASE="http://${EC2_IP}:8000"
export CORS_ORIGINS="http://${EC2_IP}:8080"

echo "VITE_API_BASE=${VITE_API_BASE}"
echo "CORS_ORIGINS=${CORS_ORIGINS}"

# ─── 정리 ────────────────────────────────────────────────────────────────────
# 학생 PoC 전용 EC2 가정 — 매번 이미지·컨테이너 새로. 볼륨은 RESET 모드에서만 삭제.
echo ""
if [ $RESET_MODE -eq 1 ]; then
  echo "🧹 이전 컨테이너·이미지·볼륨 모두 정리 중 (RESET)..."
  docker compose --profile shuffle down -v --remove-orphans --rmi all 2>/dev/null || true
  docker system prune -af --volumes
else
  echo "🧹 이전 컨테이너·이미지·빌드 캐시 정리 (볼륨 보존)..."
  docker compose --profile shuffle down --remove-orphans --rmi all 2>/dev/null || true
  docker image prune -af
  docker builder prune -af 2>/dev/null || true
fi

echo ""
echo "🏗️  새 이미지 빌드 + 컨테이너 기동..."
docker compose --profile shuffle up -d --build --force-recreate --remove-orphans

echo ""
echo "✅ 배포 완료"
echo "   메인:    http://${EC2_IP}:8080"
echo "   API:     http://${EC2_IP}:8000/health"
echo "   Shuffle: http://${EC2_IP}:3001"
echo ""
if [ $RESET_MODE -eq 1 ]; then
  echo "시드 계정 (자동 재시드됨): admin / admin   ·   user1 / user1"
else
  echo "사용자 데이터 유지됨. 시드 계정 변경 안 했다면: admin / admin   ·   user1 / user1"
fi
