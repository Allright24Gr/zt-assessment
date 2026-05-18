#!/bin/bash
set -e

# 사용법:
#   ./deploy.sh                      → 프롬프트 (엔터 = 로컬: localhost)
#   ./deploy.sh local                → 로컬 (localhost)                   · 볼륨 보존
#   ./deploy.sh 1.2.3.4              → EC2 퍼블릭 IP                       · 볼륨 보존
#   ./deploy.sh local reset          → 로컬 + 볼륨/이미지 초기화
#   ./deploy.sh 1.2.3.4 reset        → EC2  + 볼륨/이미지 초기화
#
# 기본은 **데이터 + 외부 이미지 보존** 모드.
#   - 우리 빌드 이미지(zt-backend / zt-frontend / *-wrapper)만 새로 빌드
#   - 외부 베이스 이미지(mysql / keycloak / wazuh / elasticsearch)는 재사용
#     → 재다운로드 없음, 재시작이 **수십 초** 안에 끝남
#
# `reset` 인자를 주면 볼륨(DB)·외부 이미지까지 통째로 삭제 (시드 자동 재실행).
#
# Shuffle SOAR 은 옵션 컴포넌트라 기본 배포에서 제외.
# 필요할 때만:   docker compose --profile shuffle up -d

RESET_MODE=0
if [ -n "$1" ]; then
  if [ "$1" = "local" ] || [ "$1" = "localhost" ]; then
    EC2_IP="localhost"
  elif [ "$1" = "reset" ]; then
    EC2_IP="localhost"
    RESET_MODE=1
  else
    EC2_IP="$1"
  fi
  if [ "$2" = "reset" ]; then
    RESET_MODE=1
  fi
else
  read -rp "배포 대상 IP를 입력하세요 [엔터=로컬(localhost), 예: 1.2.3.4]: " INPUT
  EC2_IP="${INPUT:-localhost}"
fi

echo "배포 대상: $EC2_IP"
if [ $RESET_MODE -eq 1 ]; then
  echo "⚠️  RESET 모드: 볼륨 + 외부 이미지까지 모두 초기화합니다."
else
  echo "💾 보존 모드: 우리 이미지만 재빌드. 외부 이미지·DB·세션 모두 유지."
fi

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
  echo "🧹 컨테이너만 정리 (이미지·볼륨·캐시 모두 보존)..."
  # --profile shuffle 을 같이 줘서 이전 실행에서 띄운 shuffle 컨테이너가 있으면 정리
  # 단, 외부 이미지는 보존 — --rmi 옵션을 주지 않음
  docker compose --profile shuffle down --remove-orphans 2>/dev/null || true
fi

# ─── 기동 ────────────────────────────────────────────────────────────────────
# shuffle 프로파일은 기본 제외 (ghcr.io 풀링 회피, SOAR 는 옵션)
echo ""
echo "🏗️  이미지 빌드 + 컨테이너 기동..."
docker compose up -d --build --remove-orphans

echo ""
echo "✅ 배포 완료"
echo "   메인:    http://${EC2_IP}:8080"
echo "   API:     http://${EC2_IP}:8000/health"
echo ""
if [ $RESET_MODE -eq 1 ]; then
  echo "시드 계정 (자동 재시드됨): admin / admin   ·   user1 / user1"
else
  echo "사용자 데이터 유지됨. 시드 계정 변경 안 했다면: admin / admin   ·   user1 / user1"
fi
echo ""
echo "ℹ️  Shuffle SOAR (옵션) 필요 시: docker compose --profile shuffle up -d"
