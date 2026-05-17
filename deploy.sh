#!/bin/bash
set -e

# 사용법:
#   ./deploy.sh                  → 프롬프트 (엔터 = 로컬: localhost)
#   ./deploy.sh local            → 로컬 (localhost)
#   ./deploy.sh 1.2.3.4          → EC2 퍼블릭 IP
#
# 인자가 "local"이면 localhost로 동작, 그 외엔 입력한 IP/도메인 그대로 사용.

if [ -n "$1" ]; then
  if [ "$1" = "local" ] || [ "$1" = "localhost" ]; then
    EC2_IP="localhost"
  else
    EC2_IP="$1"
  fi
else
  read -rp "배포 대상 IP를 입력하세요 [엔터=로컬(localhost), 예: 1.2.3.4]: " INPUT
  EC2_IP="${INPUT:-localhost}"
fi

echo "배포 대상: $EC2_IP"

export VITE_API_BASE="http://${EC2_IP}:8000"
export CORS_ORIGINS="http://${EC2_IP}:8080"

echo "VITE_API_BASE=${VITE_API_BASE}"
echo "CORS_ORIGINS=${CORS_ORIGINS}"

# ─── 완전 클린 빌드 (학생 PoC 전용 EC2 가정) ───────────────────────────────────
# 이 EC2 는 zt-assessment 전용. 다른 프로젝트 없으니 매번 모든 이미지·컨테이너·
# 볼륨·네트워크·빌드 캐시를 청소하고 새로 빌드한다 → 매번 깨끗한 상태로 시작.
#
# ⚠️ 부작용:
#   - mysql 볼륨 삭제 → 진단 세션·사용자 다 날아감 (entrypoint.sh 가 시드 자동 재실행)
#   - 이미지 캐시 없음 → 첫 빌드 시간 다소 길어짐 (보통 1~3분)

echo ""
echo "🧹 이전 컨테이너·이미지·볼륨 정리 중..."
docker compose --profile shuffle down -v --remove-orphans --rmi all 2>/dev/null || true
docker system prune -af --volumes

echo ""
echo "🏗️  새 이미지 빌드 + 컨테이너 기동..."
docker compose --profile shuffle up -d --build --force-recreate --remove-orphans

echo ""
echo "✅ 배포 완료"
echo "   메인:    http://${EC2_IP}:8080"
echo "   API:     http://${EC2_IP}:8000/health"
echo "   Shuffle: http://${EC2_IP}:3001"
echo ""
echo "시드 계정: admin / admin   ·   user1 / user1"
