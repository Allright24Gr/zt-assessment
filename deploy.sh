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

docker compose up -d --build
