#!/bin/bash
set -e

# EC2 IP 입력받기
if [ -n "$1" ]; then
  EC2_IP="$1"
else
  read -rp "EC2 퍼블릭 IP를 입력하세요 (예: 1.2.3.4): " EC2_IP
fi

if [ -z "$EC2_IP" ]; then
  echo "오류: IP를 입력해야 합니다."
  exit 1
fi

echo "배포 대상 IP: $EC2_IP"

export VITE_API_BASE="http://${EC2_IP}:8000"
export CORS_ORIGINS="http://${EC2_IP}:8080"

echo "VITE_API_BASE=${VITE_API_BASE}"
echo "CORS_ORIGINS=${CORS_ORIGINS}"

docker compose up -d --build
