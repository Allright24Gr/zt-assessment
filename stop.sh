#!/bin/bash
# 사용법:
#   ./stop.sh          → 컨테이너만 멈춤 (가장 안전, 빠르게 다시 시작 가능)
#   ./stop.sh down     → 컨테이너 + 네트워크 제거 (볼륨·이미지·DB 데이터 모두 보존)
#   ./stop.sh wipe     → 컨테이너 + 볼륨 모두 삭제 (DB·진단 이력 전부 사라짐. 확인 묻고 진행)
#
# 기본 동작은 가장 안전한 'stop' 입니다.
# DB 진단 이력, 업로드한 증적 파일, 사용자 계정 모두 보존됩니다.
# 다시 켤 때: ./deploy.sh local (또는 ./deploy.sh <EC2_IP>)

set -e

MODE="${1:-stop}"

case "$MODE" in
  stop)
    echo "▶ 컨테이너 정지 (데이터 100% 보존)"
    docker compose stop
    echo "✅ 모든 컨테이너 정지 완료."
    echo "   DB·진단 이력·업로드 파일 보존됨."
    echo "   다시 시작: ./deploy.sh local  또는  ./deploy.sh <EC2_IP>"
    echo "   빠른 재시작 (이미지 재사용): docker compose start"
    ;;
  down)
    echo "▶ 컨테이너 + 네트워크 제거 (볼륨·이미지 보존)"
    docker compose down
    echo "✅ 정리 완료."
    echo "   DB·진단 이력은 mysql-data 볼륨에 그대로 남아있음."
    echo "   다시 시작: ./deploy.sh local"
    ;;
  wipe)
    echo "⚠️  WARNING: 이 명령은 DB·진단 이력·업로드 파일을 모두 삭제합니다."
    echo "   사용자 계정 / 모든 진단 결과 / 증적 파일이 사라집니다."
    read -p "정말 모두 지우려면 'YES' 입력: " CONFIRM
    if [ "$CONFIRM" != "YES" ]; then
      echo "취소되었습니다."
      exit 0
    fi
    docker compose down -v
    echo "🧹 컨테이너 + 볼륨 전부 삭제 완료."
    ;;
  *)
    echo "사용법:"
    echo "  ./stop.sh          → 컨테이너만 멈춤 (기본, 데이터 보존)"
    echo "  ./stop.sh down     → 컨테이너+네트워크 제거 (데이터 보존)"
    echo "  ./stop.sh wipe     → 전부 삭제 (DB 포함, 확인 필요)"
    exit 1
    ;;
esac
