#!/usr/bin/env bash
#
# shuffle_export.sh — 로컬 Shuffle 에 있는 zt-* 워크플로우를 JSON 으로 export.
#
# 사용:
#   SHUFFLE_API_KEY=<키> ./scripts/shuffle_export.sh
#   SHUFFLE_URL=http://localhost:3001 SHUFFLE_API_KEY=<키> ./scripts/shuffle_export.sh
#
# 출력:
#   shuffle/workflows/zt-{tool}.json  (이름 그대로)
#
# 흐름:
#   1. /api/v1/workflows 로 전체 목록 조회
#   2. name 이 "zt-" 로 시작하는 것만 필터
#   3. 각 워크플로우 상세 JSON 을 파일로 저장 (id/org_id 포함 — import 시 제거)
#
# git 에 커밋해 두면 EC2 등 새 환경에서 shuffle_import.sh 로 1줄 복원 가능.

set -eu

SHUFFLE_URL="${SHUFFLE_URL:-http://localhost:3001}"
SHUFFLE_API_KEY="${SHUFFLE_API_KEY:?SHUFFLE_API_KEY 환경변수 필요}"
OUTDIR="${OUTDIR:-shuffle/workflows}"

command -v jq   >/dev/null || { echo "jq 필요 (apt install jq)"; exit 1; }
command -v curl >/dev/null || { echo "curl 필요"; exit 1; }

mkdir -p "$OUTDIR"

echo "[export] $SHUFFLE_URL 에서 워크플로우 목록 조회..."
LIST=$(curl -fsS "$SHUFFLE_URL/api/v1/workflows" \
    -H "Authorization: Bearer $SHUFFLE_API_KEY")

# Shuffle 응답이 객체 안에 .workflows 일 수도, 배열일 수도. 둘 다 처리.
WFS=$(echo "$LIST" | jq -c 'if type=="array" then . else .workflows end' 2>/dev/null || echo "$LIST")

COUNT=0
echo "$WFS" | jq -c '.[] | select(.name | startswith("zt-"))' | while read -r wf; do
    NAME=$(echo "$wf" | jq -r '.name')
    ID=$(echo "$wf"   | jq -r '.id // .workflow_id')
    OUT="$OUTDIR/$NAME.json"

    echo "[export]   $NAME ($ID) → $OUT"
    curl -fsS "$SHUFFLE_URL/api/v1/workflows/$ID" \
        -H "Authorization: Bearer $SHUFFLE_API_KEY" \
    | jq '.' > "$OUT"

    COUNT=$((COUNT + 1))
done

echo ""
echo "[export] 완료. 출력 파일:"
ls -la "$OUTDIR"/zt-*.json 2>/dev/null || echo "  (zt-* 워크플로우 0개 발견 — 워크플로우 이름이 zt- 로 시작해야 함)"
echo ""
echo "다음: git add shuffle/workflows/ && git commit -m 'shuffle workflows snapshot'"
