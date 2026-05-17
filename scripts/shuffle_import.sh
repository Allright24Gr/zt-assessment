#!/usr/bin/env bash
#
# shuffle_import.sh — 새 Shuffle 환경에 zt-* 워크플로우 일괄 복원.
#
# 사용:
#   SHUFFLE_API_KEY=<새환경키> ./scripts/shuffle_import.sh
#   SHUFFLE_URL=http://shuffle.example.com SHUFFLE_API_KEY=<키> ./scripts/shuffle_import.sh
#
# 동작:
#   1. shuffle/workflows/zt-*.json 파일들을 POST /api/v1/workflows 로 import
#   2. 새 워크플로우 ID 받아 .env 의 SHUFFLE_WORKFLOW_<TOOL> 자동 갱신
#   3. 마지막에 backend 재시작 안내
#
# 환경변수:
#   SHUFFLE_URL      (기본 http://localhost:3001)
#   SHUFFLE_API_KEY  (필수)
#   INDIR            (기본 shuffle/workflows)
#   ENV_FILE         (기본 .env)
#   DRY_RUN          (true 시 실제 import 안 하고 미리보기만)

set -eu

SHUFFLE_URL="${SHUFFLE_URL:-http://localhost:3001}"
SHUFFLE_API_KEY="${SHUFFLE_API_KEY:?SHUFFLE_API_KEY 환경변수 필요}"
INDIR="${INDIR:-shuffle/workflows}"
ENV_FILE="${ENV_FILE:-.env}"
DRY_RUN="${DRY_RUN:-false}"

command -v jq   >/dev/null || { echo "jq 필요 (apt install jq)"; exit 1; }
command -v curl >/dev/null || { echo "curl 필요"; exit 1; }

if [ ! -d "$INDIR" ]; then
    echo "[import] $INDIR 없음 — shuffle_export.sh 먼저 실행해야 함"; exit 1
fi

FILES=("$INDIR"/zt-*.json)
if [ "${#FILES[@]}" -eq 0 ] || [ ! -f "${FILES[0]}" ]; then
    echo "[import] $INDIR/zt-*.json 파일 없음"; exit 1
fi

echo "[import] 대상 ${#FILES[@]} 개"
declare -A ID_MAP

for f in "${FILES[@]}"; do
    NAME=$(jq -r '.name' "$f")
    # import 시 id/org_id/소유자 정보는 새로 발급되어야 하므로 제거.
    # execution_environment 등 환경 의존 필드도 비워서 새 환경 default 가 적용되게.
    PAYLOAD=$(jq 'del(.id, .org_id, .owner, .public, .execution_environment, .created, .edited, .last_runtime)' "$f")

    if [ "$DRY_RUN" = "true" ]; then
        echo "[import]   [DRY] $NAME (payload $(echo "$PAYLOAD" | wc -c) bytes)"
        continue
    fi

    echo "[import]   $NAME 생성 시도..."
    RESP=$(curl -sS -X POST "$SHUFFLE_URL/api/v1/workflows" \
        -H "Authorization: Bearer $SHUFFLE_API_KEY" \
        -H "Content-Type: application/json" \
        -d "$PAYLOAD" \
        -w "\nHTTP_STATUS:%{http_code}")
    HTTP_STATUS=$(echo "$RESP" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d: -f2)
    BODY=$(echo "$RESP" | sed '/^HTTP_STATUS:/d')

    if [ "$HTTP_STATUS" != "200" ] && [ "$HTTP_STATUS" != "201" ]; then
        echo "[import]   ✗ $NAME HTTP $HTTP_STATUS: $BODY"
        continue
    fi

    NEW_ID=$(echo "$BODY" | jq -r '.id // .workflow_id // empty')
    if [ -z "$NEW_ID" ]; then
        echo "[import]   ✗ $NAME 응답에서 id 추출 실패: $BODY"
        continue
    fi

    # 이름 zt-keycloak → KEYCLOAK
    TOOL=$(echo "$NAME" | sed 's/^zt-//' | tr '[:lower:]' '[:upper:]')
    KEY="SHUFFLE_WORKFLOW_$TOOL"
    ID_MAP["$KEY"]="$NEW_ID"
    echo "[import]   ✓ $NAME → $NEW_ID ($KEY)"
done

if [ "$DRY_RUN" = "true" ]; then
    echo ""
    echo "[import] DRY_RUN — .env 변경 없음."
    exit 0
fi

if [ "${#ID_MAP[@]}" -eq 0 ]; then
    echo "[import] 성공한 워크플로우 0건 — .env 변경 안 함"; exit 1
fi

# .env 갱신 (key 가 이미 있으면 교체, 없으면 append)
echo ""
echo "[import] $ENV_FILE 갱신..."
for KEY in "${!ID_MAP[@]}"; do
    VAL="${ID_MAP[$KEY]}"
    if grep -q "^${KEY}=" "$ENV_FILE" 2>/dev/null; then
        sed -i.bak "s|^${KEY}=.*|${KEY}=${VAL}|" "$ENV_FILE" && rm -f "${ENV_FILE}.bak"
        echo "  - 갱신: $KEY=$VAL"
    else
        echo "${KEY}=${VAL}" >> "$ENV_FILE"
        echo "  + 추가: $KEY=$VAL"
    fi
done

echo ""
echo "[import] 완료. 다음 한 줄로 backend 재시작:"
echo "    docker compose restart zt-backend"
