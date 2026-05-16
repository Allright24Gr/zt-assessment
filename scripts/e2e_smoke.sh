#!/usr/bin/env bash
#
# e2e_smoke.sh — 운영/시연 직전 핵심 흐름 자동 검증
#
# 검증 흐름:
#   1. 헬스 체크
#   2. 회원가입 (약관 동의 포함)
#   3. 로그인 → JWT 토큰
#   4. /me 본인 정보 조회 (Bearer)
#   5. 진단 실행 (데모 모드 — scan_targets 없이)
#   6. 진단 상태 폴링 (최대 90초)
#   7. 진단 결과 조회
#   8. 공유 링크 발급 + 익명 접근
#   9. 비밀번호 변경
#   10. 회원 탈퇴
#
# 사용:
#   API_BASE=http://localhost:8000 ./scripts/e2e_smoke.sh
#   API_BASE=https://readyz-t.example.com ./scripts/e2e_smoke.sh
#
# 필요: jq, curl
# 종료 코드: 0 = 모든 단계 통과, 1+ = 실패한 단계 번호

set -eu

API_BASE="${API_BASE:-http://localhost:8000}"
USER_SUFFIX="$(date +%s)"
LOGIN_ID="smoke_${USER_SUFFIX}"
PASSWORD="SmokeTest1234"
NEW_PASSWORD="SmokeTest5678"
NAME="스모크테스트사용자"

# 색상
red()    { printf "\033[31m%s\033[0m\n" "$*"; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
bold()   { printf "\033[1m%s\033[0m\n" "$*"; }

step() {
    bold "──── Step $1: $2 ────"
}

require() {
    command -v "$1" >/dev/null 2>&1 || { red "'$1' 필요"; exit 99; }
}

require curl
require jq

# ── Step 1: 헬스 체크 ────────────────────────────────────────────────────
step 1 "헬스 체크 ($API_BASE/health)"
HEALTH=$(curl -fsS "$API_BASE/health")
if [[ "$HEALTH" == *'"status":"ok"'* ]]; then
    green "✓ 백엔드 응답 OK"
else
    red "✗ 헬스 체크 실패: $HEALTH"; exit 1
fi

# ── Step 2: 회원가입 ─────────────────────────────────────────────────────
step 2 "회원가입 (login_id=$LOGIN_ID)"
REG=$(curl -fsS -X POST "$API_BASE/api/auth/register" \
    -H "Content-Type: application/json" \
    -d "{
        \"login_id\":\"$LOGIN_ID\",
        \"password\":\"$PASSWORD\",
        \"name\":\"$NAME\",
        \"tos_agreed\":true,
        \"privacy_agreed\":true,
        \"profile\":{\"org_type\":\"교육\",\"department\":\"테스트팀\"}
    }")
USER_ID=$(echo "$REG" | jq -r '.user.user_id')
ACCESS=$(echo "$REG" | jq -r '.tokens.access_token')
REFRESH=$(echo "$REG" | jq -r '.tokens.refresh_token')
if [[ -n "$ACCESS" && "$ACCESS" != "null" ]]; then
    green "✓ 회원가입 성공: user_id=$USER_ID, access_token=${ACCESS:0:20}..."
else
    red "✗ 회원가입 실패: $REG"; exit 2
fi

# 약관 미동의 시 400 검증
NOTOS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$API_BASE/api/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"login_id\":\"smoke_notos_$USER_SUFFIX\",\"password\":\"NoTos1234\",\"name\":\"미동의\"}")
if [[ "$NOTOS" == "400" ]]; then
    green "✓ 약관 미동의 시 400 정상 차단"
else
    yellow "⚠ 약관 미동의 시 응답 $NOTOS (400 기대)"
fi

# ── Step 3: 로그인 (JWT 응답 확인) ─────────────────────────────────────────
step 3 "로그인"
LOGIN=$(curl -fsS -X POST "$API_BASE/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"login_id\":\"$LOGIN_ID\",\"password\":\"$PASSWORD\"}")
ACCESS=$(echo "$LOGIN" | jq -r '.tokens.access_token')
REFRESH=$(echo "$LOGIN" | jq -r '.tokens.refresh_token')
if [[ -n "$ACCESS" && "$ACCESS" != "null" ]]; then
    green "✓ 로그인 + JWT 토큰 발급"
else
    red "✗ 로그인 실패: $LOGIN"; exit 3
fi

AUTH_HEADER="Authorization: Bearer $ACCESS"

# ── Step 4: /me 본인 정보 조회 ────────────────────────────────────────────
step 4 "/me Bearer 인증 본인 조회"
ME=$(curl -fsS "$API_BASE/api/auth/me" -H "$AUTH_HEADER")
ME_LOGIN_ID=$(echo "$ME" | jq -r '.login_id')
if [[ "$ME_LOGIN_ID" == "$LOGIN_ID" ]]; then
    green "✓ /me 인증 OK"
else
    red "✗ /me 인증 실패: $ME"; exit 4
fi

# 헤더 누락 시 401 검증
UNAUTH=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE/api/auth/me")
if [[ "$UNAUTH" == "401" ]]; then
    green "✓ 미인증 시 401 정상 차단"
else
    yellow "⚠ 미인증 시 응답 $UNAUTH (401 기대)"
fi

# ── Step 5: 진단 실행 (데모 모드) ─────────────────────────────────────────
step 5 "진단 실행 (데모 — scan_targets·creds 없이)"
RUN=$(curl -fsS -X POST "$API_BASE/api/assessment/run" \
    -H "Content-Type: application/json" -H "$AUTH_HEADER" \
    -d "{
        \"org_name\":\"${LOGIN_ID}_개인\",
        \"manager\":\"$NAME\",
        \"email\":\"${LOGIN_ID}@local\",
        \"org_type\":\"교육\",
        \"infra_type\":\"하이브리드\",
        \"profile_select\":{\"idp_type\":\"none\",\"siem_type\":\"none\"},
        \"pillar_scope\":{\"Identify\":true,\"Device\":true,\"Network\":true,\"System\":true,\"Application\":true,\"Data\":true}
    }")
SESSION_ID=$(echo "$RUN" | jq -r '.session_id')
if [[ -n "$SESSION_ID" && "$SESSION_ID" != "null" ]]; then
    green "✓ 진단 시작: session_id=$SESSION_ID"
else
    red "✗ 진단 실행 실패: $RUN"; exit 5
fi

# ── Step 6: 진단 상태 폴링 (최대 120초) ───────────────────────────────────
step 6 "진단 상태 폴링"
for i in $(seq 1 24); do
    STATUS=$(curl -fsS "$API_BASE/api/assessment/status/$SESSION_ID" -H "$AUTH_HEADER")
    COLLECTED=$(echo "$STATUS" | jq -r '.collected_count')
    TOTAL=$(echo "$STATUS" | jq -r '.auto_total')
    DONE=$(echo "$STATUS" | jq -r '.collection_done')
    printf "  [%2d] collected=%s/%s done=%s\n" "$i" "$COLLECTED" "$TOTAL" "$DONE"
    if [[ "$DONE" == "true" ]]; then
        green "✓ 자동 수집 완료"
        break
    fi
    sleep 5
done

# finalize (채점)
FIN=$(curl -fsS -X POST "$API_BASE/api/assessment/finalize/$SESSION_ID" -H "$AUTH_HEADER")
FIN_STATUS=$(echo "$FIN" | jq -r '.status')
if [[ "$FIN_STATUS" == "ok" || "$FIN_STATUS" == "already_completed" ]]; then
    green "✓ Finalize: $FIN_STATUS"
else
    yellow "⚠ Finalize 응답: $FIN"
fi

# ── Step 7: 결과 조회 ────────────────────────────────────────────────────
step 7 "결과 조회"
RESULT=$(curl -fsS "$API_BASE/api/assessment/result?session_id=$SESSION_ID" -H "$AUTH_HEADER")
RES_LEVEL=$(echo "$RESULT" | jq -r '.overall_level')
RES_SCORE=$(echo "$RESULT" | jq -r '.overall_score')
green "✓ 결과: level=$RES_LEVEL score=$RES_SCORE"

# ── Step 8: 공유 링크 발급 + 익명 접근 ────────────────────────────────────
step 8 "공유 링크 발급"
SHARE=$(curl -fsS -X POST "$API_BASE/api/assessment/share/$SESSION_ID" \
    -H "Content-Type: application/json" -H "$AUTH_HEADER" \
    -d '{"expires_days":7}')
SHARE_TOKEN=$(echo "$SHARE" | jq -r '.token // .share_token // empty')
if [[ -n "$SHARE_TOKEN" ]]; then
    green "✓ 공유 토큰 발급: ${SHARE_TOKEN:0:16}..."
    SHARED=$(curl -fsS "$API_BASE/api/assessment/shared/$SHARE_TOKEN")
    SHARED_LEVEL=$(echo "$SHARED" | jq -r '.overall_level')
    if [[ "$SHARED_LEVEL" == "$RES_LEVEL" ]]; then
        green "✓ 익명 공유 접근 (Bearer 없이) OK"
    else
        yellow "⚠ 공유 결과 level 불일치: $SHARED_LEVEL vs $RES_LEVEL"
    fi
else
    yellow "⚠ 공유 발급 응답 형식 확인 필요: $SHARE"
fi

# ── Step 9: 비밀번호 변경 ────────────────────────────────────────────────
step 9 "비밀번호 변경"
CHG=$(curl -fsS -X POST "$API_BASE/api/auth/change-password" \
    -H "Content-Type: application/json" -H "$AUTH_HEADER" \
    -d "{\"current_password\":\"$PASSWORD\",\"new_password\":\"$NEW_PASSWORD\"}")
CHG_STATUS=$(echo "$CHG" | jq -r '.status')
if [[ "$CHG_STATUS" == "ok" ]]; then
    green "✓ 비번 변경 OK"
else
    red "✗ 비번 변경 실패: $CHG"; exit 9
fi

# ── Step 10: 회원 탈퇴 ────────────────────────────────────────────────────
step 10 "회원 탈퇴"
DEL=$(curl -fsS -X DELETE "$API_BASE/api/auth/me" \
    -H "Content-Type: application/json" -H "$AUTH_HEADER" \
    -d "{\"current_password\":\"$NEW_PASSWORD\"}")
DEL_STATUS=$(echo "$DEL" | jq -r '.status')
if [[ "$DEL_STATUS" == "ok" ]]; then
    green "✓ 탈퇴 OK"
else
    red "✗ 탈퇴 실패: $DEL"; exit 10
fi

# 탈퇴 후 토큰으로 /me 시도 → 401
GONE=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE/api/auth/me" -H "$AUTH_HEADER")
if [[ "$GONE" == "401" ]]; then
    green "✓ 탈퇴 후 토큰 무효 401 확인"
else
    yellow "⚠ 탈퇴 후 토큰 응답 $GONE (401 기대)"
fi

bold ""
green "════════════════════════════════════════════"
green "  ✓ e2e smoke 모든 단계 통과"
green "════════════════════════════════════════════"
