Readyz-T - ZT Assessment 프로젝트 가이드
프로젝트 개요
제로트러스트 가이드라인 2.0 기반 성숙도 진단 자동화 플랫폼.

기술 스택
Frontend: React + TypeScript + Vite + shadcn/ui

Backend: Python + FastAPI + SQLAlchemy

DB: MySQL

SOAR: Shuffle

진단 도구: Keycloak, Wazuh, Nmap(래퍼), Trivy(래퍼)

인프라: Docker Compose, AWS EC2

디렉토리 구조
zt-assessment/
├── frontend/                  # React 프론트엔드
│   ├── src/app/pages/         # Dashboard, History, NewAssessment, Reporting
│   ├── src/app/data/          # mockData.ts, checklistItems.ts, constants.ts
│   ├── src/config/api.ts      # API 호출 함수
│   └── src/types/api.ts       # TypeScript 타입 정의
├── backend/                   # FastAPI 백엔드
│   ├── main.py                # 앱 진입점
│   ├── database.py            # DB 연결
│   ├── models.py              # SQLAlchemy 모델 (10개 테이블)
│   ├── routers/               # API 엔드포인트
│   │   ├── assessment.py      # 진단 실행/결과/이력
│   │   ├── score.py           # 점수 요약/추세
│   │   ├── improvement.py     # 개선 권고
│   │   ├── report.py          # 리포트 생성
│   │   ├── checklist.py       # 체크리스트 목록
│   │   └── manual.py          # 수동 항목 제출
│   ├── collectors/            # 도구별 수집 모듈
│   │   ├── keycloak_collector.py
│   │   ├── wazuh_collector.py
│   │   ├── nmap_collector.py
│   │   └── trivy_collector.py
│   ├── scoring/engine.py      # 점수 계산 엔진 (구현 완료)
│   └── scripts/seed_checklist.py # 체크리스트 DB 적재
├── nmap-wrapper/app.py        # Nmap CLI 래퍼 (Flask)
├── trivy-wrapper/app.py       # Trivy CLI 래퍼 (Flask)
└── docker-compose.yml         # 전체 서비스 통합

DB 테이블 (10개)
Organization, User, DiagnosisSession, Checklist, CollectedData, Evidence, DiagnosisResult, MaturityScore, ImprovementGuide, ScoreHistory

API 엔드포인트
POST /api/assessment/run : 진단 실행

POST /api/assessment/webhook : Shuffle 결과 수신

GET  /api/assessment/result : 결과 조회

GET  /api/assessment/history : 이력 조회

GET  /api/score/summary : 점수 요약

GET  /api/score/trend : 점수 추세

POST /api/manual/submit : 수동 항목 제출

GET  /api/checklist : 체크리스트 목록

GET  /api/improvement : 개선 권고

GET  /api/report/generate : 리포트 생성

수집 결과 공통 포맷
{
"item_id": "str",
"maturity": "str",
"tool": "str",
"result": "str",
"metric_key": "str",
"metric_value": 0.0,
"threshold": 0.0,
"raw_json": {},
"collected_at": "str",
"error": "str | null"
}

인프라 정보
포트 배분

8080: 프론트엔드 (Nginx)

8000: 백엔드 (FastAPI)

3000: Shuffle UI

8443: Keycloak / 9200: Elasticsearch / 55000: Wazuh API

8001: Nmap 래퍼 (호스트 8001 → 컨테이너 5000)
8002: Trivy 래퍼 (호스트 8002 → 컨테이너 5001)
3306: MySQL

서버 사양

OS: Ubuntu 24.04

Spec: t3a.xlarge (4vCPU / 16GB)

배포: ./deploy.sh <EC2_IP> (IP는 EC2 재시작마다 변경됨)

브랜치 전략
main: 최종 배포본 (직접 push 금지)

dev: 통합 테스트 브랜치

feature/backend-skeleton: 서진우

feature/keycloak-collector: 공나영

feature/wazuh-collector: 서정우

feature/nmap-trivy-wrapper: 송민희

주의사항
모든 민감 정보는 .env에서 읽을 것 (하드코딩 금지)

frontend 작업자는 backend 수정 금지, backend 작업자는 frontend 수정 금지

각 collector 반환 포맷은 위 공통 포맷 반드시 준수

mockData.ts 삭제 금지 (API 실패 시 fallback용)

작업 완료 후 반드시 자기 feature 브랜치에 push

────────────────────────────────────────────────────────────────────────────
최종 운영 모델 — 사용자가 자기 진단 대상을 어떻게 진단하는가
────────────────────────────────────────────────────────────────────────────

핵심 원칙
- 고객 시스템에 우리 코드를 설치하지 않는다. agent/sidecar/git clone 모두 금지.
- 모든 진단은 우리 EC2(원격/cloud) 에서 outbound 호출 또는 외부 스캔으로 수행.
- 가이드라인은 도구 무관(통제 요건 평가)이며, Keycloak/Wazuh 종속은 우리 1차 구현 선택일 뿐.
  → Step 0 프로파일링으로 사용 환경을 받아 미지원 도구 항목은 수동 진단으로 폴백.

진단 흐름 (Step 0 ~ Step 4)

Step 0 — 사전 환경 프로파일링 (NewAssessment 최상단 카드)
- 사용 IdP 선택: Keycloak / MS Entra ID / Okta / 자체 LDAP·AD / 사용 안 함·기타
- 사용 SIEM 선택: Wazuh / Splunk / Elastic SIEM / 사용 안 함·기타
- 외부 자동 스캔 toggle: Nmap / Trivy (도구 무관)
- 데모 모드 ↔ 실 스캔 모드 토글 (기본 데모, 시연 안전)

Step 1 — 기관 정보 (auth profile에서 prefill)

Step 2 — 진단 범위 선택 (6 Pillar)

Step 3 — 도구별 자격 입력 (실 스캔 모드 + 지원 도구 선택 시만 활성)
- Keycloak: URL + admin user + admin pass
- MS Entra ID: tenant_id + client_id + client_secret (Graph API)
- Wazuh: URL + api user + api pass
- Nmap target: IPv4/CIDR/도메인 (정규식 검증, shell metachar 차단)
- Trivy image: 컨테이너 이미지 참조 (정규식 검증)

Step 4 — 외부 스캔 동의 체크박스 (실 스캔 + scan_targets 있을 때만 필수)

POST /api/assessment/run (X-Login-Id 헤더 필수)
- body validators.py 통과 (URL/이미지/도메인/자격 길이 검증)
- session.extra 에는 URL/사용자명만 저장 (비밀번호는 메모리 dict로만 전달)
- BackgroundTasks → _run_collectors → 평가 → /finalize → 채점

InProgress 페이지 — 250ms 폴링, backend collected_count/auto_total 기반 동적 ETA

backend _run_collectors 동작
1. 메모리 dict 에서 자격 비밀번호 pop (사용 후 즉시 폐기)
2. _resolve_supported_tools(profile_select, tool_scope) — 사용자 환경 미지원 도구 자동 비활성
3. 활성 도구별 set_session_target/creds → collector 모듈 전역 주입
4. _collector_lock 으로 직렬화 (동시 진단 시 자격 충돌 방지)
5. 도구 가용성(_tool_health) 통과 시 호출. 불가 시 매핑된 모든 item_id 를 "평가불가" 처리

Reporting / Report PDF — X-Login-Id + assert_session_access 권한 검증.
결과 페이지 상단에 출처 배지: 자동 외부 스캔(녹) / 자동 API(녹) / 수동(노) / 미진단(빨).

────────────────────────────────────────────────────────────────────────────
지원 도구 매트릭스 (2026-05 기준)
────────────────────────────────────────────────────────────────────────────

IdP
- Keycloak    : ✅ 65개 자동 (1차 구현)
- MS Entra ID : ✅ 20개 자동 (Phase 2). 나머지는 수동 폴백
- Okta        : ⏳ 자동 미지원 → 100% 수동 폴백
- 자체 LDAP/AD: ⏳ 자동 미지원 → 100% 수동 폴백
- 기타        : 100% 수동 폴백

SIEM
- Wazuh   : ✅ 122개 자동
- Splunk  : ⏳ 미지원 → 수동 폴백
- Elastic : ⏳ 미지원 → 수동 폴백
- 기타    : 100% 수동 폴백

도구 무관 (항상 가능)
- Nmap (외부 IP/포트 스캔)
- Trivy (컨테이너 이미지 스캔)

────────────────────────────────────────────────────────────────────────────
보안·운영 정책
────────────────────────────────────────────────────────────────────────────

인증
- 비밀번호: PBKDF2-SHA256 600,000 라운드 (OWASP 2023)
- 정책: 8자 이상 + 영문+숫자 (RegisterRequest/ChangePasswordRequest validator)
- Lazy upgrade: 로그인 성공 시 저장 라운드 < 600k 면 자동 재해싱
- 로그인 실패: 5회 후 60초 잠금 (HTTP 423 + Retry-After)
- 시드 비번(admin/admin, user1/user1) 사용 시 Dashboard 노란 배너로 변경 유도

권한
- 모든 보호 엔드포인트: X-Login-Id 헤더 검증 (apiFetch 자동 첨부)
- 세션 접근: 본인 또는 자기 조직만. admin role은 전체 허용
- /history: 일반 user 는 자기 조직 세션으로 강제 필터
- /run: 본인 조직 외 진단 실행 차단 (admin 제외)
- 신규 가입 시 시드/관리 조직 이름 자동 join 차단 (_PROTECTED_ORG_NAMES)
- 개인 조직 이름은 "{login_id}_개인" 유일 키

자격 비밀번호
- DB 평문 저장 금지. session.extra 에는 URL/사용자명만.
- 비번은 _store_session_secrets / _pop_session_secrets 메모리 dict 로만 전달.
- _run_collectors 가 사용 후 즉시 폐기 (서버 재시작 시 자격 손실 → 재실행 필요).
- API 응답 마스킹: _mask_creds 가 admin_pass/api_pass/client_secret → "***".
- 로깅 채널에 자격을 절대 포함하지 말 것.

웹훅 / Internal API
- INTERNAL_API_TOKEN 미설정 시 webhook 503 (fail-closed).
- 로컬 개발 우회: ZTA_DEV_ALLOW_UNAUTH_WEBHOOK=true (운영 금지).

입력 검증 (backend/routers/validators.py)
- validate_nmap_target: IPv4/CIDR/도메인. shell metachar 차단.
- validate_trivy_image: 컨테이너 참조 형식. 공백/메타문자 차단.
- validate_https_url: scheme + host 검증.
- validate_cred_field: 길이 + strip.
- validate_entra_tenant_id: UUID 또는 도메인 형식.

감사 로그
- 별도 logger 채널 "zt.audit" (콘솔 출력, 운영 시 별도 핸들러로 SIEM 라우팅 가능)
- 기록 이벤트: register / login(성공·실패·잠금) / profile update / change-password /
  cleanup_old_sessions / collector session 자격 주입 실패

데이터 보관 정책
- DiagnosisSession 90일 자동 삭제 (ZTA_SESSION_RETENTION_DAYS=90)
- backend/main.py lifespan task 가 24시간 주기로 cleanup_old_sessions 실행
- 시드 데이터 보호: ZTA_PROTECT_DEMO_DATA=true (기본). _PROTECTED_ORG_NAMES 세션 보존
- 비활성: ZTA_CLEANUP_DISABLE=true
- 스탠드얼론: python backend/scripts/cleanup_old_sessions.py [--days N] [--dry-run]

────────────────────────────────────────────────────────────────────────────
API 계약 변경 사항 (1차 구현 이후)
────────────────────────────────────────────────────────────────────────────

신규 / 변경된 엔드포인트
- GET  /api/auth/me               : X-Login-Id 헤더 (query param 폐기)
- PUT  /api/auth/profile          : X-Login-Id 헤더 + body { current_password, profile }
- POST /api/auth/change-password  : X-Login-Id 헤더 + body { current_password, new_password }
- POST /api/assessment/run        : body 확장
    profile_select : { idp_type, siem_type }    ← Step 0
    scan_targets   : { nmap, trivy }
    keycloak_creds : { url, admin_user, admin_pass }
    wazuh_creds    : { url, api_user, api_pass }
    entra_creds    : { tenant_id, client_id, client_secret }
- 모든 보호 엔드포인트: X-Login-Id 헤더 필수. 누락 시 401.

frontend
- src/config/api.ts: apiFetch 가 register/login 외 모든 호출에 X-Login-Id 자동 첨부.
- src/types/api.ts: KeycloakCreds, WazuhCreds, EntraCreds, ScanTargets, ProfileSelect 추가.

────────────────────────────────────────────────────────────────────────────
다음 사이클 로드맵
────────────────────────────────────────────────────────────────────────────

Phase 2 (현재): Step 0 폴백 + Entra ID 핵심 항목 + 90일 보관
Phase 3 (다음):
  - Okta / Splunk REST 자동 collector 추가
  - audit log DB 테이블화 (현재는 stdlib logger)
  - login IP별 rate limiting (현재는 login_id 기준)
  - /run 호출 throttling (사용자당 분당 N회)
  - 비밀번호 재설정 이메일 토큰 흐름
Phase 4 (장기):
  - 자가 진단 증적 업로드 표준화 + 자동 채점 보조
  - QRadar / ArcSight / 자체 LDAP 자동 collector
  - 2FA / WebAuthn

────────────────────────────────────────────────────────────────────────────
환경변수 가이드 (.env.example 참조)
────────────────────────────────────────────────────────────────────────────

필수 (운영)
- INTERNAL_API_TOKEN          : Shuffle webhook 검증. 32+ char.
- DB_PASSWORD                 : MySQL.
- CORS_ORIGINS                : 명시적 도메인 콤마 구분. wildcard 금지.

도구 fallback (사용자 입력 없을 때 적용)
- KEYCLOAK_URL / KEYCLOAK_ADMIN / KEYCLOAK_ADMIN_PASSWORD
- WAZUH_URL / WAZUH_USER / WAZUH_PASSWORD
- ENTRA_TENANT_ID / ENTRA_CLIENT_ID / ENTRA_CLIENT_SECRET
- NMAP_TARGET / TRIVY_TARGET

운영 토글
- ZTA_SESSION_RETENTION_DAYS=90        : 세션 보관 일수
- ZTA_PROTECT_DEMO_DATA=true           : 시드 보존
- ZTA_CLEANUP_DISABLE=                 : 자동 삭제 비활성
- ZTA_CLEANUP_INTERVAL_HOURS=24
- ZTA_CLEANUP_FIRST_DELAY_SEC=30
- ZTA_DEV_ALLOW_UNAUTH_WEBHOOK=        : dev 한정 webhook 우회
- ZTA_FORCE_REAL_COLLECTION=           : placeholder 가드 우회 (비권장)
