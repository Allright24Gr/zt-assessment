# STATUS — Readyz-T ZT Assessment Platform

> 작성: 2026-05-17 / 기준 브랜치: `dev`
> 본 문서는 **처음 보는 사람이 5분 안에 전체 그림을 잡을 수 있도록** 디렉토리 트리 → 파일별 1~2줄 기능 → 데이터 흐름 다이어그램 순서로 작성. 운영 정책은 `CLAUDE.md`, 작업 로드맵은 `PLAN.md` 참조.

---

## 1. 한눈에

```
사용자 → Frontend(React) → Backend(FastAPI) → MySQL
                          ↓ (옵션) Shuffle SOAR
                          ↓
                  14개 도구 collector → 외부 시스템(IdP/SIEM/EDR/Cloud Posture/ZTNA + Nmap/Trivy 외부 스캔)
```

- 진단 기준: **제로트러스트 가이드라인 2.0** — 6 Pillar(신원/기기/네트워크/시스템/애플리케이션/데이터) × 4 성숙도(기존/초기/향상/최적화)
- 자동 진단 항목: **243 base + 114 autodiscover = 357** (14 도구, xlsx 자동 212항목과 1:1 정합 검증 완료)
- 매핑 학술 검증: `python /app/scripts/validate_checklist_mapping.py` 결과 — 자동 212 ↔ 매핑 212, 누락 0, 잘못 0, 충돌 0, 다중 매핑(의도된 카테고리 다중) 54건
- 사용자 흐름: 회원가입 → 로그인(JWT) → NewAssessment(Step 0 환경 프로파일링 → 자격 입력) → 진단 실행 → InProgress(점진 진행률) → Reporting(점수·신뢰도·맞춤 권고·PDF·공유) → History(이력·비교·삭제)

---

## 2. 디렉토리 트리 + 파일별 기능

```
zt-assessment/
├── CLAUDE.md                         # 프로젝트 가이드 + 최종 운영 계획·정책 (574줄)
├── STATUS.md                         # 본 문서. 현재 상태 스냅샷
├── PLAN.md                           # Done/TODO 로드맵
├── DEPLOY.md                         # 운영 배포 8단계 가이드
├── README.md
├── deploy.sh                         # EC2 배포 단축 스크립트
├── docker-compose.yml                # 11개 서비스 통합 (Shuffle profile 분리)
├── docker-compose.prod.yml           # 운영 override (nginx + 외부 포트 보호)
├── .env / .env.example               # 운영 환경변수 (.env는 git X)
│
├── nginx/                            # 운영 reverse proxy
│   ├── nginx.conf                    # 80→443, /api 라우팅, 보안 헤더
│   └── certs/                        # SSL 인증서 (gitignore)
│
├── scripts/                          # 호스트 스크립트
│   ├── bootstrap.sh                  # ★ EC2 한 줄 셋업 자동화 (swarm + 컨테이너 + Shuffle + 워크플로우 import + .env 자동 발급)
│   ├── e2e_smoke.sh                  # 10단계 자동 검증 (가입→탈퇴)
│   ├── shuffle_export.sh             # zt-* 워크플로우 JSON 백업
│   └── shuffle_import.sh             # 새 환경에 워크플로우 자동 복원 + .env 자동 갱신
│
├── shuffle/workflows/                # zt-* 7개 워크플로우 JSON 백업 (EC2 fresh start 복원용)
│
├── backend/                          # FastAPI 백엔드 (Python 3.11)
│   ├── Dockerfile / entrypoint.sh    # 부팅 시 migrate_schema + seed_checklist/improvement/demo 자동
│   ├── requirements.txt              # fastapi/sqlalchemy/pydantic/PyJWT/boto3/Jinja2/ldap3 등
│   ├── init.sql                      # DB 초기 스키마 (보조)
│   │
│   ├── main.py                       # FastAPI 진입점 + lifespan task(90일 cleanup) + JWT logger 셋업
│   ├── database.py                   # SQLAlchemy 세션·엔진
│   ├── models.py                     # 12개 테이블 SQLAlchemy 모델
│   │
│   ├── routers/                      # 8개 API 모듈
│   │   ├── auth.py                   (820줄) 회원가입/로그인/JWT/me/profile/change-password/비번재설정/회원탈퇴
│   │   │                              JWT(access 8h/refresh 30d) + IP 잠금 + audit DB + 비번 정책 + 시드 조직 차단
│   │   ├── assessment.py             (2566줄) 진단 실행/상태/결과/이력/finalize/webhook/internal collect
│   │   │                              /compare /share/{id} /shared/{token} /session/{id}(DELETE)
│   │   │                              10 도구 dispatcher + 점진적 진행률 + 자격 메모리 dict + IDOR 차단
│   │   ├── score.py                  (122줄) 점수 요약/추세/체크리스트 점수
│   │   ├── improvement.py            (154줄) 개선 가이드 — session profile_select 기반 권고 자동 맞춤
│   │   ├── report.py                 (477줄) JSON·PDF 보고서 (NanumGothic, 권한 검증)
│   │   ├── manual.py                 (562줄) 수동 항목 제출/Excel 업로드/증적 파일 업로드·다운로드
│   │   ├── checklist.py              (45줄)  체크리스트 목록 (공개)
│   │   └── validators.py             (198줄) 입력 검증 (Nmap/Trivy/URL/자격/Entra GUID/Okta/LDAP DN)
│   │
│   ├── scoring/
│   │   └── engine.py                 (159줄) 점수 산정 엔진 (평가불가 분모 제외 + 가중 평균 + 신뢰도)
│   │
│   ├── services/                     # 외부 서비스 통합
│   │   ├── email_sender.py           (129줄) AWS SES + Jinja2 + DRY_RUN 모드
│   │   ├── improvement_customizer.py (166줄) ★ session profile_select 기반 권고 task 자동 치환
│   │   └── email_templates/          # password_reset / account_deleted / assessment_complete (txt+html)
│   │
│   ├── collectors/                   # 14 도구 자동 수집기 (★는 최신 추가)
│   │   ├── keycloak_collector.py     (1427줄) 65 함수, IdP — Keycloak admin REST API
│   │   ├── wazuh_collector.py        (2930줄) 122 함수, SIEM/HIDS — Wazuh API + Indexer
│   │   ├── entra_collector.py        (570줄)  20 함수, IdP — Microsoft Graph (OAuth client_credentials)
│   │   ├── okta_collector.py         (452줄)  15 함수, IdP — Okta REST API (SSWS token)
│   │   ├── splunk_collector.py       (425줄)  15 함수, SIEM — Splunk REST (Basic auth + search/jobs/export)
│   │   ├── ldap_collector.py         (595줄)  15 함수, IdP — ldap3 simple bind, AD/OpenLDAP 듀얼
│   │   ├── crowdstrike_collector.py  (422줄)  15 함수, EDR — Falcon API (OAuth client_credentials)
│   │   ├── defender_collector.py     (401줄)  15 함수, EDR — Defender for Endpoint (Entra OAuth)
│   │   ├── aws_security_hub_collector.py ★    15 함수, 클라우드 자세 — AWS Security Hub findings + boto3
│   │   ├── azure_defender_cloud_collector.py ★ 15 함수, 클라우드 자세 — Defender for Cloud (ARM REST)
│   │   ├── zscaler_collector.py ★             10 함수, ZTNA — Zscaler Internet/Private Access API
│   │   ├── cloudflare_access_collector.py ★   10 함수, ZTNA — Cloudflare Zero Trust API
│   │   ├── nmap_collector.py         (308줄)  14 함수, 외부 스캔 — nmap-wrapper Flask 호출
│   │   └── trivy_collector.py        (257줄)  11 함수, 이미지 스캔 — trivy-wrapper Flask 호출
│   │
│   ├── scripts/                      # backend 내부 운영 스크립트 (docker exec)
│   │   ├── seed_checklist.py         # zt-checklist.xlsx → Checklist 테이블
│   │   ├── seed_improvement.py       # zt-improvement-guide.xlsx → ImprovementGuide 테이블
│   │   ├── seed_demo.py              # (구) 시드 — 호환용
│   │   ├── seed_demo_examples.py     # admin/user1 + 데모 세션 시드 (390줄, idempotent + 부분손상 가드)
│   │   ├── migrate_schema.py         # 멱등 스키마 ALTER + 신규 테이블 CREATE
│   │   ├── cleanup_old_sessions.py   # 90일 자동 삭제 (lifespan 자동 호출)
│   │   └── validate_checklist_mapping.py ★ xlsx ↔ _full_mapping 학술 검증 (누락/잘못/충돌/다중 분석)
│   │
│   ├── tests/                        # pytest 자동 테스트 (66 케이스, sqlite in-memory)
│   │   ├── conftest.py               # fixture (db_session / client / make_user / auth_headers)
│   │   ├── test_auth_basic.py        # 15 cases — register/login/refresh/delete
│   │   ├── test_idor.py              # 10 cases — multi-tenant 격리 회귀 차단
│   │   ├── test_collector_mapping.py # 14 cases — 10 도구 매핑 정합성
│   │   ├── test_resolve_tools.py     # 6 cases — profile_select 폴백
│   │   ├── test_validators.py        # 17 cases — shell metachar 차단
│   │   └── test_cleanup.py           # 4 cases — 90일 retention + 시드 보호
│   │
│   ├── manual-checklist.xlsx         # 수동 진단 양식 (사용자 다운로드용)
│   ├── zt-checklist.xlsx             # 310행 진단 항목 원본 (seed_checklist 입력)
│   └── zt-improvement-guide.xlsx     # 개선 가이드 원본 (seed_improvement 입력)
│
├── frontend/                         # React 18 + TS + Vite + shadcn/ui + Tailwind
│   ├── Dockerfile / nginx.conf
│   ├── vite.config.ts
│   ├── package.json / pnpm-lock.yaml
│   │
│   └── src/
│       ├── main.tsx                  # 진입점
│       ├── config/api.ts             # apiFetch (JWT Bearer 자동 첨부 + 401 refresh 재시도) + 모든 API 함수
│       ├── types/api.ts              # 232줄+ 백엔드 응답·요청 TS 타입 (10 도구 자격/profile_select 등)
│       │
│       └── app/
│           ├── App.tsx / routes.tsx  # 라우팅 (보호/공개 분리)
│           │
│           ├── context/
│           │   └── AuthContext.tsx   # 117줄. user/tokens 보관, login/register/logout, refresh
│           │
│           ├── data/
│           │   ├── mockData.ts       # API 실패 시 fallback (삭제 금지)
│           │   ├── checklistItems.ts # 정적 체크리스트 캐시
│           │   ├── constants.ts      # 6 Pillar 라벨/색상
│           │   └── legalText.ts      # 이용약관·개인정보 처리방침·마케팅 본문 (Signup 모달)
│           │
│           ├── lib/
│           │   ├── maturity.ts       # 백엔드 enum "기존" → UI 라벨 "근간" 매핑
│           │   └── pillar.ts         # Pillar 한↔영 키 변환
│           │
│           ├── pages/
│           │   ├── Login.tsx                (267줄) 로그인 + 데모 모달 + 시드 비번 감지 + 비번찾기 링크
│           │   ├── Signup.tsx               (362줄) 회원가입 + 약관 3종 체크박스 + 전문 모달
│           │   ├── PasswordResetRequest.tsx (118줄) /auth/request-password-reset 페이지
│           │   ├── PasswordResetConfirm.tsx (162줄) /auth/reset-password?token= 페이지
│           │   ├── Dashboard.tsx            (476줄) 점수 카드/추이/시드 비번 노란 배너
│           │   ├── NewAssessment.tsx        (1420줄) Step 0 사전 프로파일링 → 자격 → 진단 시작
│           │   ├── InProgress.tsx           (826줄) 동적 ETA + 수동 업로드 병행 + 증적 파일
│           │   ├── Reporting.tsx            (1396줄) 점수·신뢰도·출처 배지·맞춤 권고·PDF·공유
│           │   ├── History.tsx              (515줄) 세션 이력 + 비교 모드 + 행별 삭제 모달
│           │   ├── Compare.tsx              (308줄) 진단 비교 (improved/regressed/unchanged)
│           │   ├── Settings.tsx             (1019줄) 진단 프로필 수정 + 비번 변경 + 회원 탈퇴
│           │   └── SharedResult.tsx         (217줄) /shared/{token} 익명 공유 결과
│           │
│           └── components/
│               ├── RootLayout.tsx
│               ├── figma/ImageWithFallback.tsx
│               └── ui/               # shadcn/ui 50+ 컴포넌트
│
├── nmap-wrapper/                     # Nmap CLI 래퍼 (Flask, 8001)
│   └── app.py                        (412줄) /scan/ports /scan/subnets /scan/tls
│
└── trivy-wrapper/                    # Trivy CLI 래퍼 (Flask, 8002)
    └── app.py                        (394줄) /scan/image /scan/fs /scan/sbom
```

**규모**: backend ~13,400줄, frontend src ~10,500줄, 합계 ~24,000줄.

---

## 3. DB 테이블 (12개)

| 테이블 | 핵심 컬럼 | 목적 |
|---|---|---|
| `Organization` | org_id, name, industry, size, cloud_type | 기관 정보 |
| `User` | user_id, org_id FK, login_id UK, password_hash, role, profile JSON, tos_agreed_at, privacy_agreed_at | 사용자 + 약관 동의 시점 |
| `DiagnosisSession` | session_id, org_id FK, user_id FK, status, started_at, selected_tools JSON, extra JSON, total_score, level | 진단 세션 (extra에 profile_select·scan_targets·creds URL/user) |
| `Checklist` | check_id, item_id UK, pillar, category, item_name, maturity, maturity_score, diagnosis_type, tool | 진단 항목 (xlsx 시드) |
| `CollectedData` | data_id, session_id FK, check_id FK, tool, metric_key, metric_value, threshold, raw_json, error | 도구 수집 raw 데이터 |
| `Evidence` | evidence_id, session_id FK, check_id FK, source, observed, file_path, mime_type, file_size | 증적 (텍스트 + 파일 업로드) |
| `DiagnosisResult` | result_id, session_id FK, check_id FK, result, score, recommendation | 항목별 채점 결과 |
| `MaturityScore` | score_id, session_id FK, pillar, score, level, pass_cnt/fail_cnt/na_cnt | Pillar별 점수 (level="평가불가" 가능) |
| `ImprovementGuide` | guide_id, check_id FK?, pillar, current_level, next_level, recommended_tool, task, priority, term | 개선 가이드 (xlsx 시드) |
| `ScoreHistory` | history_id, session_id FK, org_id FK, total_score, maturity_level, pillar_scores JSON | 점수 추이 |
| `AuthAuditLog` | audit_id, event_type, user_id FK?, login_id, source_ip, user_agent, success, detail JSON | auth 이벤트 영속화 |
| `PasswordResetToken` | token_id, user_id FK, token_hash, expires_at, used_at | 비번 재설정 토큰 (해시만) |
| `SharedResult` | share_id, session_id FK, token_hash, created_by_user_id FK, expires_at, revoked_at | 공유 결과 토큰 |

---

## 4. 데이터 흐름

### 4-1. 신규 사용자 진단 (end-to-end)

```
[1] 회원가입  Signup.tsx
              └ POST /api/auth/register {login_id, password, tos_agreed, privacy_agreed, profile}
                 ├ Pydantic field_validator (8자+영문+숫자)
                 ├ tos/privacy 미동의 → 400
                 ├ 시드 조직명 자동 join 차단 (_PROTECTED_ORG_NAMES)
                 ├ 개인조직 유일 키 "{login_id}_개인"
                 ├ PBKDF2-SHA256 600,000 라운드
                 ├ User + Organization 행 생성
                 ├ AuthAuditLog "register"
                 └ ↩ {user, tokens:{access_token, refresh_token, expires_in}}

[2] 로그인    Login.tsx
              └ POST /api/auth/login {login_id, password}
                 ├ _check_lock(login_id, source_ip) — login_id 5회 / IP 50회 윈도우
                 ├ _verify_password + 잠금 카운터
                 ├ password === login_id 감지 시 sessionStorage zt_seed_password_warning
                 ├ PBKDF2 lazy upgrade (저장 라운드 < 600k → 새 해시)
                 ├ AuthAuditLog "login_ok"
                 └ ↩ {user, tokens} → localStorage.zt_user / zt_tokens

[3] AuthContext useEffect
              └ GET /api/auth/me (Authorization: Bearer {access_token})
                 └ 백엔드 최신 user 정보 재동기화

[4] Dashboard 진입
              └ zt_seed_password_warning 있으면 노란 배너
                 [지금 변경] → /settings + state:{openPasswordModal:true}

[5] NewAssessment Step 0~4
              ├ Step 0 사전 프로파일링: idp_type/siem_type/edr_type + 데모↔실 스캔 토글
              ├ Step 1 기관 정보 (auth profile prefill)
              ├ Step 2 진단 범위 (6 Pillar)
              ├ Step 3 도구별 자격 (실 스캔 + 지원 도구 한정):
              │     Keycloak/Entra/Okta/LDAP/Wazuh/Splunk/Crowdstrike/Defender + Nmap host + Trivy image
              └ Step 4 외부 스캔 동의 체크박스

[6] POST /api/assessment/run  (Authorization: Bearer)
              ├ get_current_user — JWT 검증
              ├ validators.py 입력 검증 (URL/메타문자/이미지/DN/GUID)
              ├ 본인 조직 외 진단 차단 (admin 제외)
              ├ _resolve_supported_tools(profile_select, tool_scope) → 실행 도구 결정
              ├ session.extra ← URL/사용자명만 (비밀번호 제외)
              ├ _store_session_secrets ← 자격 메모리 dict (10 도구)
              └ BackgroundTasks → _run_collectors

[7] _run_collectors (단일 _collector_lock 직렬화)
              ├ _pop_session_secrets ← 메모리 dict pop + 즉시 삭제
              ├ 도구별 set_session_target / set_session_creds
              ├ _tool_health → placeholder/TCP probe
              │     · 미연결 + ZTA_DEMO_DELAY_MS>0 → 단건 commit + sleep (점진 진행률)
              │     · 미연결 + 0 → 매핑 모든 item_id 일괄 "평가불가"
              │     · 연결됨 → collector 호출 → CollectedData/DiagnosisResult upsert
              └ finally: set_session_creds(None) — 모듈 전역 자격 폐기

[8] InProgress 250ms 폴링
              └ GET /api/assessment/status/{id}
                 └ collected_count/auto_total/tool_progress/pillar_progress
                 frontend: 평균 속도로 동적 ETA (90s 고정 폐기)

[9] POST /api/assessment/finalize/{id}
              └ _trigger_scoring:
                 ├ scoring.engine.score_session:
                 │   - 평가불가 항목은 pillar 분모에서 제외 (B-2)
                 │   - pillar 점수 = Σ(maturity_score × weight) / Σ(maturity_score) × 4
                 │   - confidence = 평가가능 / 전체 (B-3 신뢰도)
                 │   - pillar_unevaluable 카운트
                 ├ MaturityScore 6 pillar (평가불가만 있는 pillar는 level="평가불가")
                 ├ ScoreHistory 1행
                 └ DiagnosisResult.recommendation

[10] Reporting GET /api/assessment/result?session_id=
              ├ assert_session_access — 본인/admin
              ├ extra._mask_creds — admin_pass/api_pass/client_secret/api_token → "***"
              └ checklist_results + pillar_scores + confidence

      GET /api/improvement/session/{id}
              ├ session.extra.profile_select 추출
              └ improvement_customizer.customize_guide(guide, profile_select)
                 → 권고 task에 "— 사용자 환경(Keycloak/Entra/Okta/LDAP) 가이드: ..." 자동 첨부

[11] PDF 다운로드 GET /api/report/generate?session_id=&fmt=pdf
              └ frontend fetch + blob (Authorization Bearer 첨부)
                 backend: NanumGothic + reportlab

[12] 공유 POST /api/assessment/share/{id} → 토큰
      익명 GET /api/assessment/shared/{token} (인증 불필요)

[13] 삭제 DELETE /api/assessment/session/{id}
              ├ assert_session_access
              ├ _pop_session_secrets — 메모리 자격 폐기
              ├ 자식 5개 테이블 + SharedResult cascade
              └ DiagnosisSession 삭제
```

### 4-2. 인증·세션 흐름 (JWT)

```
브라우저 localStorage["zt_user"]    = { login_id, name, role, ... }
        localStorage["zt_tokens"]   = { access_token, refresh_token, expires_in }
            │
            ▼ frontend apiFetch
            ├ PUBLIC_ENDPOINTS(register/login/shared/*)이 아니면 Authorization: Bearer 자동 첨부
            ├ 401 응답 시: refresh_token으로 /api/auth/refresh → 새 토큰 → 원 요청 재시도 (한 번만)
            │
            ▼ HTTP Authorization: Bearer {access_token}
backend get_current_user 의존성
            ├ Bearer 우선 → PyJWT 검증 (HS256, kind="access")
            ├ X-Login-Id 헤더 fallback (호환성)
            └ User 행 조회 → 의존성 주입
            │
            ▼
보호 엔드포인트
            ├ assert_session_access(user, session) — 본인/조직/admin
            └ assert_org_access(user, org_id)
```

### 4-3. 자격 비밀번호 흐름

```
NewAssessment submit
   │
   ▼ POST /api/assessment/run body
     {keycloak_creds, wazuh_creds, entra_creds, okta_creds, splunk_creds, ldap_creds, crowdstrike_creds, defender_creds}
   │
   ▼ run_assessment
     ├ validators 검증
     ├ session.extra ← URL/user/tenant_id만 저장 (비밀번호 평문 DB 저장 0)
     └ _store_session_secrets(session_id, kc, wz, en, ok, sp, ldap, cs, df) → 메모리 dict + Lock
                                                                  │
                                                                  ▼ BackgroundTask
                                _run_collectors(session_id, tools)
                                ├ _pop_session_secrets(session_id) — 메모리에서 꺼내고 삭제
                                ├ set_session_creds(creds) — 각 collector 모듈 전역
                                ├ collector 호출 (httpx/ldap3)
                                └ finally: set_session_creds(None) 즉시 폐기
```

**서버 재시작 시 자격 손실** → 사용자가 재실행. 트레이드오프 — DB 평문 저장보다 훨씬 안전.

### 4-4. 90일 자동 삭제

```
backend/main.py 부팅
   │
   ▼ FastAPI lifespan
asyncio.create_task(_periodic_cleanup)
   ├ 30초 후 첫 실행 (ZTA_CLEANUP_FIRST_DELAY_SEC)
   └ 매 24시간 반복 (ZTA_CLEANUP_INTERVAL_HOURS)
      │
      ▼
   cleanup_old_sessions(days=90)
   ├ DiagnosisSession.started_at < now-90d 조회
   ├ ZTA_PROTECT_DEMO_DATA=true 시 시드 조직(_DEMO_ORG_NAMES) 세션 제외
   ├ 자식 5개 테이블(CollectedData/Evidence/DiagnosisResult/MaturityScore/ScoreHistory) cascade
   ├ DiagnosisSession 삭제
   └ zt.audit "[cleanup] cutoff=... checked=... deleted=..." 로그
```

### 4-5. 개선 권고 사용자 환경 맞춤 (B-4)

```
GET /api/improvement/session/{id}
   │
   ▼ session.extra.profile_select 추출 {idp_type, siem_type, edr_type}
   │
   ▼ ImprovementGuide row 조회
   │
   ▼ improvement_customizer.customize_guide(guide, profile_select)
      ├ IDP_PROFILES[idp_type] / SIEM_PROFILES[siem_type] / EDR_PROFILES[edr_type] 룩업
      ├ guide.task 안의 키워드 매칭 (MFA/조건부/세션/RBAC/비번/알람/탐지/격리/취약점 등)
      │     → 환경별 가이드 문장 자동 첨부
      ├ recommended_tool 가 비어있거나 "idp"/"iam" 이면 환경 라벨로 치환
      │     (예: "Keycloak", "MS Entra ID", "Okta", "자체 LDAP/AD")
      └ 원본 변경 안 함 — 응답 dict 만 변환 (회귀 0)
   │
   ▼ Reporting.tsx 권고 카드
      task 줄바꿈 + "— 사용자 환경(X) 가이드:" 부분을 파싱해 별도 블록 + 배지로 렌더
```

---

## 5. 자동 진단 매핑 (14개 도구, xlsx 자동 212항목과 1:1 정합)

| 도구 | base | autodiscover | 합계 | 카테고리 | 인증 방식 |
|---|---|---|---|---|---|
| keycloak | 32 | 33 | **65** | IdP | admin REST API token |
| entra | 20 | 0 | **20** | IdP | OAuth client_credentials → Graph |
| okta | 15 | 0 | **15** | IdP | SSWS API token |
| ldap | 15 | 0 | **15** | IdP | ldap3 simple bind (AD/OpenLDAP) |
| wazuh | 41 | 81 | **122** | SIEM/HIDS | API user/pass → JWT |
| splunk | 15 | 0 | **15** | SIEM | Basic Auth → search/jobs/export |
| crowdstrike | 15 | 0 | **15** | EDR | OAuth client_credentials |
| defender | 15 | 0 | **15** | EDR | Entra OAuth scope=securitycenter |
| **aws_securityhub** | 15 | 0 | **15** | 클라우드 자세 | boto3 (IAM Access Key) |
| **azure_defender** | 15 | 0 | **15** | 클라우드 자세 | Entra OAuth → ARM REST |
| **zscaler** | 10 | 0 | **10** | ZTNA | API key |
| **cloudflare_access** | 10 | 0 | **10** | ZTNA | API token |
| nmap | 14 | 0 | **14** | 외부 스캔 | (도구 무관) |
| trivy | 11 | 0 | **11** | 이미지 스캔 | (도구 무관) |
| **합계** | **243** | **114** | **357** | | |

> 학술 검증(2026-05-17): xlsx 자동 진단 212개 = 우리 매핑 unique item_id 212개. 잘못된 매핑 0건, 수동 충돌 0건. 함수 호출 총 357회는 IdP 4종/SIEM 2종/EDR 2종/Cloud 2종/ZTNA 2종이 같은 item_id를 다른 도구로도 측정할 수 있도록 의도된 다중 매핑(54개 item_id) 때문이다.

Step 0 프로파일링 사용자 선택 → `_resolve_supported_tools` 가 그 환경의 도구만 활성:
- idp_type=`keycloak` → keycloak만, entra/okta/ldap 비활성
- siem_type=`wazuh` → wazuh만, splunk 비활성
- edr_type=`crowdstrike` → crowdstrike만, defender 비활성
- cloud_type=`aws_securityhub` → aws만, azure 비활성
- ztna_type=`zscaler` → zscaler만, cloudflare 비활성
- 미선택/`none` → 해당 카테고리 자동 도구 전부 비활성 (수동 폴백)

---

## 6. API 엔드포인트 (인증·권한 매트릭스)

| Method · Path | 인증 | 권한 |
|---|---|---|
| `POST /api/auth/register` | ✗ | 누구나 (약관 동의 필수) |
| `POST /api/auth/login` | ✗ | 누구나 (5회/IP 50회 잠금) |
| `POST /api/auth/refresh` | refresh_token | 토큰 자체 검증 |
| `GET /api/auth/me` | Bearer / X-Login-Id | 본인 |
| `PUT /api/auth/profile` | Bearer + current_password | 본인 |
| `POST /api/auth/change-password` | Bearer + current_password | 본인 |
| `POST /api/auth/request-password-reset` | ✗ | 누구나 (enumeration 방지 동일 응답) |
| `POST /api/auth/reset-password` | token | 토큰 자체 |
| `DELETE /api/auth/me` | Bearer + current_password | 본인 (cascade) |
| `POST /api/assessment/run` | Bearer | 본인 조직만 (admin 전체) |
| `GET /api/assessment/status/{id}` | Bearer | session 권한 |
| `POST /api/assessment/finalize/{id}` | Bearer | session 권한 |
| `GET /api/assessment/result?session_id=` | Bearer | session 권한 (_mask_creds) |
| `GET /api/assessment/history` | Bearer | 자기 조직만 (admin 전체) |
| `GET /api/assessment/compare?from=&to=` | Bearer | 두 세션 모두 권한 |
| `POST /api/assessment/share/{id}` | Bearer | 본인/admin |
| `GET /api/assessment/shared/{token}` | ✗ | 토큰 자체 + 만료/취소 검사 |
| `DELETE /api/assessment/share/{share_id}` | Bearer | 발급자/admin |
| `DELETE /api/assessment/session/{id}` | Bearer | session 권한 (자식 cascade) |
| `POST /api/assessment/internal/collect/{tool}` | X-Internal-Token | Shuffle용 |
| `POST /api/assessment/webhook` | X-Internal-Token | Shuffle용 (fail-closed 503) |
| `GET /api/score/summary?session_id=` | Bearer | session 권한 |
| `GET /api/score/trend?org_id=` | Bearer | org 권한 |
| `GET /api/score/checklist/{id}` | Bearer | session 권한 |
| `GET /api/report/generate?session_id=&fmt=` | Bearer | session 권한 (json/pdf) |
| `GET /api/improvement/` | Bearer | 인증만 (정적 가이드) |
| `GET /api/improvement/session/{id}` | Bearer | session 권한 + 사용자 환경 맞춤 |
| `GET /api/improvement/{guide_id}` | Bearer | 인증만 |
| `POST /api/manual/upload` | Bearer | session 권한 (xlsx) |
| `POST /api/manual/submit` | Bearer | session 권한 |
| `POST /api/manual/upload-evidence` | Bearer | session 권한 (PDF/이미지 10MB) |
| `GET /api/manual/evidence/{id}` | Bearer | session 권한 |
| `GET /api/manual/template` | Bearer | 인증만 (xlsx) |
| `GET /api/manual/items/{id}` | Bearer | session 권한 + profile_select 폴백 |
| `GET /api/checklist` | ✗ | 공개 |
| `GET /health` | ✗ | 공개 |

---

## 7. 인프라 / 포트 / 컨테이너

| 포트 | 컨테이너 | 역할 |
|---|---|---|
| 8080 | zt-web (nginx) | Frontend |
| 8000 | zt-backend (uvicorn) | Backend API |
| 8001 | nmap-wrapper | Nmap CLI 래퍼 |
| 8002 | trivy-wrapper | Trivy CLI 래퍼 |
| 3306 | mysql | DB |
| 9201 | elasticsearch | (옵션) |
| 8443 | keycloak | (데모용, 운영 시 비노출) |
| 55000 | wazuh | (데모용) |
| 3001 | shuffle-frontend | Shuffle UI |
| 5001 | shuffle-backend | Shuffle API |
| 9200 | shuffle-database (opensearch) | 내부 |
| -    | shuffle-orborus | Worker 노드 spawn (docker.sock + swarm overlay) |

서버 사양: Ubuntu 24.04 / t3a.xlarge (4vCPU / 16GB). 배포: `./scripts/bootstrap.sh` 한 줄.

---

## 8. 환경변수 (.env 카테고리)

| 카테고리 | 키 | 비고 |
|---|---|---|
| 보안 | SECRET_KEY, INTERNAL_API_TOKEN, ZTA_JWT_ACCESS_HOURS=8, ZTA_JWT_REFRESH_DAYS=30, ZTA_LOGIN_IP_MAX=50 | bootstrap.sh 자동 발급 |
| DB | DB_HOST/PORT/NAME/USER/PASSWORD, MYSQL_ROOT_PASSWORD | bootstrap.sh 자동 발급 |
| CORS | CORS_ORIGINS | wildcard 금지 |
| Frontend | VITE_API_BASE, FRONTEND_BASE_URL | 빌드 시점에 박힘 |
| IdP fallback | KEYCLOAK_URL/ADMIN, ENTRA_TENANT_ID/CLIENT_ID/SECRET, OKTA_DOMAIN/API_TOKEN, LDAP_URL/BIND_DN/PASSWORD/BASE_DN | 사용자 입력 없을 때 |
| SIEM fallback | WAZUH_URL/USER/PASSWORD, SPLUNK_URL/USER/PASSWORD/TOKEN | |
| EDR fallback | CROWDSTRIKE_API_BASE/CLIENT_ID/SECRET, DEFENDER_TENANT_ID/CLIENT_ID/SECRET | |
| Nmap/Trivy | NMAP_WRAPPER_URL, TRIVY_WRAPPER_URL, NMAP_TARGET, TRIVY_TARGET | |
| Shuffle | SHUFFLE_URL, SHUFFLE_API_KEY, SHUFFLE_ADMIN_USER/PASS/EMAIL, SHUFFLE_WORKFLOW_* (10개) | bootstrap.sh 자동 |
| 이메일 | EMAIL_FROM, EMAIL_DRY_RUN, AWS_REGION/ACCESS_KEY_ID/SECRET_ACCESS_KEY | DRY_RUN=true 로컬 |
| 운영 토글 | ZTA_SESSION_RETENTION_DAYS=90, ZTA_PROTECT_DEMO_DATA=true, ZTA_CLEANUP_DISABLE, ZTA_DEMO_DELAY_MS, ZTA_FORCE_REAL_COLLECTION | |

---

## 9. 브랜치 / 시드 계정

브랜치
- `master` — 최종 배포본. dev fast-forward 또는 PR로만.
- `dev` — 통합 테스트. 모든 작업.
- feature/* — 1차 개발자별 (서진우/공나영/서정우/송민희)

시드 계정 (`docker compose exec zt-backend python scripts/seed_demo_examples.py [--force]`)
- `admin / admin` (role=admin, 시스템관리)
- `user1 / user1` (박기웅, 세종대학교 — 완료 3건 + 진행중 1건)
- 관리자 시점 예시 4건 (ABC 핀테크/XYZ 메디컬/국가데이터센터/스타트업 K)

> 시드 비번은 정책 위반(4자) — 로그인은 OK, 변경 시엔 새 비번 정책 검증. Dashboard에 "기본 비번 사용 중" 노란 배너로 변경 유도.

---

## 10. 자기 검증 (정적, 2026-05-17 기준)

```
✅ AST: backend 25 파일 + tests 8 파일 모두 통과
✅ _full_mapping() base 매핑:
     keycloak 32 + entra 20 + okta 15 + ldap 15 + wazuh 41 + splunk 15
     + crowdstrike 15 + defender 15 + aws_securityhub 15 + azure_defender 15
     + zscaler 10 + cloudflare_access 10 + nmap 14 + trivy 11 = 243
     (autodiscover 합산 357 / unique item_id 212)
✅ xlsx ↔ 매핑 학술 검증 (validate_checklist_mapping.py):
     xlsx 자동 212 = 매핑 unique 212 / 잘못된 매핑 0 / 수동 충돌 0 / 다중 매핑 54
✅ maturity 일관성: 14 도구 0건 불일치 (_validate_mapping 가드 적용)
✅ _resolve_supported_tools 5 카테고리(idp/siem/edr/cloud/ztna) 모든 조합 통과
✅ frontend npm run build 통과 (chunk-size 경고만, 변경 코드 무관)
✅ validators: shell metachar 차단 (Nmap target/Trivy image/URL/Entra GUID/Okta domain/LDAP URL+DN/AWS Access Key/AWS Region/Azure Subscription/CF Account ID)
✅ _mask_creds 14 도구 자격 비밀번호 모두 "***" 마스킹
✅ score_session 시뮬: 평가불가 분모 제외 동작 (5건 중 3 평가불가 + 2 충족 → 4.0 + confidence 40%)
✅ pytest 66 케이스 작성 (auth 15 / IDOR 10 / mapping 14 / resolve 6 / validators 17 / cleanup 4)
```

---

## 11. 알려진 한계 (PLAN.md P2/P3 참조)

| 한계 | 위치 | PLAN |
|---|---|---|
| _login_state in-memory (다중 인스턴스 불가) | auth.py | P2-14 Redis |
| Shuffle Orborus WSL swarm 환경에서 worker pickup 미검증 | docker-compose | 실 EC2 검증 |
| CI/CD GitHub Actions 없음 | — | P2-16 |
| Alembic DB 마이그레이션 없음 | — | P2-17 |
| Prometheus/Grafana 모니터링 없음 | — | P2-15 |
| /run 호출 throttling 없음 | assessment.py | P2-19 |
| 자가 증적 자동 파싱 (OCR+LLM) | — | P3-20 보류 |
| PDF 디자인 고도화 | report.py | P3-26 보류 |
| 정기 스케줄링 (월간 자동 진단) | — | P3-22 |

전체 TODO는 `PLAN.md`.
