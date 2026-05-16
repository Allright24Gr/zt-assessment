# STATUS — Readyz-T ZT Assessment Platform

> 작성일: 2026-05-17
> 기준 브랜치: `dev` (HEAD `2ec8457`)
> 본 문서는 "지금 시점의 사실"만 기록한다. 앞으로의 계획은 `PLAN.md`, 운영 모델·정책은 `CLAUDE.md`를 본다.

---

## 0. TL;DR

- **상태**: dev 모두 통과. 진단 자동 항목 211 → **262** (Entra +20, Okta +15, Splunk +15). P0+P1 완전 종료 + STEP 1 운영 셋업 + STEP 2 pytest 66 케이스 완료. 본격 운영 시작 준비.
- **운영 모델**: 고객 시스템 무침해(원격 outbound 호출만). Step 0 환경 프로파일링 → 자동/수동 폴백.
- **마지막 큰 변경**: `2ec8457` "pytest 자동 테스트 66 케이스" / `ab1a313` "frontend P0+P1 통합" / `882e51e` "backend P0+P1"
- **다음 단계**: STEP 3 시연 차별화는 보류 (사용자 결정 — LLM·PDF는 나중에). 운영 배포 가이드(DEPLOY.md) 작성 완료, 실제 배포는 사용자 인프라 설정 대기.

---

## 1. 진행 현황 (Phase별 요약)

| Phase | 설명 | 핵심 산출물 | 상태 |
|---|---|---|---|
| 1 | 1차 보안 패치 + 외부 스캔 흐름 | `9a149cb` 17 files | ✅ |
| 2A | auth 운영 강화 (정책·잠금·lazy upgrade·audit) | `20a6b35` 안 | ✅ |
| 2B | IdP/SIEM 자격 session별 주입 + 입력 검증 | `validators.py` 신설 | ✅ |
| 2C | UI 운영 보강 (데모 토글·동의·비번 변경 모달·시드비번 배너) | `20a6b35` 18 files | ✅ |
| 3 | 자격 평문 DB 저장 제거 (메모리 dict + lock) | 동상 | ✅ |
| 4 | 17개 보호 엔드포인트 IDOR 차단 + apiFetch X-Login-Id 자동 첨부 | 동상 | ✅ |
| 5 | Step 0 사전 프로파일링 + 자동/수동 폴백 | `8111ca0` | ✅ |
| 6 | MS Entra ID collector +20 (Microsoft Graph) | `entra_collector.py` 570줄 | ✅ |
| 7 | DiagnosisSession 90일 자동 삭제 + 시드 보호 | `cleanup_old_sessions.py` | ✅ |
| **P0** | JWT/audit DB/IP 잠금/약관 동의/회원 탈퇴/SMTP/비번 재설정 (6개) | `70ce828` + `882e51e` | ✅ |
| **P1** | Okta·Splunk collector + 증적 업로드 + 비교 + 공유 + retry + frontend 통합 | `882e51e` + `ab1a313` | ✅ |
| **STEP 1** | 운영 셋업 — docker-compose.prod.yml + nginx + DEPLOY.md + e2e_smoke.sh | (본 커밋) | ✅ |
| **STEP 2** | pytest 66 케이스 + multi-tenant 격리(테스트로 보증) | `2ec8457` | ✅ |

자동 진단 매핑(2026-05-17 기준):

| 도구 | 명시 매핑 | autodiscover | 합계 | 비고 |
|---|---|---|---|---|
| keycloak | 32 | 33 | **65** | IdP — Keycloak 사용 고객 한정 |
| wazuh | 41 | 81 | **122** | SIEM — Wazuh 사용 고객 한정 |
| nmap | 14 | 0 | **14** | 도구 무관, 외부 스캔 |
| trivy | 11 | 0 | **11** | 도구 무관, 이미지 스캔 |
| entra | 20 | 0 | **20** | IdP — Entra ID 사용 고객 (Phase A) |
| **okta (신규)** | 15 | 0 | **15** | IdP — Okta 사용 고객 (Phase A) |
| **splunk (신규)** | 15 | 0 | **15** | SIEM — Splunk 사용 고객 (Phase A) |
| **합계** | 148 | 114 | **262** | |

---

## 2. 디렉토리 구조 (현재 파일 단위)

```
zt-assessment/
├── CLAUDE.md                       # 프로젝트 가이드 + 최종 운영 계획·정책
├── STATUS.md                       # ← 본 문서. 현재 상태 스냅샷
├── PLAN.md                         # 작업 로드맵 (Done/TODO 매트릭스)
├── DEPLOY.md                       # 운영 배포 가이드 (신규 — STEP 1)
├── README.md
├── deploy.sh                       # EC2 배포 스크립트 (./deploy.sh <IP>)
├── docker-compose.yml              # 8개 서비스 통합
├── docker-compose.prod.yml         # 운영 override — nginx + 데모도구 분리 (신규)
├── .env.example                    # 운영 환경변수 가이드
│
├── nginx/                          # Reverse proxy (운영 전용, 신규)
│   ├── nginx.conf                  # 80→443, SSL, 보안 헤더, /api 라우팅
│   └── certs/.gitkeep              # 인증서는 gitignore (운영 환경 직접 배포)
│
├── scripts/                        # 호스트 스크립트 (신규)
│   └── e2e_smoke.sh                # 10단계 e2e 자동 검증 (회원가입→탈퇴)
│
├── backend/                        # FastAPI 백엔드
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── requirements.txt
│   ├── init.sql                    # DB 초기 스키마 (보조)
│   │
│   ├── main.py                     # FastAPI 진입점 + lifespan(90일 cleanup)
│   ├── database.py                 # SQLAlchemy 세션·엔진
│   ├── models.py                   # 10개 테이블 (Organization, User, ...)
│   │
│   ├── routers/                    # API 엔드포인트
│   │   ├── auth.py                 # 820줄. 회원가입/로그인/me/profile/change-password
│   │   │                           #         /refresh /request-password-reset /reset-password /me(DELETE)
│   │   │                           #         JWT 세션 + IP 잠금 + audit DB + 회원 탈퇴
│   │   ├── assessment.py           # ~2100줄. 진단 run/status/result/history/finalize/webhook
│   │   │                           #          /compare /share/{id} /shared/{token}
│   │   ├── score.py                # 122줄. 점수 요약/추이/체크리스트 점수
│   │   ├── improvement.py          # 143줄. 개선 가이드 목록/세션별/상세
│   │   ├── report.py               # 477줄. JSON·PDF 보고서 (NanumGothic)
│   │   ├── manual.py               # ~600줄. 수동 항목 제출/업로드/items + 증적 업로드/다운로드
│   │   ├── checklist.py            # 45줄. 체크리스트 목록 (인증 무필요)
│   │   └── validators.py           # 119줄. 입력 검증 (Nmap/Trivy/URL/자격/Entra/Okta)
│   │
│   ├── collectors/                 # 도구별 자동 수집기 (7개)
│   │   ├── keycloak_collector.py   # 1427줄. 65 함수, IdP 통제 평가
│   │   ├── wazuh_collector.py      # 2930줄. 122 함수, SIEM/HIDS 통제 평가
│   │   ├── entra_collector.py      # 570줄. 20 함수, Microsoft Graph API
│   │   ├── okta_collector.py       # ~500줄. 15 함수, Okta REST API (SSWS)  (신규)
│   │   ├── splunk_collector.py     # ~500줄. 15 함수, Splunk REST API       (신규)
│   │   ├── nmap_collector.py       # 308줄. 14 함수, 외부 포트/CIDR 스캔
│   │   └── trivy_collector.py      # 257줄. 11 함수, 컨테이너 이미지 스캔
│   │
│   ├── services/                   # 외부 서비스 통합 (신규)
│   │   ├── email_sender.py         # AWS SES + Jinja2 + DRY_RUN + audit
│   │   └── email_templates/        # password_reset, account_deleted, assessment_complete (txt+html)
│   │
│   ├── tests/                      # pytest 자동 테스트 (신규 — 66 케이스)
│   │   ├── conftest.py             # sqlite in-memory + JWT helper + Checklist 시드
│   │   ├── test_auth_basic.py      # 15 cases — register/login/refresh/delete
│   │   ├── test_idor.py            # 10 cases — multi-tenant 격리 회귀 차단
│   │   ├── test_collector_mapping.py  # 14 cases — 7 도구 매핑 정합성
│   │   ├── test_resolve_tools.py   # 6 cases — profile_select 폴백
│   │   ├── test_validators.py      # 17 cases — shell metachar 차단
│   │   └── test_cleanup.py         # 4 cases — 90일 retention + 시드 보호
│   │
│   ├── scoring/
│   │   └── engine.py               # 130줄. 결과 → MaturityScore 계산
│   │
│   ├── scripts/                    # 운영·시드 스크립트
│   │   ├── seed_checklist.py       # 167줄. xlsx → Checklist 테이블 적재
│   │   ├── seed_improvement.py     # 129줄. xlsx → ImprovementGuide
│   │   ├── seed_demo.py            # 271줄. (구 시드, 호환용)
│   │   ├── seed_demo_examples.py   # 390줄. admin/user1 + 데모 세션 시드
│   │   ├── migrate_schema.py       # 66줄. 멱등 스키마 변경 (ALTER 등)
│   │   └── cleanup_old_sessions.py # 117줄. 90일 보관 정책 (신규)
│   │
│   ├── manual-checklist.xlsx       # 수동 진단 양식
│   ├── zt-checklist.xlsx           # 310행 진단 항목 원본
│   └── zt-improvement-guide.xlsx   # 개선 가이드 원본
│
├── frontend/                       # React + TS + Vite + shadcn/ui
│   ├── Dockerfile, nginx.conf
│   ├── vite.config.ts
│   ├── package.json, pnpm-lock.yaml
│   │
│   └── src/
│       ├── main.tsx
│       ├── config/api.ts           # apiFetch + 모든 엔드포인트 호출 함수
│       ├── types/api.ts            # 232줄. 백엔드 응답·요청 TypeScript 타입
│       │
│       └── app/
│           ├── App.tsx, routes.tsx
│           │
│           ├── context/
│           │   └── AuthContext.tsx # 117줄. localStorage zt_user + setUser/logout
│           │
│           ├── data/
│           │   ├── mockData.ts     # API 실패 시 fallback (삭제 금지)
│           │   ├── checklistItems.ts
│           │   └── constants.ts
│           │
│           ├── lib/
│           │   ├── maturity.ts     # MATURITY_LABEL("기존"→"근간") 표시 매핑
│           │   └── pillar.ts       # 6개 Pillar 한국어 라벨/색상
│           │
│           ├── pages/
│           │   ├── Login.tsx       # 175줄. 로그인 + 데모 모달 + 시드 비번 감지
│           │   ├── Signup.tsx      # 217줄. 회원가입 + 프로필 입력
│           │   ├── Dashboard.tsx   # 215줄. 점수 카드/추이/시드 비번 경고 배너
│           │   ├── History.tsx     # 121줄. 진단 이력 + 비교 모드
│           │   ├── NewAssessment.tsx # 571줄. Step 0 ~ 진단 시작
│           │   ├── InProgress.tsx  # 681줄. 동적 ETA + 수동 업로드 병행
│           │   ├── Reporting.tsx   # 321줄. 결과 시각화 + 출처 배지 + PDF
│           │   └── Settings.tsx    # 606줄. 진단 프로필 수정 + 비번 변경 모달
│           │
│           └── components/
│               ├── RootLayout.tsx
│               ├── figma/ImageWithFallback.tsx
│               └── ui/             # shadcn/ui 컴포넌트 50+개
│
├── nmap-wrapper/                   # Nmap CLI 래퍼 (Flask, 8001)
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app.py                      # 412줄. /scan/ports /scan/subnets /scan/tls
│
└── trivy-wrapper/                  # Trivy CLI 래퍼 (Flask, 8002)
    ├── Dockerfile
    ├── requirements.txt
    └── app.py                      # 394줄. /scan/image /scan/fs /scan/sbom
```

총 backend 소스 ~9,800줄, frontend src ~9,500줄.

---

## 3. 데이터 흐름 (현재 동작)

### 3-1. 신규 사용자 진단 흐름 (end-to-end)

```
[1] 회원가입  Signup.tsx → POST /api/auth/register
              ├ login_id 중복 검사
              ├ 비밀번호 정책(8자+영문+숫자) Pydantic validator
              ├ 시드 조직명 자동 join 차단(_PROTECTED_ORG_NAMES)
              ├ 개인 조직 키 "{login_id}_개인"
              ├ PBKDF2-SHA256 600,000 라운드
              └ User + Organization 행 생성

[2] 로그인    Login.tsx → POST /api/auth/login
              ├ in-memory _login_state로 5회 실패 시 60초 잠금 (423)
              ├ password === login_id 감지 시 sessionStorage zt_seed_password_warning
              ├ Lazy upgrade — 저장 라운드 < 600k면 새 해시 재저장
              └ UserResponse 반환 → localStorage zt_user 보관

[3] Dashboard 진입
              ├ AuthContext useEffect → GET /api/auth/me (X-Login-Id 헤더)
              ├ zt_seed_password_warning 있으면 노란 배너
              └ [지금 변경] → navigate("/settings", state: openPasswordModal: true)

[4] NewAssessment Step 0~Step 4
              ├ Step 0 사전 프로파일링: idp_type / siem_type / 외부 스캔 toggle / 데모↔실 스캔 토글
              ├ Step 1 기관 정보 (auth profile prefill)
              ├ Step 2 진단 범위 6 Pillar
              ├ Step 3 도구별 자격 입력 (실 스캔 + 지원 도구 한정):
              │     · Keycloak: URL + admin
              │     · Entra: tenant_id + client_id + client_secret
              │     · Wazuh: URL + api_user
              │     · Nmap target, Trivy image
              └ Step 4 동의 체크박스(외부 입력 있을 때 필수)

[5] POST /api/assessment/run  (X-Login-Id 헤더, apiFetch 자동 첨부)
              ├ 입력 검증 validators.py: nmap/trivy/url/cred/entra_tenant
              ├ 사용자 권한: 본인 조직 외 진단 차단(admin 제외)
              ├ _resolve_supported_tools(profile_select, tool_scope) → 실행 도구 결정
              │     · idp=entra → keycloak 비활성, entra 활성
              │     · idp=okta → 두 IdP 모두 비활성 (수동 폴백)
              ├ session.extra에 URL/사용자명만 저장 (비밀번호 제외)
              ├ _store_session_secrets(session_id, kc, wz, en) → 메모리 dict
              └ BackgroundTasks → _run_collectors(session_id, selected_tools)

[6] _run_collectors  (단일 _collector_lock으로 직렬화)
              ├ _pop_session_secrets로 자격 메모리 dict에서 꺼내 즉시 폐기
              ├ 도구별 set_session_target/set_session_creds → 모듈 전역에 주입
              ├ _tool_health(tool) — placeholder 감지 / TCP probe
              │     · 미연결: 매핑된 모든 item_id를 "평가불가"로 일괄 저장
              │     · 연결됨: collector 함수 호출 → CollectedData/DiagnosisResult upsert
              └ finally: set_session_creds(None), set_session_target(None) 정리

[7] InProgress.tsx  (250ms 폴링)
              GET /api/assessment/status/{session_id}
              ├ assert_session_access — 본인/admin만
              ├ 도구별 collected/expected + 필러별 진행률 반환
              └ frontend 평균 속도(items/sec) → 동적 ETA. 90초 고정 폐기

[8] POST /api/assessment/finalize/{session_id}
              ├ score_session(session_id, db) — scoring/engine.py
              ├ DiagnosisSession.status = "완료", level, total_score
              ├ MaturityScore 6 pillar 행 + ScoreHistory 1행 생성
              └ DiagnosisResult.recommendation 채움

[9] Reporting.tsx
              GET /api/assessment/result?session_id=...
              ├ assert_session_access
              ├ _mask_creds — extra.keycloak_creds.admin_pass → "***"
              ├ pillar_scores, checklist_results, errors 반환
              └ frontend: 출처 배지(자동 외부/자동 API/수동/미진단) + 점수 시각화

[10] PDF 다운로드  GET /api/report/generate?session_id=...&fmt=pdf
              ├ assert_session_access
              ├ NanumGothic 폰트 등록 → reportlab으로 PDF 빌드
              └ Content-Disposition attachment
```

### 3-2. 인증·세션 흐름 (현재)

```
브라우저 localStorage["zt_user"] = { login_id, name, org_id, role, profile, ... }
   │
   ▼
apiFetch(endpoint, options)
   ├ PUBLIC_ENDPOINTS(register/login)이 아니면
   ├ localStorage에서 login_id 추출
   └ headers["X-Login-Id"] = login_id 자동 첨부
   │
   ▼ HTTP
backend FastAPI Dependency get_current_user
   ├ Header("X-Login-Id") 추출
   ├ 누락 → 401
   └ User row 조회 → 의존성 주입
   │
   ▼
보호 엔드포인트 내부
   ├ assert_session_access(user, session) — 본인/조직/admin
   └ assert_org_access(user, org_id)
```

**한계 (PLAN.md의 P0-1과 직결)**: 헤더가 영구 유효, 만료 없음. 누가 localStorage 훔치면 영구 접근. 진짜 운영엔 JWT/cookie 세션 필요.

### 3-3. 자격 비밀번호 흐름

```
NewAssessment submit
   │
   ▼
POST /api/assessment/run body { keycloak_creds, wazuh_creds, entra_creds, ... }
   │
   ▼
run_assessment in assessment.py
   ├ validators.py 통과
   ├ session.extra에 URL/사용자명만 저장 (DB 평문 저장 0)
   └ _store_session_secrets(session_id, kc_pass, wz_pass, en_secret) → 메모리 dict
                                                          │
                                                          ▼
                          BackgroundTask _run_collectors(session_id, tools)
                          ├ _pop_session_secrets(session_id) — 메모리에서 꺼내고 삭제
                          ├ set_session_creds(creds) — collector 모듈 전역
                          ├ collector 호출
                          └ finally: set_session_creds(None) 즉시 폐기
```

**서버 재시작 시 자격 손실** → 진단 처리 전 컨테이너 죽으면 사용자가 재실행해야 함. 트레이드오프 — DB 평문 저장보다 훨씬 안전.

### 3-4. 90일 자동 삭제 흐름

```
backend/main.py 부팅
   │
   ▼ FastAPI lifespan
asyncio.create_task(_periodic_cleanup)
   ├ 30초 후 첫 실행 (ZTA_CLEANUP_FIRST_DELAY_SEC)
   └ 매 24시간 (ZTA_CLEANUP_INTERVAL_HOURS) 반복
      │
      ▼
   cleanup_old_sessions(days=90)
   ├ DiagnosisSession.started_at < now - 90d 조회
   ├ ZTA_PROTECT_DEMO_DATA=true 시 _PROTECTED_ORG_NAMES 세션 제외
   ├ 자식 5개 테이블(CollectedData/Evidence/DiagnosisResult/MaturityScore/ScoreHistory) 삭제
   ├ DiagnosisSession 삭제
   └ audit_logger "[cleanup] cutoff=... checked=... deleted=..." 기록
```

스탠드얼론 호출: `python backend/scripts/cleanup_old_sessions.py --days 90 [--dry-run]`

---

## 4. API 엔드포인트 표 (인증·권한 매트릭스)

| Method · Path | 인증 | 권한 | 비고 |
|---|---|---|---|
| `POST /api/auth/register` | ✗ | 누구나 | 비번 정책 8자+영문+숫자 |
| `POST /api/auth/login` | ✗ | 누구나 | 5회 실패 60초 잠금 |
| `GET /api/auth/me` | X-Login-Id | 본인 | 헤더 누락 401 |
| `PUT /api/auth/profile` | X-Login-Id | 본인 | body.current_password 재확인 |
| `POST /api/auth/change-password` | X-Login-Id | 본인 | 동일 비번 차단 |
| `POST /api/assessment/run` | X-Login-Id | 본인 조직만 (admin 전체) | scan_targets/creds 검증 |
| `GET /api/assessment/status/{id}` | X-Login-Id | session 권한 | InProgress 폴링용 |
| `POST /api/assessment/finalize/{id}` | X-Login-Id | session 권한 | 채점 트리거 |
| `POST /api/assessment/internal/collect/{tool}` | X-Internal-Token | 내부 SOAR | Shuffle용 |
| `POST /api/assessment/webhook` | X-Internal-Token | 내부 SOAR | 미설정 시 503 |
| `GET /api/assessment/result?session_id=` | X-Login-Id | session 권한 | _mask_creds 적용 |
| `GET /api/assessment/history` | X-Login-Id | 자기 조직만 (admin 전체) | |
| `GET /api/score/summary?session_id=` | X-Login-Id | session 권한 | |
| `GET /api/score/trend?org_id=` | X-Login-Id | org 권한 | |
| `GET /api/score/checklist/{id}` | X-Login-Id | session 권한 | |
| `GET /api/report/generate?session_id=&fmt=` | X-Login-Id | session 권한 | json/pdf |
| `GET /api/report/generate/{id}` | X-Login-Id | session 권한 | 동상 |
| `GET /api/improvement/` | X-Login-Id | 인증만 | 정적 가이드 |
| `GET /api/improvement/session/{id}` | X-Login-Id | session 권한 | |
| `GET /api/improvement/{guide_id}` | X-Login-Id | 인증만 | |
| `POST /api/manual/upload` | X-Login-Id | session 권한 | xlsx |
| `POST /api/manual/submit` | X-Login-Id | session 권한 | |
| `GET /api/manual/template` | X-Login-Id | 인증만 | xlsx 다운로드 |
| `GET /api/manual/items/{id}` | X-Login-Id | session 권한 | profile_select 폴백 합류 |
| `GET /api/checklist` | ✗ | 공개 | 정적 목록 |
| `GET /health` | ✗ | 공개 | docker healthcheck |

---

## 5. DB 스키마 (models.py)

```
Organization     (org_id PK, name UK, industry, size, cloud_type, ...)
User             (user_id PK, org_id FK, name, email UK, role, login_id UK, password_hash, profile JSON)
DiagnosisSession (session_id PK, org_id FK, user_id FK, status, started_at, completed_at,
                  selected_tools JSON, extra JSON, total_score, level)
Checklist        (check_id PK, item_id UK, pillar, category, item_name, maturity, maturity_score,
                  diagnosis_type, tool, evidence, criteria, fields, logic, exceptions)
CollectedData    (collect_id PK, session_id FK, check_id FK, tool, metric_key, metric_value,
                  threshold, raw_json, error, collected_at)
Evidence         (evidence_id PK, session_id FK, check_id FK, source, observed, location, reason, impact)
DiagnosisResult  (result_id PK, session_id FK, check_id FK, result, score, recommendation)
MaturityScore    (score_id PK, session_id FK, pillar, score, level, pass_cnt, fail_cnt, na_cnt)
ImprovementGuide (guide_id PK, check_id FK?, pillar, current_level, next_level, recommended_tool,
                  task, priority, term, duration, difficulty, owner, expected_gain, steps, ...)
ScoreHistory     (history_id PK, session_id FK, org_id FK, total_score, maturity_level,
                  pillar_scores JSON, assessed_at)
```

10개 테이블. `session.extra` JSON에 사용자 입력 메타데이터(profile_select, scan_targets, keycloak/wazuh/entra_creds의 url·user만) 보관.

---

## 6. 환경변수 현황 (.env.example)

```
필수 (운영)
  INTERNAL_API_TOKEN          # 미설정 시 webhook 503 (fail-closed)
  DB_HOST/PORT/NAME/USER/PASSWORD
  CORS_ORIGINS                # 명시적 도메인, wildcard 금지

도구 fallback (사용자 입력 없을 때 적용)
  KEYCLOAK_URL / KEYCLOAK_ADMIN / KEYCLOAK_ADMIN_PASSWORD
  WAZUH_URL / WAZUH_USER / WAZUH_PASSWORD
  ENTRA_TENANT_ID / ENTRA_CLIENT_ID / ENTRA_CLIENT_SECRET
  NMAP_WRAPPER_URL=http://nmap-wrapper:8001
  TRIVY_WRAPPER_URL=http://trivy-wrapper:8002
  NMAP_TARGET=127.0.0.1
  TRIVY_TARGET=nginx:latest

운영 토글
  ZTA_SESSION_RETENTION_DAYS=90
  ZTA_PROTECT_DEMO_DATA=true
  ZTA_CLEANUP_DISABLE=
  ZTA_CLEANUP_INTERVAL_HOURS=24
  ZTA_CLEANUP_FIRST_DELAY_SEC=30
  ZTA_DEV_ALLOW_UNAUTH_WEBHOOK=     # dev 한정 webhook 우회
  ZTA_FORCE_REAL_COLLECTION=        # placeholder 가드 우회 (비권장)

Shuffle (옵션)
  SHUFFLE_URL / SHUFFLE_API_KEY
  SHUFFLE_WORKFLOW_KEYCLOAK / _WAZUH / _NMAP / _TRIVY
  SELF_BASE_URL=http://zt-backend:8000
```

---

## 7. 인프라 / 포트

| 포트 | 서비스 | 비고 |
|---|---|---|
| 8080 | Frontend (Nginx) | docker-compose `frontend` |
| 8000 | Backend (FastAPI) | docker-compose `backend` |
| 8001 | Nmap 래퍼 (Flask) | 호스트 8001 → 컨테이너 5000 |
| 8002 | Trivy 래퍼 (Flask) | 호스트 8002 → 컨테이너 5001 |
| 3000 | Shuffle UI (옵션) | 미사용 시 backend 직접 실행 |
| 8443 | Keycloak (데모용) | 운영은 고객 IdP로 우회 |
| 55000 | Wazuh API (데모용) | 운영은 고객 SIEM으로 우회 |
| 9200 | Elasticsearch | Wazuh 부속 |
| 3306 | MySQL | docker-compose `mysql` |

서버 사양: **Ubuntu 24.04 / t3a.xlarge (4vCPU / 16GB)**.
배포: `./deploy.sh <EC2_IP>` (EC2 재시작마다 IP 변경).

---

## 8. 브랜치 / 시드 계정

브랜치
- `master` ← 최종 배포본. `8111ca0` (= dev와 동기화됨, 2026-05-17)
- `dev` ← 통합 테스트. 현재 HEAD.
- 과거 feature 브랜치: `feature/backend-skeleton`, `feature/keycloak-collector`, `feature/wazuh-collector`, `feature/nmap-trivy-wrapper`

시드 계정 (`seed_demo_examples.py --force`로 재생성)
- `admin / admin`  → role=admin, 시스템관리 조직
- `user1 / user1`  → 박기웅, 세종대학교 (완료 세션 3 + 진행중 1)
- 관리자 시점 예시 세션 4건 (ABC 핀테크, XYZ 메디컬, 국가데이터센터, 스타트업 K)

**주의**: 시드 비번은 정책 위반(4자) 상태로 _hash_password 직접 호출로 저장됨.
로그인 직후 Dashboard에 "기본 비번 사용 중" 노란 배너 노출 → 강제 변경 안내.

---

## 9. 자기 검증 (정적, 2026-05-17 기준)

```
✅ AST parse: backend 21개 파일 + 8개 tests 모두 통과
✅ _full_mapping() base 매핑:
     keycloak 32 + wazuh 41 + nmap 14 + trivy 11 + entra 20 + okta 15 + splunk 15 = 148
     autodiscover 합산 시 262 (keycloak +33, wazuh +81)
✅ _resolve_supported_tools 7케이스 모두 통과
     · keycloak+wazuh → {keycloak, wazuh, nmap, trivy}
     · entra+wazuh    → {entra, wazuh, nmap, trivy}
     · okta+splunk    → {okta, splunk, nmap, trivy}
     · okta+wazuh     → {okta, wazuh, nmap, trivy}
     · none+none      → {nmap, trivy}  (모든 IdP/SIEM 자동 비활성)
     · 미선택         → {keycloak, entra, okta, wazuh, splunk, nmap, trivy}
     · entra만        → {entra, wazuh, nmap, trivy}
✅ frontend npm run build 통과 (chunk-size 경고만, 변경 코드 무관)
✅ validators:
     - validate_nmap_target: scanme.nmap.org / 192.168.1.0/24 통과,
       "; rm -rf /" / "$(whoami)" / "nginx;ls" / "`whoami`" 차단
     - validate_https_url: javascript:/file:// 차단
     - validate_entra_tenant_id: GUID + *.onmicrosoft.com 통과, 메타문자 차단
     - validate_okta_domain: *.okta.com 통과, "; ls" 차단
✅ _mask_creds: admin_pass / api_pass / client_secret / okta.api_token /
     splunk.password+token → "***"
✅ pytest 자동 테스트: 66 케이스 (실행은 docker 컨테이너 안에서)
     - test_auth_basic 15 / test_idor 10 / test_collector_mapping 14 /
       test_resolve_tools 6 / test_validators 17 / test_cleanup 4
```

---

## 10. 알려진 한계 (이미 인지하고 다음 사이클로 보낸 것)

✅ P0+P1 항목은 모두 완료됨. STEP 1·2(운영 셋업 + pytest) 추가 완료.

남은 한계 — `PLAN.md` P2/P3 참조:

| 한계 | 위치 | PLAN.md 항목 |
|---|---|---|
| _login_state 모듈 전역 in-memory (다중 인스턴스 불가) | auth.py | P2-14 Redis |
| Elastic SIEM / QRadar / ArcSight collector 부재 | — | P2 미정 |
| CI/CD GitHub Actions 없음 | — | P2-16 |
| Alembic DB 마이그레이션 없음 (수동 migrate_schema.py) | — | P2-17 |
| Prometheus/Grafana 모니터링 없음 | — | P2-15 |
| /run 호출 throttling 없음 (사용자가 무한 트리거 가능) | assessment.py | P2-19 |
| 자가 증적 자동 파싱 (OCR+LLM) | — | P3-20 (사용자 결정: 보류) |
| PDF 디자인 고도화 | report.py | P3-26 (사용자 결정: 나중에) |
| 정기 스케줄링 (월간 자동 진단) | — | P3-22 |
| 결제 (Stripe/토스) | — | P3-23 |
| 다국어 (i18n 영문) | — | P3-24 |
| 2FA / WebAuthn | — | P3-25 |
| 회원 탈퇴 후 30일 유예(soft delete) — 현재 즉시 cascade | auth.py | (선택) |

전체 TODO는 `PLAN.md` 참조.
