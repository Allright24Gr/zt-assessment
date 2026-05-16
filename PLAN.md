# PLAN — Readyz-T 작업 로드맵

> 본 문서는 **무엇이 끝났고 무엇이 남았는지** 헷갈리지 않도록 기능별·우선순위별로 정리한다.
> 현재 상태 스냅샷은 `STATUS.md`, 운영 정책·아키텍처는 `CLAUDE.md`를 본다.

작성: 2026-05-17 / 기준 브랜치 `dev` @ `8111ca0`

---

## 0. 우선순위 정의

| 등급 | 의미 | 시점 |
|---|---|---|
| **P0** | 운영 시작 전 필수. 빠지면 법적·보안 리스크 또는 운영 불가능 | 시연 후 즉시 (1주 내) |
| **P1** | 베타 고객 1~3사 응대 가능 수준. 빠지면 실제 사용 불편 큼 | 운영 1개월 내 |
| **P2** | 10+ 고객 확장기. 빠지면 운영 효율·안정성 저하 | 운영 3개월 내 |
| **P3** | 차별화·장기 비전. 빠져도 운영 자체엔 영향 작음 | 6개월+ |

---

## 1. 완료된 작업 (Done)

### 1-A. 보안 인증 (auth)
- [x] PBKDF2-SHA256 200k → **600k** 상향 (OWASP 2023)
- [x] PBKDF2 **lazy upgrade** — 로그인 시 저장 라운드 < 600k면 새 해시로 자동 재저장
- [x] 비밀번호 정책 **8자 이상 + 영문+숫자 혼합** (Pydantic field_validator)
- [x] 로그인 실패 잠금 — **5회 후 60초** (HTTP 423 + Retry-After), in-memory `_login_state`
- [x] 회원가입 시 **시드 조직명 자동 join 차단** (`_PROTECTED_ORG_NAMES` 6개)
- [x] 개인 조직 **유일 키** `"{login_id}_개인"` (동명이인 충돌 방지)
- [x] `GET /me`, `PUT /profile` query param 폐기 → **X-Login-Id 헤더**
- [x] `PUT /profile`에 **current_password 재확인** body 필드
- [x] `POST /change-password` 신설 — 동일 비번 차단
- [x] Pydantic v2 `.dict()` → `.model_dump()`
- [x] **audit logger** 채널 `zt.audit` — register/login/profile/change-password 이벤트 (stdlib logger)

### 1-B. 진단 실행 흐름 (assessment)
- [x] `AssessmentRunRequest`에 `scan_targets` 추가 (Nmap host, Trivy image)
- [x] `AssessmentRunRequest`에 `keycloak_creds`, `wazuh_creds`, `entra_creds` 추가
- [x] **Step 0** `profile_select`(idp_type, siem_type) 추가
- [x] `_resolve_supported_tools` — 사용자 환경에 따라 자동 도구 활성/비활성
- [x] `validators.py` — `validate_nmap_target` / `validate_trivy_image` / `validate_https_url` / `validate_cred_field` / `validate_entra_tenant_id`. shell 메타문자 차단
- [x] `_kc_mapping` 충돌 수정: `4.1.1.3_2 → collect_conditional_policy`, `6.2.1.3_1 → collect_data_abac_policy` 신규
- [x] **`/webhook` fail-closed** — `INTERNAL_API_TOKEN` 미설정 시 503. 개발 우회 `ZTA_DEV_ALLOW_UNAUTH_WEBHOOK=true`
- [x] **자격 비밀번호 메모리 dict 보관** (`_store_session_secrets` / `_pop_session_secrets`). DB 평문 저장 금지
- [x] `_run_collectors` 전체를 `_collector_lock`으로 직렬화
- [x] nmap/trivy/keycloak/wazuh/entra collector에 `set_session_target` / `set_session_creds` 헬퍼 일괄 추가
- [x] `_mask_creds` — API 응답에서 `admin_pass`/`api_pass`/`client_secret` → `"***"`

### 1-C. 권한·IDOR 차단
- [x] `get_current_user` / `assert_session_access` / `assert_org_access` 의존성 (`routers/auth.py`)
- [x] 보호 엔드포인트 17개에 의존성 적용 (assessment / score / report / improvement / manual)
- [x] `/history`는 일반 user에게 자기 조직 강제 필터
- [x] `/run`은 본인 조직 외 진단 차단 (admin 제외)
- [x] frontend `apiFetch`에 X-Login-Id **자동 첨부** (register/login 제외)

### 1-D. 진단 도구 (collectors)
- [x] Keycloak collector 65개 (1차 구현)
- [x] Wazuh collector 122개 (1차 구현)
- [x] Nmap collector 14개 (1차 구현)
- [x] Trivy collector 11개 (1차 구현)
- [x] **MS Entra ID collector 20개** (Microsoft Graph, Phase A)
- [x] `_tool_health` 가용성 프리체크 — 미연결 시 매핑된 모든 항목 "평가불가" 일괄 처리
- [x] 환경변수 fallback (`KEYCLOAK_URL`/`ENTRA_TENANT_ID`/`NMAP_TARGET` 등)

### 1-E. 프론트엔드 UX
- [x] 회원가입/로그인 페이지
- [x] AuthContext — localStorage `zt_user` + JSON 파싱 실패 시 손상 키 자동 제거
- [x] NewAssessment **데모/실 스캔 토글** (기본 데모, 시연 안전)
- [x] NewAssessment **Step 0 사전 프로파일링** (IdP/SIEM 선택)
- [x] NewAssessment **외부 스캔 동의 체크박스** (외부 입력 시 필수)
- [x] NewAssessment **Keycloak/Entra/Wazuh 자격 입력 카드** (도구 선택 + 실 스캔 시만)
- [x] NewAssessment Nmap/Trivy 스캔 대상 입력 (정규식 검증 메시지)
- [x] InProgress **동적 ETA** (90초 고정 폐기) + 완료 후 interval 정지
- [x] Reporting fetch 실패 시 **fallback 배너** (mockData 사용 명시)
- [x] Reporting **출처 배지** — 자동 외부 스캔 / 자동 API / 수동 / 미진단
- [x] Reporting 성숙도 step에 `maturityLabel` 적용
- [x] Settings **비밀번호 변경 모달** (8자+영문+숫자 클라이언트 검증, 401/400/423 분기)
- [x] Settings **진단 프로필 수정 시 비번 재확인 모달**
- [x] Login 데모/복구 모달 접근성 (ESC, role/aria-modal, autoFocus)
- [x] Dashboard **시드 비번 경고 배너** + `[지금 변경]` → Settings 자동 오픈
- [x] **한국어 라벨 정리**: 기존→근간(UI 표시 매핑) / 오류→위험 영역 / 취약한 필러→점수 낮은 영역 / 귀사→해당 기관 / 기업 환경 입력→기관 정보 입력
- [x] types/api.ts — `KeycloakCreds`, `WazuhCreds`, `EntraCreds`, `ScanTargets`, `ProfileSelect`

### 1-F. 데이터 보관·운영
- [x] `cleanup_old_sessions.py` — 90일 자동 삭제 스탠드얼론 스크립트
- [x] FastAPI **lifespan task** — 24시간 주기 cleanup 자동 실행
- [x] 시드 보호 `ZTA_PROTECT_DEMO_DATA=true` (기본)
- [x] 자식 5개 테이블 cascade 삭제 (CollectedData / Evidence / DiagnosisResult / MaturityScore / ScoreHistory)
- [x] cleanup 결과 `zt.audit` 로그에 기록
- [x] CORS wildcard 경고 (`main.py` 시작 시)
- [x] seed 부분 손상(admin·user1 중 1개만) 시 wipe 차단 — `--force` 필요

### 1-G. 문서
- [x] CLAUDE.md — 운영 모델, 지원 도구 매트릭스, 보안 정책, API 계약, 환경변수 가이드
- [x] STATUS.md — 현재 진행 상황 스냅샷
- [x] PLAN.md — 본 문서
- [x] `.env.example` — 운영·도구·토글 환경변수 상세 주석

---

## 2. 진행할 작업 (TODO, 우선순위별)

### 2-P0 — 운영 시작 전 필수 (6개)

> 빠지면 진짜 운영 시작 불가. 시연 영상 직후 즉시 진행 권장. **합계 ~5.5일, 3트랙 병렬이면 2~3일.**

#### P0-1. JWT 세션 토큰화
- **왜**: 현재 X-Login-Id 헤더는 만료 없음. localStorage 탈취 시 영구 접근.
- **무엇**:
  - backend: `POST /api/auth/login` 응답에 `access_token` (JWT, 만료 8h) + `refresh_token` 추가
  - backend: `get_current_user`를 `Authorization: Bearer ...` 검증으로 교체. X-Login-Id는 deprecation으로 한동안 병행 또는 즉시 제거
  - backend: `POST /api/auth/refresh` 엔드포인트
  - backend: PyJWT 의존성 추가, SECRET_KEY 환경변수 사용
  - frontend: `apiFetch`에서 X-Login-Id → Authorization 헤더로 교체
  - frontend: AuthContext에 accessToken/refreshToken 보관(메모리 우선, localStorage는 refreshToken만)
  - frontend: 401 응답 시 refresh → 재시도 한 번
- **공수**: 1.5일

#### P0-2. 비밀번호 재설정 이메일 흐름
- **왜**: 비번 잊으면 admin 개입 필요. 운영 불가능.
- **무엇**:
  - backend: `PasswordResetToken` 테이블 신규 (token, user_id, expires_at, used)
  - backend: `POST /api/auth/request-password-reset` (login_id 또는 email → 토큰 발급 + 이메일 발송)
  - backend: `POST /api/auth/reset-password` (token + new_password)
  - frontend: Login 페이지에 "비밀번호 찾기" 링크
  - frontend: `/auth/reset-password?token=...` 페이지 신설
  - 이메일 발송은 P0-6 인프라 의존
- **공수**: 1일

#### P0-3. audit log DB 테이블화
- **왜**: 현재 stdlib logger 콘솔만. 컨테이너 재시작 시 손실. 감사·법규 대응 불가.
- **무엇**:
  - backend: `AuthAuditLog` 테이블 신규 (id, user_id?, login_id?, event_type, ip, user_agent, success, metadata JSON, created_at)
  - backend: `audit_logger` 사용처에 DB insert 병행 (콘솔 + DB 이중 기록)
  - backend: `GET /api/admin/audit-log` (admin 전용, 페이징)
  - frontend: admin 대시보드에 audit 탭 (간단 표 형태)
  - 90일 cleanup 정책에 audit log 포함 여부 결정 (보관 정책 분리 권장)
- **공수**: 0.5~1일

#### P0-4. 로그인 IP별 rate limit
- **왜**: 현재는 `login_id`별 잠금. 공격자가 ID 100개 돌리면 무방비.
- **무엇**:
  - backend: 잠금 키를 `(login_id, source_ip)` 조합 + `source_ip` 단일 키 양쪽으로 확장
  - backend: 같은 IP에서 10분 내 50회 실패 시 IP 전체 잠금 30분
  - backend: `X-Forwarded-For` 처리 (nginx 통과 IP)
  - 다중 인스턴스 시 Redis 필요 (P2-14) — 우선 in-memory + 단일 인스턴스 운영 가정
- **공수**: 0.5일

#### P0-5. 이용약관·개인정보 처리방침 동의
- **왜**: 한국 정보통신망법·개인정보보호법 의무. 미동의 시 운영 불가.
- **무엇**:
  - 약관·방침 본문 작성 (법무 검토 필요 — 또는 표준 템플릿 기반 초안)
  - backend: User 테이블에 `tos_agreed_at`, `privacy_agreed_at` 컬럼 추가 (migrate_schema.py)
  - backend: register 시 둘 다 필수 + 시점 기록
  - frontend: Signup 페이지에 체크박스 2개 + 약관 본문 모달
  - frontend: Settings에 "약관 다시 보기" 링크
- **공수**: 1일 (법무 검토 별도)

#### P0-6. 회원 탈퇴 + 이메일 발송 인프라
- **왜**: 탈퇴 — 법령 의무. 이메일 — 비번 재설정·진단 완료 알림 필수.
- **무엇** (회원 탈퇴):
  - backend: `DELETE /api/auth/me` (X-Login-Id + current_password 재확인)
  - backend: User + 본인이 만든 DiagnosisSession + 자식 테이블 cascade 삭제 (개인 조직이면 Organization도)
  - frontend: Settings 하단 "회원 탈퇴" 위험 영역 카드
- **무엇** (이메일 인프라):
  - backend: `email_sender.py` — SMTP 기반 (gmail / SES / Mailgun 중 택1). env: `SMTP_HOST/PORT/USER/PASSWORD/FROM`
  - backend: 템플릿 시스템 (Jinja2 또는 단순 f-string)
  - 사용처: 비번 재설정(P0-2), 진단 완료 알림(P1-9), 회원 탈퇴 확인
- **공수**: 1.5일

**P0 합계**: 5.5일 (3트랙 병렬: 2~3일)

---

### 2-P1 — 베타 고객 응대 수준 (운영 1개월 내)

#### P1-7. 수동 증적 파일 업로드 (PDF/이미지)
- 현재 `Evidence.observed`는 텍스트만. 자가 진단의 핵심인 정책 스크린샷·문서 첨부 불가.
- backend: `POST /api/manual/upload-evidence` (multipart, check_id별), MinIO 또는 S3 또는 로컬 디스크 저장
- backend: `Evidence` 테이블에 `file_path`, `mime_type`, `file_size` 컬럼 추가
- frontend: manual 페이지 항목별 파일 업로드 + 미리보기
- 공수: 1.5일

#### P1-8. 진단 비교 시각화
- History에서 "이전 진단 vs 현재" 차이 시각화. 임원 보고용 핵심.
- backend: `GET /api/assessment/compare?from=<session_id>&to=<session_id>`
- 응답: 항목별 result 차이, 점수 차이, 새로 충족 / 새로 미충족 / 변화 없음 분류
- frontend: History 페이지에 비교 모드 UI (체크박스 2개 → "비교" 버튼)
- 공수: 1일

#### P1-9. 이메일 알림
- 진단 완료/실패, 수동 진단 마감 알림
- P0-6 SMTP 인프라 위에 구현
- backend: `_trigger_scoring` 끝에 `send_completion_email(user, session)` 호출
- 공수: 0.5일 (P0-6 끝났을 때)

#### P1-10. Okta + Splunk collector 각 1차
- Entra 다음으로 점유율 높은 IdP·SIEM.
- Okta: REST API `/api/v1/users`, `/api/v1/policies`, `/api/v1/groups` 기반
- Splunk: REST API `/services/search/jobs` (search query 기반)
- 각 핵심 항목 15~20개씩 우선 구현
- `_resolve_supported_tools`에 매핑 추가 + `_TOOL_DISPATCH` 확장
- 공수: 도구당 2~3일 = 5일

#### P1-11. 진단 결과 외부 공유 링크
- 임원 보고 시 로그인 없이 결과 볼 수 있는 서명 URL.
- backend: `POST /api/assessment/share/{session_id}` — 서명 토큰 발급 (만료 7일, 읽기 전용)
- backend: `GET /api/assessment/shared/{token}` — 토큰으로 결과 조회 (X-Login-Id 불필요)
- frontend: Reporting에 "공유 링크 생성" 버튼 + URL 복사
- 공수: 1일

#### P1-12. collector 실패 retry + 부분 결과 표시
- 외부 시스템 일시 장애 시 전체 평가불가가 아니라 N회 재시도 후 일부 성공/일부 실패 표시.
- collector 헬퍼 `_safe_call`에 재시도 3회 + 지수 백오프 추가
- 공수: 0.5일

**P1 합계**: 9.5일

---

### 2-P2 — 확장기 (10+ 고객, 운영 3개월 내)

#### P2-13. multi-tenant 격리 강화
- 현재 user.org_id 필터로 논리 격리만. row-level security 또는 schema 분리 검토.
- 임시 보강: 모든 쿼리에 org_id 필터를 `__init_subclass__` 또는 query event listener로 강제
- 장기: PostgreSQL 마이그레이션 + RLS
- 공수: 2~3일

#### P2-14. Redis 기반 rate limit / 세션
- in-memory `_login_state`는 단일 프로세스만. 다중 인스턴스 운영 시 작동 안 함.
- docker-compose에 redis 추가
- `_login_state` → `redis.set` / `redis.get` 교체
- JWT refresh token도 Redis로 옮기는 게 자연스러움
- 공수: 1일

#### P2-15. Prometheus / Grafana 모니터링
- `prometheus_client` 추가 — request latency, error rate, collector 처리 시간
- backend: `GET /metrics` 엔드포인트
- Grafana 대시보드 JSON 템플릿 1개
- 공수: 1일

#### P2-16. CI/CD GitHub Actions
- 현재 `./deploy.sh` 수동.
- `.github/workflows/ci.yml` — PR마다 backend pytest + frontend build + ruff/eslint
- `.github/workflows/deploy.yml` — main 머지 시 자동 배포 (ssh + docker-compose pull/up)
- 공수: 1일

#### P2-17. Alembic DB 마이그레이션
- 현재 `migrate_schema.py` 수동 + 멱등 if-not-exists.
- Alembic 도입 — `alembic revision --autogenerate` 워크플로
- 기존 DB 스키마를 baseline으로
- 공수: 1일

#### P2-18. pytest 자동 테스트
- 현재 0개. 회귀 방지 핵심 경로 단위/통합 테스트.
- `tests/test_auth.py` — 가입/로그인/잠금/비번정책
- `tests/test_validators.py` — shell metachar 차단
- `tests/test_assessment.py` — _resolve_supported_tools, IDOR 차단
- 목표 커버리지: routers 80%, validators 100%
- 공수: 2일

#### P2-19. /run 호출 throttling
- 사용자가 외부 스캔 무한 트리거 방지.
- 사용자당 분당 N회, 시간당 N회 제한.
- P2-14 Redis 위에서 자연스럽게 구현 가능.
- 공수: 0.5일

**P2 합계**: 9일

---

### 2-P3 — 장기 (확장·차별화)

| # | 항목 | 공수 |
|---|---|---|
| P3-20 | 자가 증적 자동 파싱 (PDF/이미지 OCR → LLM → 자동 채점 보조) | 1~2주 |
| P3-21 | AWS Security Hub / Azure Defender collector | 도구당 3~5일 |
| P3-22 | 진단 스케줄링 (월간 정기 진단 cron / worker queue) | 2일 |
| P3-23 | 요금제 / 결제 (Stripe 또는 토스페이먼츠) | 1~2주 |
| P3-24 | 다국어 (i18n, 영문 → 글로벌) | 1주 |
| P3-25 | 2FA / WebAuthn (관리자 계정 강화) | 2~3일 |
| P3-26 | 진단 결과 PDF 디자인 고도화 (브랜딩, 차트 다양화) | 3일 |
| P3-27 | 자가 진단 증적 OCR | 1주 |
| P3-28 | 진단 요청 동시성 — Celery / Dramatiq worker 분리 | 3일 |
| P3-29 | 백업/복원 자동화 (DB 일일 dump → S3) | 1일 |

---

## 3. 기능별 분류 (또 다른 시각)

같은 항목을 우선순위 대신 기능 영역으로 묶은 것. 어느 한 영역에 손댈 때 무엇이 동시에 필요한지 한눈에.

### 인증·계정
- [x] PBKDF2 600k + lazy upgrade
- [x] 비번 정책 8+영숫
- [x] 로그인 잠금 (login_id 기준)
- [x] /me /profile /change-password
- [x] X-Login-Id 헤더 + IDOR 차단
- [ ] **P0-1** JWT 세션
- [ ] **P0-2** 비번 재설정 이메일
- [ ] **P0-4** IP 기반 잠금
- [ ] **P0-6** 회원 탈퇴
- [ ] **P3-25** 2FA

### 진단 실행
- [x] Step 0 사전 프로파일링
- [x] 데모/실 스캔 토글
- [x] 자격 메모리 dict + lock 직렬화
- [x] 입력 검증 (validators.py)
- [x] _resolve_supported_tools
- [x] 자동/수동 폴백
- [ ] **P1-12** retry + 부분 결과
- [ ] **P2-19** /run throttling
- [ ] **P3-22** 정기 스케줄링
- [ ] **P3-28** worker 분리

### 진단 도구 (Collectors)
- [x] Keycloak 65 / Wazuh 122 / Nmap 14 / Trivy 11
- [x] **Entra ID 20 (Phase A)**
- [ ] **P1-10** Okta / Splunk
- [ ] **P2** Entra ID Phase B (남은 항목 추가)
- [ ] **P3-21** AWS Security Hub / Azure Defender
- [ ] **P3** Elastic SIEM / QRadar / ArcSight

### 결과 / 보고
- [x] Reporting + PDF (NanumGothic)
- [x] 출처 배지 (자동/수동/미진단)
- [x] InProgress 동적 ETA
- [ ] **P1-7** 수동 증적 파일 업로드
- [ ] **P1-8** 진단 비교 시각화
- [ ] **P1-11** 외부 공유 링크
- [ ] **P3-20** 증적 자동 파싱
- [ ] **P3-26** PDF 디자인 고도화

### 데이터·운영
- [x] 90일 자동 삭제 + 시드 보호
- [x] audit logger (stdlib)
- [x] CORS wildcard 경고
- [ ] **P0-3** audit log DB 테이블
- [ ] **P0-5** 약관·방침 동의
- [ ] **P2-13** multi-tenant 격리 강화
- [ ] **P2-14** Redis (rate limit + 세션)
- [ ] **P3-29** DB 일일 백업

### 인프라·DevOps
- [x] docker-compose 통합
- [x] FastAPI lifespan task
- [ ] **P0-6** SMTP 이메일 인프라
- [ ] **P2-15** Prometheus/Grafana
- [ ] **P2-16** GitHub Actions CI/CD
- [ ] **P2-17** Alembic 마이그레이션
- [ ] **P2-18** pytest 테스트

### UX / Frontend
- [x] 한국어 라벨 정리
- [x] Settings 비번 변경 모달
- [x] Login/Settings 접근성
- [x] 시드 비번 경고 배너
- [x] 데모/실 스캔 토글
- [ ] **P0-2** 비번 재설정 페이지
- [ ] **P0-5** Signup 약관 동의
- [ ] **P0-6** Settings 회원 탈퇴
- [ ] **P1-7** 수동 증적 업로드 UI
- [ ] **P1-8** History 비교 모드 UI
- [ ] **P1-11** Reporting 공유 링크 버튼
- [ ] **P3-24** i18n

---

## 4. 권장 진행 순서

```
[지금] dev @ 8111ca0
   │
   ▼  P0 6개 (병렬 3트랙, 2~3일)
   ├ 트랙 A (auth): P0-1 JWT + P0-2 비번 재설정 backend + P0-3 audit DB + P0-4 IP 잠금
   ├ 트랙 B (frontend): P0-1 frontend + P0-2 페이지 + P0-5 약관 + P0-6 탈퇴 UI
   └ 트랙 C (infra): P0-6 SMTP 인프라 + 이메일 템플릿
   │
   ▼  베타 1~3사 시작 시점
   P1 (1개월 분량, 우선순위 P1-7 → P1-8 → P1-9 → P1-12 → P1-11 → P1-10)
   │
   ▼  10+ 고객
   P2 (3개월 분량, 우선순위 P2-14 → P2-13 → P2-16 → P2-18 → P2-15 → P2-17 → P2-19)
   │
   ▼  차별화
   P3 (선택)
```

---

## 5. 결정 필요 (사용자가 답해야 할 것)

다음에 진행할 때 명확히 결정 필요한 것들:

1. **P0-1 JWT** — 토큰 만료 시간 (기본 8h 권장 / refresh 30d), `SECRET_KEY` 발급 방법
2. **P0-2 이메일** — SMTP 공급자 (Gmail App Password / AWS SES / Mailgun / SendGrid 중)
3. **P0-3 audit log 보관 기간** — 90일 동일 vs 1년 별도 정책
4. **P0-5 약관 본문** — 표준 템플릿 사용 vs 법무 검토 의뢰
5. **P0-6 회원 탈퇴 정책** — 즉시 삭제 vs 30일 유예 (복구 가능 기간)
6. **P1-10 자동 IdP/SIEM 추가 순위** — Okta / 자체 LDAP / Splunk / Elastic 중 우선

이 6개 답이 정해지면 P0 즉시 분배 시작 가능.
