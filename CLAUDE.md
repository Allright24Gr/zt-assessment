# Readyz-T — ZT Assessment 프로젝트 가이드

> 본 문서는 **프로젝트 전반 가이드 + 최종 운영 계획 + 시스템별 상세 설명**을 담는다.
> 현재 진행 상황 스냅샷은 [`STATUS.md`](./STATUS.md), 작업 로드맵은 [`PLAN.md`](./PLAN.md) 참조.

---

## A. 프로젝트 개요

제로트러스트 가이드라인 2.0 기반 보안 성숙도 진단 자동화 플랫폼.
고객 시스템에 무침해(원격 outbound 호출만)하면서 6대 Pillar / 4단계 성숙도를 자동·반자동 진단한다.

### A-1. 기술 스택

| 영역 | 스택 |
|---|---|
| Frontend | React 18 + TypeScript + Vite + shadcn/ui + Tailwind |
| Backend | Python 3.11+ + FastAPI + SQLAlchemy 2 + Pydantic 2 |
| DB | MySQL 8 |
| SOAR (옵션) | Shuffle |
| 진단 도구 | Keycloak, Wazuh, Nmap(래퍼), Trivy(래퍼), **MS Entra ID** (Phase A) |
| 인프라 | Docker Compose, AWS EC2 (t3a.xlarge) |
| PDF | reportlab + NanumGothic |

### A-2. 디렉토리 구조 (요약 — 상세는 STATUS.md §2)

```
zt-assessment/
├── frontend/                # React UI (대시보드, 진단 신청, 결과)
├── backend/                 # FastAPI (routers, collectors, scoring, scripts)
│   ├── routers/             # 8개 — auth, assessment, score, report, improvement, manual, checklist, validators
│   ├── collectors/          # 5개 — keycloak/wazuh/nmap/trivy/entra
│   ├── scoring/engine.py    # 결과 → MaturityScore 계산
│   └── scripts/             # 시드, 마이그레이션, 90일 cleanup
├── nmap-wrapper/            # 외부 IP/포트 스캔 (Flask, 8001)
├── trivy-wrapper/           # 컨테이너 이미지 스캔 (Flask, 8002)
├── docker-compose.yml
├── deploy.sh                # ./deploy.sh <EC2_IP>
├── CLAUDE.md                # ← 본 문서
├── STATUS.md                # 현재 상태 스냅샷
└── PLAN.md                  # 작업 로드맵 (Done/TODO)
```

### A-3. 인프라 / 포트

| 포트 | 서비스 |
|---|---|
| 8080 | Frontend (Nginx) |
| 8000 | Backend (FastAPI) |
| 8001 | Nmap 래퍼 (호스트 8001 → 컨테이너 5000) |
| 8002 | Trivy 래퍼 (호스트 8002 → 컨테이너 5001) |
| 3000 | Shuffle UI (옵션) |
| 8443 / 55000 / 9200 | Keycloak / Wazuh API / Elasticsearch (데모용) |
| 3306 | MySQL |

서버 사양: **Ubuntu 24.04 / t3a.xlarge (4vCPU / 16GB)** / 배포 `./deploy.sh <IP>`.

### A-4. 브랜치 / 시드 계정

브랜치
- `master` — 최종 배포본. 직접 push는 dev fast-forward 또는 PR.
- `dev` — 통합 테스트. 모든 작업은 dev에 push 후 master로.
- feature/* — 1차 개발자별 (서진우, 공나영, 서정우, 송민희)

시드 계정 (`python backend/scripts/seed_demo_examples.py --force`)
- `admin / admin` (role=admin, 시스템관리)
- `user1 / user1` (박기웅, 세종대학교 — 완료 3건 + 진행중 1건)
- 관리자 시점 예시 4건 (ABC 핀테크, XYZ 메디컬, 국가데이터센터, 스타트업 K)

> 시드 비번은 정책 위반(4자) 상태. 로그인 시 Dashboard 노란 배너로 "기본 비번 사용 중 → 지금 변경" 안내.

---

## B. 최종 운영 계획

### B-1. 핵심 원칙

1. **고객 시스템에 우리 코드를 설치하지 않는다.** agent/sidecar/git clone 일체 금지.
2. **모든 진단은 우리 EC2(원격/cloud)에서 outbound 호출** 또는 외부 스캔으로 수행.
3. **가이드라인은 도구 무관(통제 요건 평가)이며, Keycloak/Wazuh 종속은 우리 1차 구현 선택일 뿐.**
   → Step 0 환경 프로파일링으로 사용 도구를 받아 미지원 영역은 수동 진단으로 자동 폴백.
4. **자격 비밀번호는 DB 평문 저장 금지.** 메모리 dict로만 BackgroundTask에 전달 후 즉시 폐기.
5. **모든 보호 엔드포인트는 X-Login-Id 인증 + 세션·조직 권한 검증.** (P0-1 이후 JWT로 교체 예정)
6. **고객 자산 보호** — 진단 결과 90일 자동 삭제 + audit log + 데이터 위탁 동의.

### B-2. 진단 흐름 (사용자 관점, Step 0~4)

#### Step 0 — 사전 환경 프로파일링 (NewAssessment 최상단)
- IdP 선택: Keycloak / **MS Entra ID** / Okta / 자체 LDAP·AD / 사용 안 함·기타
- SIEM 선택: Wazuh / Splunk / Elastic / 사용 안 함·기타
- 외부 자동 스캔 toggle: Nmap / Trivy
- **데모 모드 ↔ 실 스캔 모드 토글** (기본 데모, 시연 안전)

미지원 옵션 선택 시 그 분야 자동 항목은 **수동 진단으로 자동 폴백**된다.

#### Step 1 — 기관 정보 (auth profile에서 prefill)
부서, 산업군, 인프라 유형, 직원 수, 서버 수, 애플리케이션 수, 비고.

#### Step 2 — 진단 범위 선택 (6 Pillar)
신원·기기·네트워크·시스템·애플리케이션·데이터 중 진단할 영역.

#### Step 3 — 도구별 자격 입력 (실 스캔 + 지원 도구 선택 시만 활성)
- Keycloak: URL + admin user + admin pass
- MS Entra ID: tenant_id + client_id + client_secret (Microsoft Graph)
- Wazuh: URL + api user + api pass
- Nmap target: IPv4/CIDR/도메인 (정규식 + shell metachar 차단)
- Trivy image: 컨테이너 참조 (정규식 검증)

#### Step 4 — 외부 스캔 동의 체크박스
실 스캔 + Nmap/Trivy target 있을 때만 필수. 법적 보호 + UX 명확.

### B-3. 백엔드 처리 흐름

```
POST /api/assessment/run  (X-Login-Id 헤더, apiFetch 자동 첨부)
    ├ validators.py 통과
    ├ 권한 — 본인 조직만 (admin 제외)
    ├ session.extra ← URL/사용자명만 저장 (비밀번호 제외)
    ├ _store_session_secrets ← 비밀번호 메모리 dict
    └ BackgroundTasks.add_task(_run_collectors, session_id, tools)

_run_collectors (단일 _collector_lock으로 직렬화)
    ├ _pop_session_secrets ← 메모리에서 꺼내고 삭제
    ├ _resolve_supported_tools(profile_select, tool_scope) → 실행 도구
    ├ 도구별 set_session_target / set_session_creds
    ├ _tool_health(tool):
    │     · 미연결 → 매핑된 모든 item_id "평가불가" 일괄
    │     · 연결됨 → collector 호출 → CollectedData/DiagnosisResult upsert
    └ finally: set_session_creds(None), set_session_target(None)

POST /api/assessment/finalize/{id}
    └ score_session → MaturityScore + ScoreHistory + recommendation
```

InProgress 페이지가 250ms 폴링으로 진행률을 표시 (frontend가 평균 속도로 동적 ETA 추정).

### B-4. 지원 도구 매트릭스 (2026-05 기준)

#### IdP (신원)
| 도구 | 상태 | 자동 항목 수 | 비고 |
|---|---|---|---|
| Keycloak | ✅ 지원 | 65 | 1차 구현, 한국 대학/공공/금융 일부 |
| **MS Entra ID** | ✅ 지원 (Phase A) | 20 | 한국 기업 점유율 1위. Microsoft Graph |
| Okta | ⏳ 미지원 (PLAN.md P1-10) | 0 → 100% 수동 폴백 | |
| 자체 LDAP / AD | ⏳ 미지원 | 0 → 100% 수동 폴백 | |
| 기타 / 사용 안 함 | — | 0 → 100% 수동 폴백 | |

#### SIEM (보안 정보)
| 도구 | 상태 | 자동 항목 수 |
|---|---|---|
| Wazuh | ✅ 지원 | 122 |
| Splunk | ⏳ 미지원 (PLAN.md P1-10) | 0 → 수동 |
| Elastic SIEM | ⏳ 미지원 | 0 → 수동 |
| 기타 | — | 0 → 수동 |

#### 도구 무관 (항상 가능)
- Nmap (외부 IP/포트 스캔) — 14 항목
- Trivy (컨테이너 이미지 스캔) — 11 항목

**현재 자동 진단 합계: 211 → 231 (Entra +20).**

### B-5. 데이터 보관 정책

- DiagnosisSession + 자식 5개 테이블 **90일** 자동 삭제 (`ZTA_SESSION_RETENTION_DAYS`)
- backend/main.py FastAPI lifespan task가 24h 주기로 cleanup 실행
- 시드 데이터 보호: `ZTA_PROTECT_DEMO_DATA=true` (기본). `_PROTECTED_ORG_NAMES` 세션 보존
- 비활성: `ZTA_CLEANUP_DISABLE=true`
- 스탠드얼론: `python backend/scripts/cleanup_old_sessions.py --days 90 [--dry-run]`
- audit log(`zt.audit`)에 cutoff·checked·deleted 건수 기록

### B-6. 보안 정책

#### 인증
- 비밀번호: **PBKDF2-SHA256 600,000 라운드** (OWASP 2023)
- 정책: **8자 이상 + 영문+숫자** (Pydantic field_validator)
- Lazy upgrade: 로그인 성공 시 저장 라운드 < 600k면 자동 재해싱
- 로그인 실패: 5회 후 60초 잠금 (HTTP 423 + Retry-After). in-memory `_login_state`
- 시드 비번(admin/admin, user1/user1) 사용 시 Dashboard 노란 배너로 변경 유도

#### 권한
- 모든 보호 엔드포인트: `X-Login-Id` 헤더 검증 (`get_current_user` 의존성)
- frontend apiFetch가 자동 첨부 (register/login 제외)
- 세션 접근: 본인 또는 자기 조직 또는 admin (`assert_session_access`)
- `/history`: 일반 user는 자기 조직 강제 필터
- `/run`: 본인 조직 외 진단 차단 (admin 제외)
- 회원가입 시 시드/관리 조직 자동 join 차단 (`_PROTECTED_ORG_NAMES`)
- 개인 조직 이름은 `"{login_id}_개인"` 유일 키

#### 자격 비밀번호
- DB 평문 저장 금지. `session.extra`에는 URL/사용자명만
- `_store_session_secrets` → 메모리 dict → `_pop_session_secrets`로 BackgroundTask에 전달
- collector 호출 후 즉시 폐기 (`set_session_creds(None)`)
- 응답 마스킹: `_mask_creds`가 `admin_pass`/`api_pass`/`client_secret` → `"***"`
- 로깅 채널에 자격 절대 포함하지 말 것

#### 웹훅
- `INTERNAL_API_TOKEN` 미설정 시 webhook 503 (fail-closed)
- 로컬 개발 우회: `ZTA_DEV_ALLOW_UNAUTH_WEBHOOK=true` (운영 금지)

#### 입력 검증 (`backend/routers/validators.py`)
- `validate_nmap_target` — IPv4/CIDR/도메인. shell metachar(`;|&` `$<>\`) 차단
- `validate_trivy_image` — 컨테이너 참조 형식. 공백/메타문자 차단
- `validate_https_url` — scheme + host 검증
- `validate_cred_field` — 길이 + strip
- `validate_entra_tenant_id` — UUID 또는 도메인 형식

#### 감사 로그
- 채널: `zt.audit` (stdlib logger, 콘솔)
- 이벤트: register / login(성공·실패·잠금) / profile update / change-password / cleanup
- **한계**: 현재 콘솔만. P0-3에서 DB 테이블화 예정.

---

## C. 시스템별 세세 설명

### C-1. 인증 시스템 (`backend/routers/auth.py`)

#### 핵심 함수
- `_hash_password(password, salt=None)` — `pbkdf2$<iters>$<hex_salt>$<hex_hash>` 형식 반환
- `_verify_password(password, stored)` — 저장 라운드를 읽어 검증. 역호환 보장
- `_stored_iters(stored)` — 라운드 수 추출 (lazy upgrade 판단용)
- `_validate_password_policy(password)` — 8자+영문+숫자 (위배 시 ValueError)
- `_check_lock(login_id)` / `_record_login_failure` / `_record_login_success` — in-memory 잠금
- `_resolve_user_or_401(db, login_id)` — X-Login-Id 헤더 검증
- `get_current_user` — FastAPI Dependency. 다른 router들이 import해 사용
- `assert_session_access(user, session)` — 본인/조직/admin만
- `assert_org_access(user, org_id)` — 조직 단위 권한

#### Pydantic 스키마
- `ProfileFields` — org_name, department, contact, org_type, infra_type, employees, servers, applications, note
- `RegisterRequest` — login_id, password, name, email?, profile? (정책 validator)
- `LoginRequest` — login_id, password
- `UserResponse` — user_id, login_id, name, email, role, org_id, org_name, profile?
- `ProfileUpdateRequest` — current_password + profile
- `ChangePasswordRequest` — current_password + new_password (정책 validator)

#### 보호 조직 (`_PROTECTED_ORG_NAMES`)
```
{"시스템관리", "세종대학교", "ABC 핀테크", "XYZ 메디컬", "국가데이터센터", "스타트업 K"}
```
신규 가입자가 위 이름으로 join 시도 시 400 반환.

#### 엔드포인트
- `POST /register` — User + Organization upsert
- `POST /login` — 잠금 검사 → 검증 → 잠금 리셋 → lazy upgrade → UserResponse
- `GET /me` — X-Login-Id로 본인 정보
- `PUT /profile` — current_password 재확인 후 profile 갱신
- `POST /change-password` — current 검증 + new 정책 + 동일 비번 차단

---

### C-2. 진단 실행 시스템 (`backend/routers/assessment.py`)

#### Pydantic 모델
```python
class ProfileSelect(BaseModel):
    idp_type:  Optional[str]  # keycloak | entra | okta | ldap | none
    siem_type: Optional[str]  # wazuh | splunk | elastic | none

class AssessmentRunRequest(BaseModel):
    org_name, manager, email, department, contact, org_type, infra_type,
    employees, servers, applications, note,
    pillar_scope: dict,
    tool_scope: dict,
    profile_select: ProfileSelect | None,
    scan_targets: dict,             # {"nmap": "...", "trivy": "..."}
    keycloak_creds: dict | None,    # {"url": "...", "admin_user", "admin_pass"}
    wazuh_creds: dict | None,       # {"url", "api_user", "api_pass"}
    entra_creds: dict | None,       # {"tenant_id", "client_id", "client_secret"}
```

#### 핵심 함수
- `_resolve_supported_tools(profile_select, requested)` — tool_scope ∩ 사용자 환경
- `_store_session_secrets(session_id, kc, wz, en)` — 메모리 dict + Lock
- `_pop_session_secrets(session_id)` — 메모리에서 꺼내고 즉시 삭제
- `_mask_creds(extra)` — 응답 마스킹
- `_run_collectors(session_id, tools)` — BackgroundTask. `_collector_lock`으로 직렬화
- `_tool_health(tool)` — placeholder 검사 + TCP probe
- `_unavailable_result(tool, item_id, maturity, error_msg)` — 미연결 시 "평가불가"
- `_full_mapping(tool)` — base mapping + autodiscover (docstring 기반)
- `_safe_call(fn, ...)` — 호출 + 예외 → 평가불가 변환

#### 도구 매핑 (`_TOOL_DISPATCH`)
```python
{
  "keycloak": (lambda: _full_mapping("keycloak"), True),   # 65
  "wazuh":    (lambda: _full_mapping("wazuh"),    True),   # 122
  "nmap":     (lambda: _full_mapping("nmap"),     False),  # 14
  "trivy":    (lambda: _full_mapping("trivy"),    False),  # 11
  "entra":    (lambda: _full_mapping("entra"),    True),   # 20
}
ALL_TOOLS = ("keycloak", "wazuh", "nmap", "trivy", "entra")
```

`takes_args=True`인 도구는 collector 함수가 `(item_id, maturity)` 인자를 받는다. `False`는 인자 없음.

#### IdP/SIEM 사용자 선택 ↔ 자동 도구
```python
_IDP_TOOL_OF = {"keycloak": "keycloak", "entra": "entra"}
_SIEM_TOOL_OF = {"wazuh": "wazuh"}
_IDP_AUTO_TOOLS = {"keycloak", "entra"}
_SIEM_AUTO_TOOLS = {"wazuh"}
```
Okta/Splunk/Elastic collector가 추가되면 위 dict에 등록 + ALL_TOOLS 확장.

#### 엔드포인트 (인증·권한 §B-6 참조)
- `POST /run` — 진단 실행
- `GET /status/{id}` — 진행률
- `POST /finalize/{id}` — 채점 트리거
- `POST /internal/collect/{tool}` — Shuffle 호출
- `POST /webhook` — Shuffle 결과 수신 (INTERNAL_API_TOKEN 필수)
- `GET /result?session_id=` — 결과 조회 (_mask_creds 적용)
- `GET /history` — 자기 조직 (admin 전체)

---

### C-3. Collector 시스템

#### 공통 인터페이스
- 모듈 상단에 환경변수 fallback 상수 (`KEYCLOAK_URL` 등)
- `_session_creds: dict | None` + `set_session_creds(creds)` — 세션별 자격 주입
- 헬퍼: `_get_url() / _get_user() / _get_pass()` — session 우선, 없으면 env fallback
- 각 `collect_*` 함수는 다음 dict 반환 (수집 결과 공통 포맷):
  ```python
  {
    "item_id": str, "maturity": str, "tool": str,
    "result": "충족"|"부분충족"|"미충족"|"평가불가",
    "metric_key": str, "metric_value": float, "threshold": float,
    "raw_json": dict, "collected_at": isoformat, "error": str|None
  }
  ```
- docstring 첫 줄에 `<item_id>:` 패턴 명시 — autodiscover가 추출

#### Keycloak (`keycloak_collector.py`, 1427줄)
- 인증: admin REST API token (`/realms/master/protocol/openid-connect/token`)
- 진단 영역: 사용자 인벤토리, IdP 등록, MFA, OTP, WebAuthn, Conditional Auth,
  Session Policy, ICAM, RBAC, ABAC, Password Policy, 권한 정책
- 65 함수, base mapping 32 + autodiscover 33

#### Wazuh (`wazuh_collector.py`, 2930줄)
- 인증: API user/pass → JWT 토큰
- 진단 영역: 에이전트 등록, SCA, 알림, 정책 위반, FIM, 행위 탐지, 자동 차단, EDR
- 122 함수, base mapping 41 + autodiscover 81

#### Nmap (`nmap_collector.py`, 308줄)
- nmap-wrapper Flask 서비스에 POST `/scan/ports` `/scan/subnets` `/scan/tls`
- session별 target 주입 (NMAP_TARGET → `_get_target()`)
- 14 함수: 호스트 발견, 포트 스캔, 서브넷 토폴로지, TLS 비율, VPN 포트 등

#### Trivy (`trivy_collector.py`, 257줄)
- trivy-wrapper Flask 서비스에 POST `/scan/image` `/scan/fs` `/scan/sbom`
- 11 함수: 이미지 스캔, CI/CD 스캔 비율, 무결성 검증, SBOM, 의존성 스캔

#### MS Entra ID (`entra_collector.py`, 570줄) — Phase A
- 인증: OAuth 2.0 client_credentials (`/oauth2/v2.0/token` → access_token)
- Microsoft Graph: `https://graph.microsoft.com/v1.0/...`
- 토큰 캐시 + 세션 전환 시 무효화
- 20 함수 (Phase A 핵심): users, identityProviders, conditionalAccess policies,
  authenticationMethodsPolicy, directoryRoles, applications, servicePrincipals
- 필요 권한 (Graph App permissions): `Directory.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`

---

### C-4. 점수 산정 (`backend/scoring/engine.py`)

- `score_session(session_id, db)` — 6 Pillar별 MaturityScore 생성 + 총점 + 레벨
- `determine_maturity_level(score)` — 0.0~1.0 점수를 4단계 enum으로 매핑
- 결과 weight: 충족=1.0, 부분충족=0.5, 미충족=0.0, 평가불가=0.0
- pillar 점수 = Σ(item × maturity_score × weight) / Σ(item × maturity_score)
- 최종 level: 모든 pillar가 N 이상 만족 → N 단계 (보수적 평가)

---

### C-5. 입력 검증 (`backend/routers/validators.py`)

```python
validate_nmap_target("scanme.nmap.org")  # OK
validate_nmap_target("; rm -rf /")        # ValueError

validate_trivy_image("nginx:1.25")        # OK
validate_trivy_image("nginx;ls")          # ValueError

validate_https_url("https://example.com:8443")  # OK
validate_https_url("javascript:alert(1)")        # ValueError

validate_entra_tenant_id("00000000-0000-0000-0000-000000000000")  # OK
validate_entra_tenant_id("contoso.onmicrosoft.com")               # OK

validate_cred_field(value, field_name)  # 길이/strip + 메타문자
```

모두 `run_assessment` 시작 부분에서 호출. 위배 시 `HTTPException(400, detail=str(e))`.

---

### C-6. 데이터 보관 (`backend/scripts/cleanup_old_sessions.py`)

```python
cleanup_old_sessions(days=90, dry_run=False) -> dict
# 반환: {"checked": N, "deleted": M, "preserved_demo": K, "cutoff": iso}
```

- `DiagnosisSession.started_at < now - days` 조회
- `ZTA_PROTECT_DEMO_DATA=true` 시 `_DEMO_ORG_NAMES` 세션 제외
- 자식 5개 테이블(CollectedData/Evidence/DiagnosisResult/MaturityScore/ScoreHistory) cascade
- audit_logger("[cleanup] cutoff=... checked=... deleted=...")
- main.py FastAPI lifespan task가 24h 주기 자동 호출

---

### C-7. 프론트엔드 (`frontend/`)

#### apiFetch (`src/config/api.ts`)
- 모든 HTTP 호출의 공통 wrapper
- `localStorage["zt_user"]` 에서 `login_id` 추출 → `X-Login-Id` 헤더 자동 첨부
- `PUBLIC_ENDPOINTS = {register, login}` — 헤더 첨부 제외
- `ApiError` 클래스로 상태코드별 분기 가능

#### AuthContext (`src/app/context/AuthContext.tsx`)
- `useAuth()` 훅 — `{ user, login, logout, setUser, loading }`
- localStorage 영속화 + 백엔드 `/me` 재조회로 최신화
- JSON 파싱 실패 시 손상 키 자동 제거

#### 페이지
- **Login** — 데모/복구 모달, 시드 비번 감지 (`zt_seed_password_warning`)
- **Signup** — 회원가입 + 프로필 입력
- **Dashboard** — 점수 카드, 추이, 시드 비번 경고 배너
- **History** — 진단 이력 + 비교 모드 (P1-8에서 강화)
- **NewAssessment** — Step 0~4 (사전 프로파일링 → 기관 → 범위 → 도구 → 동의)
- **InProgress** — 250ms 폴링, 동적 ETA, 수동 업로드 병행
- **Reporting** — 결과 시각화, 출처 배지, PDF 다운로드
- **Settings** — 진단 프로필 수정 모달, 비밀번호 변경 모달

#### 라벨 매핑 (`src/app/lib/maturity.ts`)
```ts
MATURITY_LABEL = { 기존: "근간", 초기: "초기", 향상: "향상", 최적화: "최적화" }
```
백엔드 enum 값은 그대로 비교 로직에 사용, 표시 시점에만 `maturityLabel()` 통과.

---

## D. API 계약 (요약)

상세 매트릭스는 STATUS.md §4 참조.

### 헤더
- 보호 엔드포인트: `X-Login-Id` 필수 (apiFetch 자동 첨부)
- 내부 SOAR 엔드포인트: `X-Internal-Token` 필수 (`INTERNAL_API_TOKEN`)

### 표준 응답
- 200/204: 성공
- 400: 입력 검증 실패 (validators.py / Pydantic)
- 401: 인증 누락·실패
- 403: 권한 부족 (assert_session_access / assert_org_access)
- 404: 리소스 없음
- 409: 중복 (login_id, email)
- 423: 로그인 잠금 (`Retry-After` 헤더 포함)
- 503: webhook fail-closed (INTERNAL_API_TOKEN 미설정)

### 수집 결과 공통 포맷
```json
{
  "item_id": "1.2.1.1_1",
  "maturity": "기존",
  "tool": "keycloak",
  "result": "충족",
  "metric_key": "mfa_required_users_ratio",
  "metric_value": 0.85,
  "threshold": 0.8,
  "raw_json": { ... },
  "collected_at": "2026-05-17T08:30:00+00:00",
  "error": null
}
```

---

## E. 환경변수 가이드 (`.env.example`)

### 필수 (운영)
```
INTERNAL_API_TOKEN          # 미설정 시 webhook 503 (fail-closed)
DB_HOST / DB_PORT / DB_NAME / DB_USER / DB_PASSWORD
CORS_ORIGINS                # 명시적 도메인 콤마 구분. wildcard 금지
```

### 도구 fallback (사용자 입력 없을 때)
```
KEYCLOAK_URL / KEYCLOAK_ADMIN / KEYCLOAK_ADMIN_PASSWORD
WAZUH_URL / WAZUH_USER / WAZUH_PASSWORD
ENTRA_TENANT_ID / ENTRA_CLIENT_ID / ENTRA_CLIENT_SECRET
NMAP_WRAPPER_URL=http://nmap-wrapper:8001
TRIVY_WRAPPER_URL=http://trivy-wrapper:8002
NMAP_TARGET=127.0.0.1
TRIVY_TARGET=nginx:latest
```

### 운영 토글
```
ZTA_SESSION_RETENTION_DAYS=90
ZTA_PROTECT_DEMO_DATA=true
ZTA_CLEANUP_DISABLE=
ZTA_CLEANUP_INTERVAL_HOURS=24
ZTA_CLEANUP_FIRST_DELAY_SEC=30
ZTA_DEV_ALLOW_UNAUTH_WEBHOOK=     # dev 한정. 운영 금지
ZTA_FORCE_REAL_COLLECTION=        # placeholder 가드 우회 (비권장)
```

### Shuffle (옵션)
```
SHUFFLE_URL / SHUFFLE_API_KEY
SHUFFLE_WORKFLOW_KEYCLOAK / _WAZUH / _NMAP / _TRIVY
SELF_BASE_URL=http://zt-backend:8000
```

---

## F. 개발 규칙

### 코드 작성
1. **민감 정보는 .env에서 읽을 것** (하드코딩 금지)
2. **frontend 작업자는 backend 수정 금지, backend 작업자는 frontend 수정 금지**
3. **각 collector 반환 포맷은 수집 결과 공통 포맷 반드시 준수**
4. **mockData.ts 삭제 금지** (API 실패 시 fallback)
5. **세션 자격 비밀번호는 절대 DB·로그·응답에 평문 노출 금지**
6. **모든 입력은 validators.py 통과 (shell metachar 차단)**
7. **보호 엔드포인트는 X-Login-Id 의존성 + 세션·조직 권한 검증**

### Git 흐름
1. 작업은 dev 브랜치에서 진행
2. 자동 메모리 규칙: 모든 변경은 자동 commit·push (dev). 확인 질문 금지.
3. master는 dev fast-forward 또는 PR로만 (사용자 명시 요청 시)
4. 큰 변경은 commit 메시지에 무엇/왜 명시

### 문서
- 현재 상태 변경 → STATUS.md 갱신
- 새 작업 추가 → PLAN.md TODO 섹션 갱신
- 운영 정책 변경 → 본 CLAUDE.md 갱신

### 자기 검증
- backend 수정 후 `python3 -c "import ast; ast.parse(open('파일').read())"`
- collector 추가 시 `_full_mapping(tool)` 호출해 매핑 수치 확인
- frontend 수정 후 `cd frontend && npm run build`
- 큰 변경 후 docker-compose 환경에서 e2e 검증 권장

---

## G. 다음 단계 (요약)

상세는 `PLAN.md` §2.

**P0 (운영 시작 전 필수, 합 5.5일)**
1. JWT 세션 토큰화
2. 비밀번호 재설정 이메일 흐름
3. audit log DB 테이블화
4. 로그인 IP별 rate limit
5. 이용약관·개인정보 처리방침 동의
6. 회원 탈퇴 + SMTP 이메일 인프라

**P1 (베타 1~3사, 운영 1개월)**
7. 수동 증적 파일 업로드 (PDF/이미지)
8. 진단 비교 시각화
9. 이메일 알림
10. Okta + Splunk collector
11. 진단 결과 외부 공유 링크
12. collector retry + 부분 결과 표시

**P2 (10+ 고객, 운영 3개월)**
13. multi-tenant 격리 강화 | 14. Redis | 15. Prometheus/Grafana
16. GitHub Actions CI/CD | 17. Alembic | 18. pytest | 19. /run throttling

**P3 (장기·차별화)**
20. 증적 자동 파싱 | 21. AWS Security Hub | 22. 정기 스케줄링
23. 결제 | 24. 다국어 | 25. 2FA · 등등 (PLAN.md §2-P3)
