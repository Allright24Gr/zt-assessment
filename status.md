# Readyz-T ZT Assessment — 전체 구현 현황 및 기능 명세

> 작성일: 2026-05-13 (최초: 2026-05-12, 최종 수정: 2026-05-13)  
> 현재 체크아웃: `dev`  
> 서버: EC2 `3.35.200.145` (Ubuntu 24.04, t3a.xlarge 4vCPU/16GB)

---

## 1. 브랜치 현황

| 브랜치 | 로컬 | 원격 | 마지막 커밋 | 담당 |
|--------|------|------|-------------|------|
| `master` | ✅ | ✅ | — | 최종 배포본 (직접 push 금지) |
| `dev` | ✅ | ✅ | `f95a1bb` Merge feature/nmap-trivy-wrapper | 통합 기준 |
| `feature/keycloak-collector` | ❌ | ✅ `e0fa919` | feat: wire assessment pipeline and API endpoints | 공나영 |
| `feature/wazuh-collector` | ❌ | ✅ `02879ea` | feat: implement wazuh_collector with 42 diagnostic functions | 공나영 (대리) |
| `feature/backend-skeleton` | ✅ | ✅ | — | 서진우 |
| `feature/nmap-trivy-wrapper` | ✅ | ✅ | — | 송민희 |

> **참고**: `feature/keycloak-collector`, `feature/wazuh-collector`는 원격에만 존재하며 로컬에 체크아웃되어 있지 않음.  
> **머지 완료**: 위 4개 feature 브랜치 모두 `dev`에 머지됨 (2026-05-13).

---

## 2. 디렉토리 구조

```
zt-assessment/
├── backend/
│   ├── main.py                        # FastAPI 앱 진입점, 라우터 6개 등록
│   ├── database.py                    # SQLAlchemy DB 연결
│   ├── models.py                      # DB 모델 10개
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── init.sql
│   ├── collectors/
│   │   ├── keycloak_collector.py      # ✅ 구현 완료 — 65개 함수
│   │   ├── wazuh_collector.py         # ✅ 구현 완료 — 122개 함수
│   │   ├── nmap_collector.py          # ✅ 구현 완료 — 14개 함수
│   │   └── trivy_collector.py         # ✅ 구현 완료 — 11개 함수
│   ├── routers/
│   │   ├── assessment.py              # ✅ 구현 완료 (4개 엔드포인트)
│   │   ├── score.py                   # ✅ 구현 완료 (3개 엔드포인트)
│   │   ├── checklist.py               # ✅ 구현 완료
│   │   ├── improvement.py             # ✅ 구현 완료
│   │   ├── manual.py                  # ⬜ TODO (NotImplementedError)
│   │   └── report.py                  # ⬜ TODO (NotImplementedError)
│   ├── scoring/
│   │   └── engine.py                  # ✅ 구현 완료 (threshold=0 버그 수정 완료)
│   └── scripts/
│       └── seed_checklist.py          # ✅ 체크리스트 DB 적재 스크립트 (xlsx → 새 item_id 포맷)
├── frontend/
│   ├── src/app/pages/
│   │   ├── Dashboard.tsx              # ✅ API 연동 완료 (fallback 포함)
│   │   ├── History.tsx                # ✅ API 연동 완료 (fallback 포함)
│   │   ├── NewAssessment.tsx          # ✅ API 연동 완료 (runAssessment 호출)
│   │   └── Reporting.tsx              # ✅ API 연동 완료 (fallback 포함)
│   ├── src/app/data/                  # mockData.ts, checklistItems.ts, constants.ts
│   ├── src/config/api.ts              # API 호출 함수
│   └── src/types/api.ts               # TypeScript 타입 정의
├── nmap-wrapper/
│   └── app.py                         # ✅ 구현 완료 — 10개 엔드포인트 (Flask)
├── trivy-wrapper/
│   └── app.py                         # ✅ 구현 완료 — 11개 엔드포인트 (Flask)
├── docker-compose.yml
└── CLAUDE.md
```

---

## 3. 포트 배분

| 포트 | 서비스 |
|------|--------|
| 8080 | 프론트엔드 (Nginx) |
| 8000 | 백엔드 (FastAPI) |
| 3000 | Shuffle UI |
| 8443 | Keycloak |
| 9201 | Wazuh Indexer / Elasticsearch (호스트 포트 9201 → 컨테이너 9200) |
| 55000 | Wazuh Manager API |
| 8001 | Nmap 래퍼 (호스트 포트 8001 → 컨테이너 5000) |
| 8002 | Trivy 래퍼 (호스트 포트 8002 → 컨테이너 5001) |
| 3306 | MySQL |

> Shuffle 서비스는 docker-compose.yml에서 주석 처리됨 (로컬 미사용).

---

## 4. DB 모델 (models.py)

10개 테이블, SQLAlchemy ORM.

| 테이블 | 주요 컬럼 | 설명 |
|--------|-----------|------|
| `Organization` | org_id, name, industry, size, cloud_type | 조직 정보 |
| `User` | user_id, org_id, name, email, role, mfa_enabled | 사용자 |
| `DiagnosisSession` | session_id, org_id, user_id, status(진행중/완료/오류), level, total_score, started_at, completed_at | 진단 세션 |
| `Checklist` | check_id, item_id, item_num, pillar, category, item_name, maturity, maturity_score, diagnosis_type, tool, weight | 진단 체크리스트 항목 (`question` 필드 제거, `item_num` 추가) |
| `CollectedData` | data_id, session_id, check_id, tool, metric_key, metric_value, threshold, raw_json, error | 수집 원시 데이터 |
| `Evidence` | evidence_id, session_id, check_id, source, observed, location, reason, impact | 증거 데이터 |
| `DiagnosisResult` | result_id, session_id, check_id, result(충족/부분충족/미충족/평가불가), score, recommendation | 진단 결과 |
| `MaturityScore` | score_id, session_id, pillar, score, level, pass_cnt, fail_cnt, na_cnt | pillar별 성숙도 점수 |
| `ImprovementGuide` | guide_id, check_id, pillar, task, priority(Critical/High/Medium/Low), term(단기/중기/장기), recommended_tool 등 | 개선 가이드 |
| `ScoreHistory` | history_id, session_id, org_id, pillar_scores(JSON), total_score, maturity_level, assessed_at | 점수 이력 |

---

## 5. API 엔드포인트 (backend/routers/)

### 5-1. Assessment (`/api/assessment`)

#### `POST /api/assessment/run`
진단 세션을 생성하고 Shuffle 워크플로우를 트리거한다.

**요청 파라미터 (query)**
```
org_id: int
user_id: int
```

**응답**
```json
{
  "session_id": 1,
  "status": "진행 중",
  "message": "진단이 시작되었습니다.",
  "started_at": "2026-05-12T00:00:00+00:00"
}
```

**내부 동작**
1. `DiagnosisSession` 레코드 생성 (status="진행 중")
2. `SHUFFLE_WORKFLOW_ID` 환경변수 있으면 Shuffle API `POST /api/v1/workflows/{id}/execute` 호출 (`httpx` 사용)
3. Shuffle 호출 실패해도 세션 ID는 반환 (fire-and-forget)

---

#### `POST /api/assessment/webhook`
Shuffle에서 수집 결과 배열을 수신하고, 완료 시 채점을 자동 트리거한다.

**요청 Body (JSON)**
```json
{
  "session_id": 1,
  "results": [
    {
      "item_id": "1.1.1_향상",
      "tool": "wazuh",
      "metric_key": "auth_failure_alert_count",
      "metric_value": 5.0,
      "threshold": 1.0,
      "raw_json": {},
      "error": null
    }
  ]
}
```

**내부 동작**
1. `results` 배열 순회 → `item_id`로 `Checklist` 조회
2. `CollectedData` upsert (기존 있으면 update, 없으면 insert)
3. 자동 진단 항목 전체 수집 완료 여부 확인 (`auto_total <= collected_count`)
4. 완료 시 `_trigger_scoring()` 호출:
   - `score_session()` 실행 → `DiagnosisResult`, `MaturityScore`, `ScoreHistory` upsert
   - `DiagnosisSession.status = "완료"`, `total_score`, `level` 업데이트

**응답**
```json
{ "status": "ok", "saved": 3 }
```

---

#### `GET /api/assessment/result?session_id={id}`
진단 결과 전체를 반환한다.

**응답**
```json
{
  "session": { "session_id": 1, "status": "완료", "level": "초기", "total_score": 1.75, ... },
  "pillar_scores": [
    { "pillar": "사용자", "score": 2.1, "level": "초기", "pass_cnt": 5, "fail_cnt": 3, "na_cnt": 1 }
  ],
  "overall_score": 1.75,
  "overall_level": "초기",
  "checklist_results": [
    { "item_id": "1.1.1_향상", "pillar": "사용자", "result": "충족", "score": 2.0, "recommendation": "" }
  ]
}
```

---

#### `GET /api/assessment/history?org_id={id}`
조직별 진단 세션 이력을 최신순으로 반환한다. `org_id` 생략 시 전체 반환.

---

### 5-2. Score (`/api/score`)

#### `GET /api/score/summary?session_id={id}`
pillar별 성숙도 점수 요약.

**응답**
```json
{
  "overall_score": 1.75,
  "overall_level": "초기",
  "pillar_scores": [{ "pillar": "사용자", "score": 2.1, "level": "초기", "pass_cnt": 5, ... }]
}
```

---

#### `GET /api/score/trend?org_id={id}&limit=12`
조직의 시간순 점수 추이 (최대 `limit`개).

---

#### `GET /api/score/checklist/{session_id}`
세션의 체크리스트 항목별 상세 점수.

---

### 5-3. Checklist (`/api/checklist`)

#### `GET /api/checklist/?pillar={pillar}&maturity={maturity}`
체크리스트 항목 목록. `pillar`, `maturity` 필터 선택 가능.

**응답 필드**: check_id, item_id, pillar, category, item_name, maturity, maturity_score, question, diagnosis_type, tool, weight, criteria, evidence

---

### 5-4. Improvement (`/api/improvement`)

#### `GET /api/improvement/?pillar=&term=&priority=`
개선 가이드 목록. 필터 선택 가능.

#### `GET /api/improvement/session/{session_id}`
세션의 미충족·부분충족 항목에 연결된 개선 가이드를 **우선순위(Critical→Low) + 기간(단기→장기) 순**으로 반환.

#### `GET /api/improvement/{guide_id}`
개선 가이드 상세 (연결된 체크리스트 항목 포함).

---

### 5-5. Manual (`/api/manual`) — ⬜ 미구현

#### `POST /api/manual/submit`
수동 진단 항목 결과 제출 (TODO).

---

### 5-6. Report (`/api/report`) — ⬜ 미구현

#### `GET /api/report/generate/{session_id}?fmt=json|pdf`
리포트 생성 (TODO).

---

### 5-7. Health

#### `GET /health`
```json
{ "status": "ok" }
```

---

## 6. 채점 엔진 (scoring/engine.py)

### 성숙도 레벨

| 점수 범위 | 레벨 |
|-----------|------|
| ≥ 3.5 | 최적화 |
| ≥ 2.5 | 향상 |
| ≥ 1.5 | 초기 |
| < 1.5 | 기존 |

### 단일 항목 채점 (`score_single_item`)

| 조건 | result | weight |
|------|--------|--------|
| `metric_value >= threshold` | 충족 | 1.0 |
| `metric_value >= threshold * 0.7` | 부분충족 | 0.5 |
| 미만 | 미충족 | 0.0 |
| error 있음 또는 값 누락 | 평가불가 | 0.0 |

`score = maturity_score × weight`

> ⚠️ **알려진 버그**: `threshold == 0`이면 값 누락으로 간주하여 강제로 "평가불가" 반환.  
> `cleartext_alert_count`, `critical_unfixed_count`, `high_risk_alert_count` 등 threshold=0인 항목이 항상 평가불가 처리됨. 수정 필요.

### 세션 채점 (`score_session`)

1. 항목별 `score_single_item` 실행
2. pillar별 점수 평균 → `pillar_scores`
3. pillar 점수 전체 평균 → `total_score`
4. `determine_maturity_level(total_score)` → `maturity_level`

### 추가 함수 (`generate_recommendations`)

미충족·부분충족 항목의 check_id를 기준으로 ImprovementGuide를 매핑하여 우선순위(Critical→Low) + 기간(단기→장기) 순으로 반환. assessment.py의 `_trigger_scoring()`에서 사용.

---

## 7. 수집 결과 공통 포맷

모든 collector 함수는 아래 형식을 반환해야 한다.

```python
{
    "item_id":      str,       # 체크리스트 항목 ID (예: "1.1.1.2_1" = 항목1.1.1, 초기(2), 질문1)
    "maturity":     str,       # 성숙도 단계 ("기존"|"초기"|"향상"|"최적화")
    "tool":         str,       # "keycloak" | "wazuh" | "nmap" | "trivy"
    "result":       str,       # "충족" | "부분충족" | "미충족" | "평가불가"
    "metric_key":   str,       # 측정 지표 키
    "metric_value": float,     # 측정값
    "threshold":    float,     # 기준값
    "raw_json":     dict,      # 원시 응답
    "collected_at": str,       # UTC ISO 8601
    "error":        str|None   # 오류 메시지
}
```

### item_id 포맷

`{항목번호}.{성숙도번호}_{질문번호}` — 예: `1.1.1.2_1`  
- 항목번호: `1.1.1` (xlsx `항목` 컬럼에서 첫 번째 공백 기준 앞부분)  
- 성숙도번호: 기존=1, 초기=2, 향상=3, 최적화=4  
- 질문번호: 동일 항목+성숙도 내 순서 (1부터)

---

## 8. Keycloak Collector

**파일**: `backend/collectors/keycloak_collector.py`  
**API**: Keycloak Admin REST API (`KEYCLOAK_URL/admin/realms/...`)  
**인증**: `POST /realms/master/protocol/openid-connect/token` → Bearer 토큰 (캐시)  
**SSL**: verify=True (기본)

### 환경변수

| 변수 | 설명 |
|------|------|
| `KEYCLOAK_URL` | Keycloak 서버 주소 (기본: `http://keycloak:8080`) |
| `KEYCLOAK_REALM` | 대상 realm (기본: `master`) |
| `KEYCLOAK_CLIENT_ID` | 클라이언트 ID (기본: `admin-cli`) |
| `KEYCLOAK_ADMIN_USER` | 관리자 계정 |
| `KEYCLOAK_ADMIN_PASS` | 관리자 비밀번호 |

### 내부 헬퍼

| 함수 | 설명 |
|------|------|
| `_get_admin_token()` | 토큰 발급·캐시 (expires_in 기준, 만료 30초 전 재발급) |
| `_kc_get(path, params)` | `GET {KEYCLOAK_URL}/admin/realms/{REALM}{path}` |
| `_now_iso()` | UTC ISO 8601 문자열 |
| `_make_result(...)` / `_unavailable(...)` | 공통 결과 dict 생성 |
| `_get_all_users()` | 전체 사용자 목록 수집 |
| `_active_human_users()` | 활성 사람 계정 필터 |
| `_flows_with_executions()` | 인증 흐름 + 실행기 목록 |
| `_get_authz_clients()` | 인가 서비스 활성 클라이언트 목록 |
| `_get_all_authz_policies()` | 전체 인가 정책 목록 |
| `_get_all_authz_permissions()` | 전체 인가 권한 목록 |

### collector 함수 목록 (65개)

| # | 함수명 | item_id 계열 | metric_key | threshold | API 엔드포인트 | 판정 기준 |
|---|--------|-------------|------------|-----------|----------------|-----------|
| 1 | `collect_user_role_ratio` | 사용자·역할 | user_role_ratio | 0.8 | `/users`, `/users/{id}/role-mappings/realm` | 역할 배정 사용자 비율 ≥ 0.8 |
| 2 | `collect_idp_inventory` | IdP 목록 | idp_count | 1 | `/identity-provider/instances` | IdP ≥ 1 |
| 3 | `collect_client_group_inventory` | 클라이언트·그룹 | client_group_count | 1 | `/clients`, `/groups` | client 또는 group ≥ 1 |
| 4 | `collect_idp_count` | IdP 수 | idp_total | 1 | `/identity-provider/instances` | total ≥ 1 |
| 5 | `collect_active_idp_count` | 활성 IdP | active_idp_count | 1 | `/identity-provider/instances` | enabled=true ≥ 1 |
| 6 | `collect_mfa_required` | MFA 필수 여부 | mfa_required | 1 | `/authentication/flows`, `/authentication/flows/{id}/executions` | MFA 실행기 REQUIRED 존재 |
| 7 | `collect_otp_flow` | OTP 흐름 | otp_flow_count | 1 | `/authentication/flows/{id}/executions` | OTP 실행기 REQUIRED |
| 8 | `collect_webauthn_status` | WebAuthn 상태 | webauthn_enabled | 1 | `/authentication/flows/{id}/executions` | WebAuthn 실행기 존재 |
| 9 | `collect_conditional_auth` | 조건부 인증 | conditional_auth_count | 1 | `/authentication/flows/{id}/executions` | conditional 실행기 존재 |
| 10 | `collect_session_policy` | 세션 정책 | session_policy_set | 1 | `/` (realm settings) | ssoSessionMaxLifespan ≤ 28800 |
| 11 | `collect_stepup_auth` | Step-up 인증 | stepup_flow_count | 1 | `/authentication/flows` | step-up flow 존재 |
| 12 | `collect_dynamic_auth_flow` | 동적 인증 흐름 | dynamic_flow_count | 1 | `/authentication/flows` | 커스텀 flow ≥ 1 |
| 13 | `collect_realm_count` | realm 수 | realm_count | 1 | `/` (GET all realms) | realm ≥ 2 (master 외) |
| 14 | `collect_icam_inventory` | ICAM 인벤토리 | icam_item_count | 3 | `/users`, `/clients`, `/identity-provider/instances`, `/groups` | 합산 ≥ 3 |
| 15 | `collect_custom_auth_flow` | 커스텀 인증 흐름 | custom_flow_count | 1 | `/authentication/flows` | builtIn=false flow ≥ 1 |
| 16 | `collect_idp_oidc_saml` | OIDC/SAML IdP | oidc_saml_idp_count | 1 | `/identity-provider/instances` | providerId in [oidc, saml] ≥ 1 |
| 17 | `collect_webauthn_users` | WebAuthn 사용자 | webauthn_user_count | 1 | `/users/{id}/credentials` | webauthn 자격증명 보유 사용자 ≥ 1 |
| 18 | `collect_context_policy` | 컨텍스트 정책 | context_policy_count | 1 | `/clients/{id}/authz/resource-server/policy` | type=time 또는 js 정책 ≥ 1 |
| 19 | `collect_authz_clients` | 인가 클라이언트 | authz_client_count | 1 | `/clients` | authorizationServicesEnabled=true 클라이언트 ≥ 1 |
| 20 | `collect_conditional_policy` | 조건부 정책 | conditional_policy_count | 1 | `/clients/{id}/authz/resource-server/policy` | type=aggregate 또는 js ≥ 1 |
| 21 | `collect_session_policy_advanced` | 고급 세션 정책 | advanced_session_policy | 1 | `/` realm + `/clients` | offlineSessionIdle 설정 여부 |
| 22 | `collect_aggregate_policy` | 집계 정책 | aggregate_policy_count | 1 | `/clients/{id}/authz/resource-server/policy` | type=aggregate ≥ 1 |
| 23 | `collect_resource_permission` | 리소스 권한 | resource_permission_count | 1 | `/clients/{id}/authz/resource-server/permission` | permission ≥ 1 |
| 24 | `collect_custom_roles` | 커스텀 역할 | custom_role_count | 1 | `/roles` | 시스템 역할 제외 custom role ≥ 1 |
| 25 | `collect_role_change_events` | 역할 변경 이벤트 | role_change_event_count | 1 | `/admin-events?operationType=CREATE,UPDATE,DELETE&resourceType=REALM_ROLE` | 이벤트 ≥ 1 |
| 26 | `collect_rbac_policy` | RBAC 정책 | rbac_policy_count | 1 | `/clients/{id}/authz/resource-server/policy` | type=role ≥ 1 |
| 27 | `collect_central_authz_policy` | 중앙 인가 정책 | central_authz_client_count | 1 | `/clients` | authorizationServicesEnabled=true ≥ 1 |
| 28 | `collect_abac_policy` | ABAC 정책 | abac_policy_count | 1 | `/clients/{id}/authz/resource-server/policy` | type=js 또는 time ≥ 1 |
| 29 | `collect_central_authz_ratio` | 중앙 인가 비율 | central_authz_ratio | 0.5 | `/clients` | authz 클라이언트 / 전체 클라이언트 비율 ≥ 0.5 |
| 30 | `collect_password_policy` | 비밀번호 정책 | password_policy_count | 3 | `/` (realm passwordPolicy) | 정책 항목 수 ≥ 3 |
| 31 | `collect_mfa_required_actions` | MFA Required Actions | mfa_action_count | 1 | `/authentication/required-actions` | CONFIGURE_TOTP 또는 webauthn-register enabled ≥ 1 |
| 32 | `collect_webauthn_credential_users` | WebAuthn 자격증명 사용자 수 | webauthn_credential_count | 1 | `/users/{id}/credentials` | webauthn 자격증명 보유 사용자 수 ≥ 1 |
| 33 | `collect_sso_clients` | SSO 클라이언트 | sso_client_count | 1 | `/clients` | standardFlowEnabled=true 클라이언트 ≥ 1 |
| 34–65 | (pillar 3~6 정책·인가·데이터 관련 함수) | — | — | — | — | 각 pillar의 중앙인가, ABAC, RBAC, 세션, 집계 정책, 컨텍스트, 데이터 접근 등 32개 추가 |

---

## 9. Wazuh Collector

**파일**: `backend/collectors/wazuh_collector.py`  
**API A (Manager API)**: `WAZUH_API_URL` (포트 55000) — JWT 인증  
**API B (Indexer API)**: `WAZUH_INDEXER_URL` (포트 9200) — Basic Auth  
**SSL**: `verify=False` (urllib3 경고 억제)

> Wazuh 4.8.0부터 Manager API의 `/vulnerability/`, `/alerts` 엔드포인트 제거됨.  
> 취약점 및 알림은 **반드시 Indexer(OpenSearch)로 조회**한다.

### 환경변수

| 변수 | 설명 |
|------|------|
| `WAZUH_API_URL` | Manager API 주소 (기본: `https://localhost:55000`) |
| `WAZUH_API_USER` | Manager API 계정 |
| `WAZUH_API_PASS` | Manager API 비밀번호 |
| `WAZUH_INDEXER_URL` | Indexer 주소 (기본: `https://localhost:9200`) |
| `WAZUH_INDEXER_USER` | Indexer 계정 |
| `WAZUH_INDEXER_PASS` | Indexer 비밀번호 |

### 내부 헬퍼

| 함수 | 설명 |
|------|------|
| `_get_wazuh_token()` | JWT 토큰 발급·캐시 (900초, 만료 30초 전 재발급). `POST /security/user/authenticate` |
| `_get_indexer_session()` | Basic Auth `requests.Session` 싱글턴 반환 |
| `_indexer_count(index, query)` | `POST {index}/_search` size=0 → `hits.total.value` |
| `_indexer_search(index, query)` | `POST {index}/_search` → 전체 응답 dict |
| `_wazuh_get(path, params)` | Bearer JWT로 Manager API GET |
| `_get_active_agents()` | `GET /agents?status=active` 페이지네이션 전체 수집 |
| `_get_all_agents()` | `GET /agents` 페이지네이션 전체 수집 |
| `_err(...)` | result="평가불가" 공통 반환 |
| `_ok(...)` | 정상 결과 공통 반환 |
| `_parse_dt(s)` | ISO 8601 문자열 → datetime (Z 처리 포함) |

### 추가 헬퍼 (DRY 패턴)

| 함수 | 설명 |
|------|------|
| `_indexer_alert_count(groups, window)` | 그룹 목록으로 인덱서 알림 수 집계 |
| `_rule_and_alert(...)` | rule 존재 여부 + 알림 수 패턴 |
| `_alert_only(...)` | 알림 수만으로 판정하는 패턴 |

### collector 함수 목록 (122개)

함수 1–42는 이전과 동일. 43–122는 아래 영역 추가:

| 영역 | 함수 수 | 대표 함수 |
|------|---------|-----------|
| 인증 자동화·동적 접근 | 6 | collect_auto_reauth, collect_icam_automation, collect_dynamic_access_policy |
| 기기·엔드포인트 | 4 | collect_device_security_check, collect_endpoint_central_policy |
| 네트워크 세그먼테이션 | 14 | collect_macro_segment_*, collect_micro_segment_*, collect_static_network_rules |
| 앱·TLS·데이터 흐름 | 7 | collect_tls_coverage, collect_auto_data_flow_map, collect_abnormal_data_movement |
| 복구·연속성 | 3 | collect_network_continuity, collect_auto_recovery |
| PAM·접근 관리 | 5 | collect_pam_basic, collect_pam_policy, collect_pam_monitor |
| 워크로드·정책 자동화 | 12 | collect_workload_segment_policy, collect_system_policy_basic, collect_autonomous_policy |
| 앱·배포 파이프라인 | 6 | collect_deploy_pipeline_monitor, collect_app_inventory_auto |
| 데이터 거버넌스·암호화 | 15 | collect_data_risk_monitor, collect_data_encryption_*, collect_dlp_* |
| 데이터 활동 모니터링 | 8 | collect_data_activity_monitor, collect_data_anomaly_detect, collect_data_context_access |

---

### 이전 collector 함수 목록 (1–42)

#### 인증·사용자 행동 영역 (항목 1~8)

| # | 함수명 | item_id 계열 | metric_key | threshold | API | 판정 |
|---|--------|-------------|------------|-----------|-----|------|
| 1 | `collect_auth_failure_alerts` | 1.1.1_향상 | auth_failure_alert_count | 1 | Manager /rules + Indexer wazuh-alerts-* | rule 활성화 AND 24h 내 알림 ≥ 1 → 충족 |
| 2 | `collect_active_response_auth` | 1.2.1_최적화 | auth_autoresponse_count | 1 | Manager /rules + /active-response | rule ≥ 1 AND AR ≥ 1 → 충족 |
| 3 | `collect_agent_sca_ratio` | 1.2.2_기존 | sca_collection_ratio | 0.8 | Manager /agents + /sca/{id} | SCA 보유 에이전트 비율 ≥ 0.8 |
| 4 | `collect_sca_average` | 1.3.1_초기 | sca_avg_score | 70 | Manager /agents + /sca/{id} | SCA 평균 점수: ≥70 충족, ≥50 부분충족 |
| 5 | `collect_high_risk_alerts` | 1.3.1_최적화 | high_risk_alert_count | 0 | Indexer wazuh-alerts-* (level ≥ 10, 1h) | count ≥ 1 AND 처리지연 ≤ 60s → 충족 |
| 6 | `collect_behavior_alerts` | 1.3.2_향상 | behavior_alert_count | 1 | Manager /rules + Indexer (authentication/anomaly, 24h) | rule AND count ≥ 1 → 충족 |
| 7 | `collect_activity_rules` | 1.4.1_기존 | activity_rule_count | 1 | Manager /agents + /rules?search=syslog | agent ≥ 1 AND rule ≥ 1 → 충족 |
| 8 | `collect_privilege_change_alerts` | 1.4.2_향상 | privilege_change_alert_count | 1 | Manager /rules + Indexer (policy_changed/privilege_escalation, 30d) | rule AND count ≥ 1 → 충족 |

#### 기기·컴플라이언스 영역 (항목 9~14)

| # | 함수명 | item_id 계열 | metric_key | threshold | API | 판정 |
|---|--------|-------------|------------|-----------|-----|------|
| 9 | `collect_sca_compliance` | 2.1.1_초기 | sca_active_ratio | 0.9 | Manager /agents + /sca/{id} | SCA 보유 비율: ≥0.9 충족, ≥0.5 부분충족 |
| 10 | `collect_policy_violation_alerts` | 2.1.1_초기(비준수) | policy_violation_count | 1 | Indexer (policy_violation) + Manager /active-response | alert ≥ 1 AND AR ≥ 1 → 충족 |
| 11 | `collect_sca_auto_remediation` | 2.1.1_향상 | sca_autofix_count | 1 | Manager /agents + /sca/{id} + /active-response | sca_avg ≥ 70 AND AR ≥ 1 → 충족 |
| 12 | `collect_os_inventory` | 2.2.1_기존 | os_inventory_ratio | 0.9 | Manager /agents + /syscollector/{id}/os | OS 정보 수집 비율 ≥ 0.9 |
| 13 | `collect_sca_access_control` | 2.2.1_향상 | sca_pass_ratio | 0.8 | Manager /agents + /sca/{id} | score ≥ 70인 SCA 비율 ≥ 0.8 |
| 14 | `collect_auto_block` | 2.2.1_최적화 | auto_block_count | 1 | Manager /active-response + /agents?status=disconnected | AR ≥ 1 AND disconnected ≥ 1 → 충족 |

#### 에이전트·인벤토리 영역 (항목 15~23)

| # | 함수명 | item_id 계열 | metric_key | threshold | API | 판정 |
|---|--------|-------------|------------|-----------|-----|------|
| 15 | `collect_agent_registration` | 2.3.1_기존 | agent_registration_ratio | 1 | Manager /agents | 전체 에이전트 ≥ 1 → 충족 |
| 16 | `collect_agent_keepalive` | 2.3.1_초기 | keepalive_ratio | 0.9 | Manager /agents | lastKeepAlive 24h 이내 비율 ≥ 0.9 |
| 17 | `collect_unauthorized_device_alerts` | 2.3.1_향상(미승인) | unauthorized_device_count | 1 | Manager /rules + Indexer (unauthorized_device/new_agent) | rule AND count ≥ 1 → 충족 |
| 18 | `collect_vulnerability_summary` | 2.3.1_향상(취약점) | vuln_scan_agent_count | 1 | Manager /agents + Indexer wazuh-states-vulnerabilities-* | scan 데이터 있는 에이전트 ≥ 1 |
| 19 | `collect_realtime_monitoring` | 2.3.1_최적화 | realtime_alert_count | 1 | Indexer wazuh-alerts-* (1h) | count ≥ 1 AND 처리지연 ≤ 60s → 충족 |
| 20 | `collect_os_distribution` | 2.3.2_기존 | agent_os_count | 1 | Manager /agents | OS 종류(linux/windows/darwin) 2종 이상 → 충족 |
| 21 | `collect_sca_policy_ratio` | 2.3.2_기존(정책) | sca_policy_ratio | 0.8 | Manager /agents + /sca/{id} | SCA 보유 비율 ≥ 0.8 → 충족 |
| 22 | `collect_continuous_monitoring` | 2.3.2_초기 | continuous_monitor_ratio | 0.9 | Manager /agents | lastKeepAlive 1h 이내 비율 ≥ 0.9 |
| 23 | `collect_auto_threat_response` | 2.3.2_최적화 | auto_threat_response_count | 1 | Manager /active-response | AR ≥ 1 AND 최근 30일 내 실행 ≥ 1 → 충족 |

#### EDR·취약점 영역 (항목 24~28)

| # | 함수명 | item_id 계열 | metric_key | threshold | API | 판정 |
|---|--------|-------------|------------|-----------|-----|------|
| 24 | `collect_edr_agents` | 2.4.1_기존 | edr_agent_count | 1 | Manager /agents | version 필드 있는 활성 에이전트 ≥ 1 → 충족 |
| 25 | `collect_threat_detection_alerts` | 2.4.1_초기 | threat_detection_count | 1 | Indexer (malware/rootcheck/virus, 24h) + Manager /active-response | alert ≥ 1 AND AR ≥ 1 → 충족 |
| 26 | `collect_vuln_asset_list` | 2.4.2_기존 | vuln_asset_count | 1 | Manager /agents + Indexer wazuh-states-vulnerabilities-* | scan 있는 에이전트 ≥ 1 → 충족 |
| 27 | `collect_vuln_scan_ratio` | 2.4.2_향상 | vuln_scan_ratio | 0.9 | Manager /agents + Indexer (24h 내 취약점 스캔) | scan 에이전트 비율 ≥ 0.9 |
| 28 | `collect_critical_unfixed_vulns` | 2.4.2_최적화 | critical_unfixed_count | 0 | Manager /agents + Indexer (severity=critical, status=VULNERABLE) | unfixed=0 → 충족, ≤5 → 부분충족, >5 → 미충족 |

#### 네트워크·세그먼트 영역 (항목 29~34)

| # | 함수명 | item_id 계열 | metric_key | threshold | API | 판정 |
|---|--------|-------------|------------|-----------|-----|------|
| 29 | `collect_segment_policy_alerts` | 3.1.1_초기 | segment_policy_alert_count | 1 | Manager /rules + Indexer (network_policy) | rule AND count ≥ 1 → 충족 |
| 30 | `collect_lateral_movement_alerts` | 3.1.2_초기 | lateral_movement_count | 1 | Indexer (lateral_movement/network_scan) + Manager /active-response | AR ≥ 1 AND alert ≥ 1 → 충족 |
| 31 | `collect_ids_alerts` | 3.2.1_기존 | ids_alert_count | 1 | Manager /rules + Indexer (ids/intrusion_detection, 24h) | rule AND count ≥ 1 → 충족 |
| 32 | `collect_attack_response` | 3.2.1_초기 | attack_response_count | 1 | Indexer (attack) + Manager /active-response | alert ≥ 1 AND AR ≥ 1 → 충족 |
| 33 | `collect_realtime_threat_alerts` | 3.2.1_향상 | realtime_threat_count | 1 | Indexer (level ≥ 7, 1h) | count ≥ 1 AND 처리지연 ≤ 60s → 충족 |
| 34 | `collect_tls_cleartext_alerts` | 3.3.1_초기 | cleartext_alert_count | 0 | Manager /rules + Indexer (cleartext/unencrypted) | rule 존재 여부만으로 판정 |

#### 복구·가용성 영역 (항목 35~36)

| # | 함수명 | item_id 계열 | metric_key | threshold | API | 판정 |
|---|--------|-------------|------------|-----------|-----|------|
| 35 | `collect_backup_history` | 3.5.1_기존 | backup_history_count | 1 | Manager /agents | lastKeepAlive 24h 이내 에이전트 ≥ 1 → 충족 |
| 36 | `collect_agent_uptime` | 3.5.1_향상 | agent_uptime_ratio | 0.99 | Manager /agents | active 비율 ≥ 0.99 → 충족, ≥ 0.95 → 부분충족 |

#### 정책·권한 변경 영역 (항목 37~39)

| # | 함수명 | item_id 계열 | metric_key | threshold | API | 판정 |
|---|--------|-------------|------------|-----------|-----|------|
| 37 | `collect_policy_change_alerts` | 4.1.1_초기 | policy_change_alert_count | 1 | Manager /rules + Indexer (policy_changed) | count ≥ 1 → 충족, rule 있고 count=0 → 부분충족 |
| 38 | `collect_privilege_escalation_alerts` | 4.2.1_초기 | privilege_alert_count | 1 | Manager /rules + Indexer (privilege_escalation/admin_access) | rule AND count ≥ 1 → 충족 |
| 39 | `collect_abnormal_privilege_alerts` | 4.2.1_향상 | abnormal_privilege_count | 1 | Manager /rules + Indexer (privilege_escalation AND level ≥ 7) | rule AND count ≥ 1 → 충족 |

#### FIM·데이터 보호 영역 (항목 40~42)

| # | 함수명 | item_id 계열 | metric_key | threshold | API | 판정 |
|---|--------|-------------|------------|-----------|-----|------|
| 40 | `collect_fim_status` | 6.1.1_초기(카탈로그) | fim_active_count | 1 | Manager /agents + /syscheck/{id} | syscheck 이벤트 보유 에이전트 ≥ 1 → 충족 |
| 41 | `collect_fim_collection_ratio` | 6.1.1_초기(자동수집) | fim_collection_ratio | 0.8 | Manager /agents + /syscheck/{id} | syscheck 보유 비율 ≥ 0.8 → 충족 |
| 42 | `collect_dlp_alerts` | 6.5.1_초기 | dlp_alert_count | 1 | Manager /rules + Indexer (data_loss/exfiltration) | rule AND count ≥ 1 → 충족 |

### 단위 테스트 (if __name__ == "__main__")

파일 하단에 `unittest` 기반 테스트 14개 클래스, 33개 케이스 포함.  
실행: `python3 backend/collectors/wazuh_collector.py`  
네트워크 없이 실행 가능 (unittest.mock으로 HTTP 응답 모킹).

| 테스트 클래스 | 케이스 수 | 검증 내용 |
|--------------|----------|-----------|
| `TestTokenCache` | 3 | 토큰 최초 발급, 캐시 재사용, 만료 후 재발급 |
| `TestCollectAuthFailureAlerts` | 4 | 충족/부분충족/미충족/평가불가 |
| `TestCollectActiveResponseAuth` | 3 | 충족/부분충족/미충족 |
| `TestCollectScaAverage` | 3 | 충족/부분충족/평가불가(에이전트 0) |
| `TestCollectHighRiskAlerts` | 3 | 충족(최신 알림)/부분충족(오래된 알림)/부분충족(알림 0) |
| `TestCollectAgentRegistration` | 2 | 충족/미충족 |
| `TestCollectAgentKeepalive` | 2 | 충족/미충족 |
| `TestCollectVulnerabilitySummary` | 1 | 충족 |
| `TestCollectCriticalUnfixedVulns` | 3 | 충족(0개)/부분충족(3개)/미충족(10개) |
| `TestCollectEdrAgents` | 2 | 충족/미충족 |
| `TestCollectTlsCleartextAlerts` | 2 | 충족(룰 있음)/미충족(룰 없음) |
| `TestCollectAgentUptime` | 2 | 충족(100% active)/미충족(90%) |
| `TestCollectFimStatus` | 2 | 충족/부분충족(FIM 데이터 없음) |
| `TestIndexerSession` | 1 | 싱글턴 동일 객체 반환 |

---

## 10. Nmap 래퍼 (nmap-wrapper/app.py) — ✅ 구현 완료

**포트**: 8001 (호스트) → 5000 (컨테이너)  
**인증**: 없음 (내부 서비스)  
**권한**: `cap_add: NET_RAW, NET_ADMIN` (docker-compose 적용됨)

| 엔드포인트 | 항목 | metric_key | 설명 |
|-----------|------|------------|------|
| `POST /scan/ports` | 2.1.1_기존, 3.1.1_기존 | open_port_count | `-p {ports} --open` 포트 스캔 |
| `POST /scan/tls` | 3.3.1_기존 | tls_covered_ratio | `--script ssl-cert` TLS 적용 비율 |
| `POST /scan/subnets` | 3.1.1_기존, 4.3.1_기존 | subnet_count | `-sn` 서브넷 검색 |
| `POST /scan/hosts` | 2.1.1_기존 | host_discovery_ratio | `-sn` 활성 호스트 비율 |
| `POST /scan/port-distribution` | 3.1.2_기존 | port_distribution_variance | 호스트별 포트 분산값 |
| `POST /scan/tls-version` | 3.3.1_향상 | tls13_ratio | `--script ssl-enum-ciphers` TLS 1.3 비율 |
| `POST /scan/services` | 3.4.1_초기 | service_mapping_count | `-sV` 서비스 식별 수 |
| `POST /scan/redundancy` | 3.5.1_초기 | redundancy_path_count | 동일 서비스 포트 열린 호스트 수 |
| `POST /scan/vpn` | 5.3.1_기존 | vpn_port_count | VPN 포트(1194/500/4500 등) 개방 여부 |
| `POST /scan/vulnerable-services` | 2.4.2_초기 | vulnerable_service_count | `-sV` 알려진 취약 버전 서비스 수 |

---

## 11. Trivy 래퍼 (trivy-wrapper/app.py) — ✅ 구현 완료

**포트**: 8002 (호스트) → 5001 (컨테이너)  
**캐시**: `trivy-cache` 볼륨 마운트 (DB 재다운로드 방지)  
**환경변수**: `TRIVY_NO_PROGRESS=true`  
**볼륨**: `/var/run/docker.sock` (이미지 스캔용)

| 엔드포인트 | 항목 | metric_key | 설명 |
|-----------|------|------------|------|
| `POST /scan/image` | 5.4.1_초기 | critical_high_vuln_count | 이미지 Critical+High 취약점 수 |
| `POST /scan/fs` | 5.5.1_초기 | fs_vuln_count | 파일시스템 취약점 스캔 |
| `POST /scan/sbom` | 5.5.1_초기 | sbom_component_count | SPDX-JSON SBOM 컴포넌트 수 |
| `POST /scan/cicd` | 5.4.1_초기 | cicd_scan_ratio | 다중 이미지 스캔 완료 비율 |
| `POST /scan/integrity` | 5.4.1_초기 | integrity_check_count | 코드 무결성 검사 수행 여부 |
| `POST /scan/compliance` | 5.4.1_향상 | fixable_critical_count | 패치 가능한 Critical 위반 수 |
| `POST /scan/coverage` | 5.4.1_향상 | component_scan_ratio | 전체 대상 스캔 완료 비율 |
| `POST /scan/third-party` | 5.5.1_향상 | third_party_critical_count | 서드파티 라이브러리 Critical 수 |
| `POST /scan/sbom-full` | 5.5.1_향상 | full_sbom_count | 전 주기 SBOM 생성 성공 수 |
| `POST /scan/risk` | 5.5.2_초기 | risk_scan_count | 소프트웨어 위험 평가 수행 여부 |
| `POST /scan/supply-chain` | 5.5.2_향상 | supply_chain_scan_count | SBOM 기반 공급망 스캔 수행 여부 |

---

## 10. Nmap Collector — ✅ 구현 완료 (14개 함수)

**파일**: `backend/collectors/nmap_collector.py`  
**환경변수**: `NMAP_WRAPPER_URL` (기본: `http://localhost:8001`), `NMAP_TARGET` (기본: `127.0.0.1`)

| # | 함수명 | item_id | metric_key | threshold | 엔드포인트 |
|---|--------|---------|------------|-----------|-----------|
| 1 | `collect_host_discovery` | 2.1.1.1_1 | identified_host_count | 1.0 | POST /scan/ports |
| 2 | `collect_port_service_map` | 2.4.2.2_1 | scan_performed | 1.0 | POST /scan/ports |
| 3 | `collect_subnet_topology` | 3.1.1.1_1 | subnet_count | 2.0 | POST /scan/subnets |
| 4 | `collect_subnet_traffic_map` | 3.1.1.1_2 | subnet_count | 2.0 | POST /scan/subnets |
| 5 | `collect_micro_segment_ports` | 3.1.2.1_1 | unique_port_profile_count | 2.0 | POST /scan/ports |
| 6 | `collect_tls_ratio` | 3.3.1.1_1 | tls_ratio | 0.5 | POST /scan/tls |
| 7 | `collect_tls_services` | 3.3.1.1_2 | tls_service_count | 1.0 | POST /scan/tls |
| 8 | `collect_tls_advanced` | 3.3.1.3_2 | tls13_ratio | 0.8 | POST /scan/tls |
| 9 | `collect_app_traffic_map` | 3.4.1.2_1 | service_map_count | 1.0 | POST /scan/ports |
| 10 | `collect_network_redundancy` | 3.5.1.2_3 | redundant_subnet_count | 2.0 | POST /scan/subnets |
| 11 | `collect_subnet_segmentation` | 4.3.1.1_1 | subnet_count | 2.0 | POST /scan/subnets |
| 12 | `collect_perimeter_model` | 4.3.1.1_2 | open_port_count | 1.0 | POST /scan/ports |
| 13 | `collect_system_subnet_separation` | 4.3.1.2_1 | subnet_count | 2.0 | POST /scan/subnets |
| 14 | `collect_vpn_ports` | 5.3.1.1_1 | vpn_port_count | 1.0 | POST /scan/ports (500,1194,1723,4500) |

---

## 11. Trivy Collector — ✅ 구현 완료 (11개 함수)

**파일**: `backend/collectors/trivy_collector.py`  
**환경변수**: `TRIVY_WRAPPER_URL` (기본: `http://localhost:8002`), `TRIVY_TARGET` (기본: `.`)

| # | 함수명 | item_id | metric_key | threshold | 엔드포인트 |
|---|--------|---------|------------|-----------|-----------|
| 1 | `collect_image_scan` | 6.1.1.1_1 | critical_high_vuln_count | 0.0 | POST /scan/image |
| 2 | `collect_cicd_scan_ratio` | 6.1.1.2_1 | scan_ratio | 0.8 | POST /scan/image |
| 3 | `collect_integrity_check` | 6.1.1.3_1 | integrity_check_passed | 1.0 | POST /scan/image |
| 4 | `collect_policy_compliance_scan` | 6.2.1.1_1 | compliance_pass_ratio | 0.8 | POST /scan/fs |
| 5 | `collect_full_component_scan` | 6.2.1.2_1 | component_count | 1.0 | POST /scan/fs |
| 6 | `collect_fs_scan` | 6.3.1.1_1 | fs_vuln_count | 0.0 | POST /scan/fs |
| 7 | `collect_sbom` | 6.4.1.1_1 | sbom_component_count | 1.0 | POST /scan/sbom |
| 8 | `collect_dependency_scan` | 6.4.1.2_1 | dependency_vuln_count | 0.0 | POST /scan/sbom |
| 9 | `collect_sbom_full` | 6.4.1.3_1 | sbom_component_count | 10.0 | POST /scan/sbom |
| 10 | `collect_risk_scan` | 6.5.1.1_1 | risk_score | 50.0 | POST /scan/image |
| 11 | `collect_supply_chain_scan` | 6.5.1.2_1 | supply_chain_vuln_count | 0.0 | POST /scan/sbom |

---

## 12. Nmap 래퍼 (nmap-wrapper/app.py) — ✅ 구현 완료

**포트**: 8001 (호스트) → 5000 (컨테이너)  
**인증**: 없음 (내부 서비스)  
**권한**: `cap_add: NET_RAW, NET_ADMIN` (docker-compose 적용됨)

| 엔드포인트 | metric_key | 설명 |
|-----------|------------|------|
| `POST /scan/ports` | open_port_count | `-p {ports} --open` 포트 스캔 |
| `POST /scan/tls` | tls_covered_ratio | `--script ssl-cert` TLS 적용 비율 |
| `POST /scan/subnets` | subnet_count | `-sn` 서브넷 검색 |

---

## 13. Trivy 래퍼 (trivy-wrapper/app.py) — ✅ 구현 완료

**포트**: 8002 (호스트) → 5001 (컨테이너)  
**캐시**: `trivy-cache` 볼륨 마운트 (DB 재다운로드 방지)  
**환경변수**: `TRIVY_NO_PROGRESS=true`  
**볼륨**: `/var/run/docker.sock` (이미지 스캔용)

| 엔드포인트 | metric_key | 설명 |
|-----------|------------|------|
| `POST /scan/image` | critical_high_vuln_count | 이미지 Critical+High 취약점 수 |
| `POST /scan/fs` | fs_vuln_count | 파일시스템 취약점 스캔 |
| `POST /scan/sbom` | sbom_component_count | SPDX-JSON SBOM 컴포넌트 수 |

---

## 14. 프론트엔드 API 연동 현황

| 페이지 | 상태 | 연동 API | fallback |
|--------|------|----------|---------|
| `Dashboard.tsx` | ✅ 완료 | `getScoreSummary()`, `getAssessmentHistory()`, `getImprovement()` | mockData |
| `History.tsx` | ✅ 완료 | `getAssessmentHistory()` | mockSessions |
| `NewAssessment.tsx` | ✅ 완료 | `runAssessment()` → `navigate(/in-progress/{session_id})` | navigate("/in-progress/new-session") |
| `Reporting.tsx` | ✅ 완료 | `getAssessmentResult(sessionId)`, `getImprovement(sessionId)` | mockData |

---

## 15. 미구현 및 알려진 이슈

### 미구현 항목

| 파일 | 상태 | 내용 |
|------|------|------|
| `backend/routers/manual.py` | ⬜ TODO | `POST /api/manual/submit` — 수동 진단 결과 제출 |
| `backend/routers/report.py` | ⬜ TODO | `GET /api/report/generate/{session_id}` — JSON/PDF 리포트 |

### 알려진 이슈

| 파일 | 심각도 | 내용 |
|------|--------|------|
| `seed_checklist.py` | 🟡 낮음 | 루트(`/`)와 `backend/scripts/` 두 곳에 중복 존재. 루트 파일 삭제 또는 git에서 추적 제외 필요. |

---

## 16. 환경변수 전체 목록

| 변수 | 설명 | 기본값 |
|------|------|--------|
| `KEYCLOAK_URL` | Keycloak 주소 | `http://keycloak:8080` |
| `KEYCLOAK_REALM` | 대상 realm | `master` |
| `KEYCLOAK_CLIENT_ID` | 클라이언트 ID | `admin-cli` |
| `KEYCLOAK_ADMIN_USER` | 관리자 계정 | — |
| `KEYCLOAK_ADMIN_PASS` | 관리자 비밀번호 | — |
| `WAZUH_API_URL` | Wazuh Manager API | `https://localhost:55000` |
| `WAZUH_API_USER` | Manager 계정 | `wazuh` |
| `WAZUH_API_PASS` | Manager 비밀번호 | `wazuh` |
| `WAZUH_INDEXER_URL` | Wazuh Indexer | `https://localhost:9200` |
| `WAZUH_INDEXER_USER` | Indexer 계정 | `admin` |
| `WAZUH_INDEXER_PASS` | Indexer 비밀번호 | `admin` |
| `NMAP_WRAPPER_URL` | Nmap 래퍼 주소 | `http://localhost:8001` |
| `NMAP_TARGET` | Nmap 스캔 대상 IP/대역 | `127.0.0.1` |
| `TRIVY_WRAPPER_URL` | Trivy 래퍼 주소 | `http://localhost:8002` |
| `TRIVY_TARGET` | Trivy 스캔 대상 경로/이미지 | `.` |
| `SHUFFLE_URL` | Shuffle 주소 | `http://shuffle:3000` |
| `SHUFFLE_WORKFLOW_ID` | 실행할 워크플로우 ID | — |
| `SHUFFLE_API_KEY` | Shuffle API 키 | — |
| `CORS_ORIGINS` | CORS 허용 도메인 (콤마 구분) | `*` |
| `VITE_API_BASE` | 프론트엔드 API 베이스 URL | `http://3.35.200.145:8000` |

---

## 17. 동작 확인 체크리스트

### 백엔드 기본 동작

```bash
# 헬스체크
curl http://3.35.200.145:8000/health
# → {"status": "ok"}

# 체크리스트 조회
curl "http://3.35.200.145:8000/api/checklist/"

# 특정 pillar 필터
curl "http://3.35.200.145:8000/api/checklist/?pillar=사용자"

# 진단 세션 시작
curl -X POST "http://3.35.200.145:8000/api/assessment/run?org_id=1&user_id=1"

# 결과 조회
curl "http://3.35.200.145:8000/api/assessment/result?session_id=1"

# 점수 요약
curl "http://3.35.200.145:8000/api/score/summary?session_id=1"

# 점수 추이
curl "http://3.35.200.145:8000/api/score/trend?org_id=1"

# 개선 권고 (세션별)
curl "http://3.35.200.145:8000/api/improvement/session/1"
```

### Nmap 래퍼 테스트

```bash
curl -X POST "http://3.35.200.145:8001/scan/ports" \
  -H "Content-Type: application/json" \
  -d '{"target_ip": "3.35.200.145", "ports": "80,443,8000,8080", "item_id": "2.1.1_기존"}'
```

### Trivy 래퍼 테스트

```bash
curl -X POST "http://3.35.200.145:8002/scan/image" \
  -H "Content-Type: application/json" \
  -d '{"image_name": "nginx:latest", "item_id": "5.4.1_초기"}'
```

### Wazuh Collector 단위 테스트 (mock, 네트워크 불필요)

```bash
python3 backend/collectors/wazuh_collector.py
# → Ran 33 tests in 0.022s OK
```

### Webhook 수동 테스트

```bash
curl -X POST "http://3.35.200.145:8000/api/assessment/webhook" \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": 1,
    "results": [
      {
        "item_id": "1.1.1_향상",
        "tool": "wazuh",
        "metric_key": "auth_failure_alert_count",
        "metric_value": 5.0,
        "threshold": 1.0,
        "raw_json": {},
        "error": null
      }
    ]
  }'
```

---

## 18. 주의사항 (CLAUDE.md 요약)

- 모든 민감 정보는 `.env` 환경변수로 관리. **하드코딩 금지**
- `frontend/` ↔ `backend/` 크로스 수정 금지
- `mockData.ts` 삭제 금지 (API 실패 시 fallback 용도)
- collector 반환 포맷은 위 공통 포맷 **반드시** 준수
- 작업 완료 후 반드시 자기 feature 브랜치에 push
- `main` 브랜치 직접 push 금지
