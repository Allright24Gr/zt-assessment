# Readyz-T — Zero Trust Assessment Platform

> **What is this?**
> 한국 제로트러스트 가이드라인 2.0 기반의 보안 성숙도 진단 자동화 플랫폼.
> 웹 UI로 진단 신청 → SOAR가 보안 도구 자동 수집 → 점수화 → 보고서(PDF) 생성까지 전 과정을 자동화함.

---

## 0. 한눈에 보기

| 항목 | 내용 |
|---|---|
| 진단 기준 | 한국 제로트러스트 가이드라인 2.0 — 6대 필러(신원/기기/네트워크/시스템/애플리케이션/데이터) |
| 성숙도 단계 | 기존(1) → 초기(2) → 향상(3) → 최적화(4) — 4단계 |
| 자동 진단 도구 | Keycloak(IAM), Wazuh(SIEM/EDR), Nmap(네트워크), Trivy(컨테이너) |
| 수동 진단 | 웹 설문 또는 Excel 업로드 |
| 오케스트레이션 | Shuffle SOAR (옵션) — 미설정 시 백엔드가 직접 collector 실행 |
| 출력물 | 대시보드(점수/추이/취약점), 진단 보고서(PDF, NanumGothic) |
| 배포 | Docker Compose (단일 EC2 t3a.xlarge 권장) |

```
                       ┌────────────────────┐
   사용자  ───── 진단 신청 ───►  Frontend (React)  ─── REST API ──┐
                       └────────────────────┘                    │
                                                                 ▼
                       ┌──────────────────────────────────────────────┐
                       │           Backend (FastAPI)                  │
                       │  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
                       │  │ Router   │  │ Scoring  │  │ Report   │    │
                       │  └──────────┘  └──────────┘  └──────────┘    │
                       └──────┬──────────────┬─────────────────┬──────┘
                              │              │                 │
                  Shuffle SOAR │   직접 호출  │           MySQL │
                       (옵션)  │   (fallback) │            DB   │
                              ▼              ▼                 │
                       ┌──────────────────────────┐            │
                       │   Collectors (Python)    │            │
                       │ Keycloak / Wazuh         │────────────┘
                       │ Nmap-Wrapper / Trivy-Wrapper          │
                       └──────────────────────────┘
```

---

## 1. 디렉토리 구조

```
zt-assessment/
├── README.md                      # 배포·실행 가이드
├── CLAUDE.md                      # AI 개발 어시스턴트용 프로젝트 가이드
├── status.md                      # ← 이 문서 (전체 구현 명세)
├── deploy.sh                      # EC2 동적 IP 배포 스크립트
├── docker-compose.yml             # 전체 서비스 통합 정의
│
├── backend/                       # FastAPI 백엔드
│   ├── Dockerfile                 # NanumGothic 폰트 포함, entrypoint.sh 실행
│   ├── entrypoint.sh              # MySQL 대기 → 마이그레이션 → seed → 서버 기동
│   ├── init.sql                   # MySQL 초기 스키마 (10개 테이블)
│   ├── main.py                    # FastAPI 앱 + CORS + 6개 router 등록
│   ├── database.py                # SQLAlchemy 엔진/세션
│   ├── models.py                  # ORM 모델 10개 (Organization, User, …)
│   ├── requirements.txt           # FastAPI/SQLAlchemy/httpx/openpyxl/reportlab/…
│   ├── manual-checklist.xlsx      # 수동 진단 Excel 템플릿 원본
│   ├── zt-checklist.xlsx          # 체크리스트 마스터 데이터
│   ├── zt-improvement-guide.xlsx  # 개선 권고 마스터 데이터
│   │
│   ├── routers/                   # API 엔드포인트
│   │   ├── assessment.py          # 진단 실행/상태/결과/이력/Shuffle 연동
│   │   ├── score.py               # 점수 요약/추세/체크리스트 점수
│   │   ├── improvement.py         # 개선 권고 조회
│   │   ├── manual.py              # 수동 진단 (웹 제출 + Excel 업로드)
│   │   ├── checklist.py           # 체크리스트 마스터 조회
│   │   └── report.py              # JSON/PDF 보고서 생성
│   │
│   ├── collectors/                # 도구별 자동 수집기 (총 212개 함수)
│   │   ├── keycloak_collector.py  # 65개 — IAM/SSO/MFA 정책 점검
│   │   ├── wazuh_collector.py     # 122개 — SIEM/EDR/SCA/FIM 점검
│   │   ├── nmap_collector.py      # 14개 — Nmap-Wrapper 호출
│   │   └── trivy_collector.py     # 11개 — Trivy-Wrapper 호출
│   │
│   ├── scoring/
│   │   └── engine.py              # 충족/부분충족/미충족 판정 + pillar 평균 + maturity_level
│   │
│   └── scripts/                   # 부팅 시 자동 실행
│       ├── migrate_schema.py      # 신규 컬럼 idempotent ALTER
│       ├── seed_checklist.py      # xlsx → Checklist 테이블 적재
│       ├── seed_improvement.py    # xlsx → ImprovementGuide 적재
│       └── seed_demo.py           # 데모용 조직/사용자/완료세션/진행세션 생성
│
├── frontend/                      # React + TypeScript + Vite + shadcn/ui
│   ├── Dockerfile                 # multi-stage: pnpm build → nginx
│   ├── nginx.conf                 # SPA 라우팅 + /api 프록시 비활성 (직접 호출)
│   ├── package.json
│   └── src/
│       ├── main.tsx               # React 진입점
│       ├── config/api.ts          # 백엔드 API 호출 함수 + ApiError 클래스
│       ├── types/api.ts           # 전체 API 타입 정의 (백엔드 enum과 일치)
│       └── app/
│           ├── App.tsx
│           ├── routes.tsx         # 7개 페이지 라우팅
│           ├── context/
│           │   └── AuthContext.tsx  # 데모용 4계정 인증 (admin/user1~3)
│           ├── components/
│           │   ├── RootLayout.tsx   # 사이드바 + 메인 영역
│           │   ├── ui/              # shadcn/ui 50+ 컴포넌트
│           │   └── figma/
│           ├── data/
│           │   ├── constants.ts     # PILLARS 정의
│           │   ├── mockData.ts      # API 실패 시 fallback 데이터
│           │   └── checklistItems.ts
│           ├── lib/
│           │   ├── maturity.ts      # 점수→레벨 변환, 색상
│           │   └── pillar.ts        # 한글↔영문 필러 매핑
│           └── pages/
│               ├── Login.tsx        # 데모 로그인 (id===password)
│               ├── Dashboard.tsx    # 종합 점수/추세/취약 필러/최근 세션
│               ├── NewAssessment.tsx# 3단계 진단 신청 폼
│               ├── InProgress.tsx   # 자동수집 폴링 + 수동 진단 입력
│               ├── Reporting.tsx    # 4탭 결과: 종합/세부/로드맵/PDF
│               ├── History.tsx      # 세션 비교 (정렬/필터/레이더)
│               └── Settings.tsx     # 임계값/목표/알림 (localStorage)
│
├── nmap-wrapper/                  # Nmap CLI 래퍼 (Flask)
│   ├── Dockerfile
│   └── app.py                     # 10개 엔드포인트: /scan/ports, /scan/tls, …
│
└── trivy-wrapper/                 # Trivy CLI 래퍼 (Flask)
    ├── Dockerfile
    └── app.py                     # 11개 엔드포인트: /scan/image, /scan/sbom, …
```

---

## 2. 기술 스택

### Backend
| 분류 | 기술 | 버전/설명 |
|---|---|---|
| 언어/런타임 | Python 3.11-slim |  |
| 웹 프레임워크 | FastAPI 0.115 | OpenAPI 자동 생성 (`/docs`) |
| ORM | SQLAlchemy 2.0 | declarative_base |
| DB 드라이버 | PyMySQL 1.1 |  |
| HTTP 클라이언트 | httpx 0.28 | collector 도구 호출 |
| Excel 파싱 | openpyxl | xlsx 읽기/쓰기 |
| PDF 생성 | reportlab | NanumGothic 한글 폰트 |
| 인증/암호화 | cryptography 44 | 향후 토큰 서명 대비 |

### Frontend
| 분류 | 기술 |
|---|---|
| 빌드 | Vite 6 |
| UI | React 18, TypeScript |
| 컴포넌트 | shadcn/ui (Radix 기반) |
| 차트 | recharts (Radar, Bar, Line) |
| 아이콘 | lucide-react |
| 알림 | sonner (toast) |
| 라우팅 | react-router v7 |
| 스타일 | TailwindCSS |

### 보안 도구 (자동 진단)
| 도구 | 항목 수 | 역할 |
|---|---|---|
| **Keycloak** | 31개 | IAM/SSO/MFA/RBAC/ABAC 정책 점검 |
| **Wazuh** | 41개 | SIEM/EDR/SCA/FIM, 알림 룰, 취약점 |
| **Nmap** | 14개 | 호스트 탐지, 포트 노출, TLS 사용률 |
| **Trivy** | 11개 | 이미지 취약점, SBOM, 공급망 무결성 |

### 인프라
- Docker Compose (전체 서비스 단일 host)
- AWS EC2 t3a.xlarge (4vCPU/16GB)
- Ubuntu 24.04

---

## 3. 데이터베이스 모델 (10개 테이블)

`backend/models.py` + `backend/init.sql`

```
Organization ─┬── User ───── DiagnosisSession ─┬── CollectedData ── Checklist ─── ImprovementGuide
              │                                ├── DiagnosisResult ───┘
              │                                ├── MaturityScore
              │                                ├── Evidence
              │                                └── ScoreHistory
              └── ScoreHistory (FK)
```

| 테이블 | 주요 컬럼 | 설명 |
|---|---|---|
| **Organization** | org_id, name, industry, size, cloud_type | 진단 대상 조직 메타데이터 |
| **User** | user_id, org_id, name, email, role, mfa_enabled | 담당자/관리자 계정 |
| **DiagnosisSession** | session_id, org_id, user_id, status, level, total_score, **selected_tools(JSON)**, **extra(JSON)** | 진단 세션. selected_tools: 선택된 자동 도구, extra: 임직원수·서버수·note·pillar_scope 등 |
| **Checklist** | check_id, item_id, pillar, category, item_name, maturity, maturity_score, diagnosis_type, tool, evidence, criteria, fields, logic, exceptions | 마스터 체크리스트. xlsx에서 seed. item_id 형식: `1.1.1.1_1` (3단계 dot + 성숙도숫자 + 카운터) |
| **CollectedData** | data_id, session_id, check_id, tool, metric_key, metric_value, threshold, raw_json, collected_at, error | 도구별 수집 원본 (Shuffle 또는 collector가 채움) |
| **DiagnosisResult** | result_id, session_id, check_id, **result(enum)**, score, recommendation | scoring engine 결과. enum: `충족 / 부분충족 / 미충족 / 평가불가` |
| **Evidence** | evidence_id, session_id, check_id, source, observed, location, reason, impact | 수동 입력 증적 |
| **MaturityScore** | score_id, session_id, pillar, score, level, pass_cnt, fail_cnt, na_cnt | 필러별 점수 + 결과 카운트 (PDF 필러 테이블용) |
| **ImprovementGuide** | guide_id, check_id, pillar, task, priority, term, recommended_tool, steps(JSON), … | 개선 권고. priority: Critical/High/Medium/Low, term: 단기/중기/장기 |
| **ScoreHistory** | history_id, session_id, org_id, pillar_scores(JSON), total_score, maturity_level, assessed_at | 시간순 점수 추이용 |

---

## 4. API 엔드포인트 (총 21개)

### 4.1 `/api/assessment/*` — 진단 실행/조회

| 메서드 | 경로 | 기능 |
|---|---|---|
| POST | `/run` | 진단 시작. Organization/User upsert → DiagnosisSession 생성 → 백그라운드로 Shuffle 트리거 또는 collector 실행 |
| GET  | `/status/{session_id}` | 자동수집 진행률 (선택된 도구 기준 expected count) — InProgress 페이지가 5초마다 폴링 |
| POST | `/finalize/{session_id}` | 수동 제출 완료 후 채점 트리거 (idempotent) |
| POST | `/internal/collect/{tool}` | Shuffle 워크플로우가 호출하는 도구별 수집 엔드포인트. `X-Internal-Token` 헤더 검증 |
| POST | `/webhook` | 외부(Shuffle)에서 수집 결과 전송 — CollectedData upsert |
| GET  | `/result?session_id=N` | 결과 + 동적 위험영역(errors) + extra 메타데이터 반환 |
| GET  | `/history?org_name=…` | 세션 이력. `org_name` 필터로 일반 사용자가 자기 조직 세션만 조회 |

### 4.2 `/api/score/*` — 점수

| GET | `/summary?session_id=N` | 필러별 점수, pass/fail/na 카운트, 종합 등급 |
| GET | `/trend?org_id=N&limit=12` | 시간순 점수 추이 (ScoreHistory) |
| GET | `/checklist/{session_id}` | 항목별 상세 점수 |

### 4.3 `/api/manual/*` — 수동 진단

| GET | `/items/{session_id}?excluded_tools=…` | 수동 항목 + 미사용 도구 항목 반환 |
| POST | `/submit` | 웹 폼 답변 일괄 저장 (`{check_id, value, evidence}` 배열) |
| POST | `/upload` (multipart) | Excel 일괄 업로드. `parsed_count`/`unmatched_count`/`skipped_count` 반환 |
| GET | `/template` | 빈 `manual-checklist.xlsx` 다운로드 |

### 4.4 `/api/checklist/*` — 마스터 데이터

| GET | `/?pillar=…&maturity=…` | 체크리스트 항목 목록 |

### 4.5 `/api/improvement/*` — 개선 권고

| GET | `/?pillar=&term=&priority=` | 전체 권고 필터 조회 |
| GET | `/session/{session_id}` | 세션 결과에 연결된 권고 (failed 항목 기준) |
| GET | `/{guide_id}` | 권고 단건 상세 |

### 4.6 `/api/report/*` — 보고서

| GET | `/generate?session_id=N&fmt=json\|pdf` | JSON 또는 PDF 다운로드. PDF는 NanumGothic 사용 |
| GET | `/generate/{session_id}?fmt=…` | path-param 버전 (동일 기능) |

### 기타

| GET | `/health` | liveness 체크 |
| GET | `/docs`   | FastAPI Swagger UI |

---

## 5. 사용자 시나리오 (End-to-End)

### 5.1 로그인
1. `/login`에서 데모 계정 클릭(자동 입력) 또는 직접 입력
   - `admin/admin`: 전체 조직 이력 조회 가능
   - `user1/user1`: ABC 기업 / `user2/user2`: XYZ 금융 / 등
2. AuthContext가 localStorage에 사용자 저장 → 새로고침해도 유지

### 5.2 신규 진단 (3단계 위저드)
**Step 1 — 환경 입력**
- 기관명, 담당자, 이메일, 부서, 인프라 유형(온프레미스/AWS/…)
- 진단 범위(6 필러 체크박스)
- 사용 중 보안 도구(Keycloak/Wazuh/Nmap/Trivy) — 선택한 도구만 자동 수집
- 임직원 수/서버 수/앱 수 (Organization.size 자동 계산)
- 임시저장 버튼 → localStorage

**Step 2 — 진단 방식 안내**
- 선택된 필러별로 자동수집 대상 도구 표시
- 수동 항목은 다음 단계 (InProgress 페이지)에서 입력

**Step 3 — 최종 확인 후 시작**
- `POST /api/assessment/run` 호출 → `session_id` 발급
- 백엔드: BackgroundTasks로 Shuffle 트리거 or `_run_collectors` 직접 실행
- `/in-progress/{session_id}`로 navigate (state로 excludedTools 전달)

### 5.3 자동수집 진행 + 수동 입력 (InProgress 페이지)
- 5초마다 `GET /api/assessment/status/{id}` 폴링 (즉시 1회 + interval)
- `collection_done`이 true가 되면 토스트로 알림
- 동시에 수동 항목 입력 가능:
  - **웹 설문 모드**: 필러별 아코디언, 4개 답변 버튼(충족/부분충족/미충족/평가불가) + 증적 텍스트
  - **Excel 업로드 모드**: 템플릿 다운로드 → 작성 → 업로드 (즉시 점수 계산)
- 제출 후 `POST /api/assessment/finalize/{id}` → 채점 → `/reporting/{id}`로 이동

### 5.4 결과 확인 (Reporting 페이지) — 4개 탭

**① 종합 결과**
- 종합 등급 배너 (점수 / 기존→초기→향상→최적화 진행 배지)
- 관리자: 위험영역 카드 (DiagnosisResult 기반 동적 생성, E001~E006 코드, 심각도)
- AS-IS / TO-BE 레이더 차트
- 필러별 점수 카드 (목표 마커, GAP)

**② 세부 항목**
- 필러 검색 + 질문/도구/증적 텍스트 검색
- 결과별 색상: 충족(녹색)/부분충족(황색)/미충족(적색)/평가불가(회색)
- 클릭 시 펼침: 진단 근거 스냅샷(수집값·위치·판정이유), 증적, 판정기준, 추출필드, 처리로직, 예외, 개선권고

**③ 개선 로드맵 (칸반)**
- GAP 분석 요약 (currentAvg → targetAvg, Critical/High/Medium 건수)
- 단기/중기/장기 3컬럼
- 카드: 우선순위 배지, 예상기간, 난이도, 담당, 기대점수, 실행계획(접힘)

**④ 보고서 출력**
- "PDF 다운로드" → `GET /api/report/generate?fmt=pdf`
- 4섹션 구성: 표지/필러점수/체크리스트세부/개선권고 — NanumGothic

### 5.5 이력 및 비교 (History 페이지)
- 정렬 가능 테이블 (기관/담당자/날짜)
- 일반 사용자는 자기 조직(orgName) 세션만 — 백엔드 `org_name` 필터링
- 체크박스로 2개 이상 선택 시 비교 섹션 표시
  - 종합 점수 가로 막대 비교
  - 필러별 레이더 비교 (각 세션의 `getScoreSummary` 호출하여 실제 MaturityScore 사용)

### 5.6 대시보드
- 종합 점수 / 직전 점수 대비 trend
- 가장 취약한 필러 (자동 계산)
- 우선 개선 과제 top 3 (ImprovementGuide)
- 필러별 진행률 바
- 레이더 차트 (현재 vs 목표)
- 성숙도 추이 라인 차트 — `GET /api/score/trend` 또는 history fallback
- 최근 진단 세션 5/3건

---

## 6. 데이터 흐름 (시스템 관점)

### 6.1 컨테이너 부팅
```
docker compose up
  └─ mysql:        init.sql 실행 (테이블 10개)
  └─ zt-backend:   entrypoint.sh
        1. MySQL 준비 대기 (pymysql connect 폴링)
        2. migrate_schema.py     ── 신규 컬럼 idempotent ALTER
        3. seed_checklist.py     ── zt-checklist.xlsx → Checklist
        4. seed_improvement.py   ── zt-improvement-guide.xlsx → ImprovementGuide
        5. seed_demo.py          ── 데모_조직 + 완료세션 + 진행세션 (중복 시 skip)
        6. uvicorn main:app --host 0.0.0.0 --port 8000
```

### 6.2 진단 수행 (Shuffle 사용 시)
```
Frontend ──POST /run──► Backend
                           ├─ DiagnosisSession 생성 (status="진행 중")
                           └─ BackgroundTasks:
                                _trigger_shuffle_workflows(session_id, selected_tools)
                                  └─ 각 도구별 워크플로우에 webhook_url + internal_token 전달

Shuffle ── 도구별 워크플로우 실행 ──► Backend POST /internal/collect/{tool}
                                              ├─ X-Internal-Token 검증
                                              └─ BackgroundTasks: _run_collectors(session_id, [tool])
                                                    └─ collector 호출 → CollectedData 직접 INSERT

[ 또는 Shuffle이 외부에서 직접 결과 묶음 전송 ]
Shuffle ──POST /webhook──► Backend
                              └─ results 배열 → CollectedData upsert

Frontend ── 5초 폴링 ──► GET /status/{id}
                              └─ collected_count / auto_total 비교

수동 입력 완료 후 ──POST /manual/submit ──► CollectedData + DiagnosisResult (수동 항목)
                  ──POST /finalize/{id}──► _trigger_scoring(session_id)
                                              ├─ score_session() — 충족/부분/미충족 판정
                                              ├─ DiagnosisResult upsert
                                              ├─ MaturityScore (pass_cnt/fail_cnt/na_cnt 포함)
                                              ├─ ScoreHistory INSERT
                                              └─ session.status = "완료"
```

### 6.3 Shuffle 미사용 시 (개발/로컬)
- `SHUFFLE_URL`이 비어있거나 도구별 WF ID가 모두 미설정이면 자동 fallback
- `_run_collectors(session_id, selected_tools)`를 BackgroundTasks로 직접 실행
- 결과를 httpx로 자기 webhook 호출하지 않고 DB에 직접 INSERT (deadlock 회피)

### 6.4 보고서 생성
```
Frontend ── 다운로드 클릭 ──► GET /api/report/generate?fmt=pdf
                                  └─ _build_data(session_id)
                                        ├─ DiagnosisSession + Organization + User
                                        ├─ MaturityScore (pass/fail/na)
                                        ├─ DiagnosisResult ⋈ Checklist
                                        └─ ImprovementGuide (failed check_id 기준)
                                  └─ _make_pdf(data) → reportlab platypus
                                        ├─ 1) 표지: 점수 + 카운트 4분할
                                        ├─ 2) 필러별: 막대 그래프 + 표
                                        ├─ 3) 체크리스트: 필러별 표 (결과 색상)
                                        └─ 4) 개선권고: 단기/중기/장기 표
                                  → StreamingResponse(application/pdf)
```

---

## 7. 핵심 알고리즘

### 7.1 점수 계산 (`scoring/engine.py`)

**항목 단위**
```python
weight = 1.0 (충족) | 0.5 (부분충족) | 0.0 (미충족)
score = maturity_score × weight    # maturity_score: 1~4
```

판정 기준:
- 임계값(threshold) 양수: `metric_value >= threshold` → 충족 / `>= threshold*0.7` → 부분충족 / 그 외 미충족
- 임계값 0 (낮을수록 좋음, 예: CVE 수): `0` → 충족 / `≤5` → 부분충족 / 그 외 미충족
- `error` 있으면 평가불가 (0점)

**필러/종합**
```python
pillar_score = mean(item.score for item in pillar)
total_score  = mean(pillar_scores.values())
```

**성숙도 단계 매핑**
```python
total >= 3.5 → "최적화"
total >= 2.5 → "향상"
total >= 1.5 → "초기"
else         → "기존"
```

### 7.2 위험 영역 동적 생성 (`assessment._build_session_errors`)
- 미충족·부분충족 DiagnosisResult를 pillar별로 group by
- 가장 많이 실패한 pillar 순서로 정렬
- 미충족 비율 ≥ 50%: Critical / ≥ 20%: High / 그 외 Medium
- 코드 부여: 신원(E001) / 기기(E002) / 네트워크(E003) / 시스템(E004) / 앱(E005) / 데이터(E006)

### 7.3 Excel 매칭 (`manual._find_checklist`)
- Excel 항목번호: `"1.1.1 사용자 인벤토리"` (3단계 dot)
- DB item_id: `"1.1.1.1_1"` (3단계 + `.` + 성숙도숫자 + `_` + 카운터)
- 매칭 패턴: `f"{prefix}.{mat_num}_%"` LIKE
- 후보군에서 질문(item_name) 완전일치 우선, 없으면 첫 번째 선택
- 매칭 실패는 `unmatched_count`로 응답에 노출

### 7.4 Excel `judgment_mapping` 시트
- `(M_id, 선택값) → 판정결과` 딕셔너리 구성
- 예: `(M001, "문서 존재") → "충족"`, `(M001, "미존재") → "미충족"`
- 사용자는 "선택값"만 입력하면 자동으로 판정 enum으로 변환

---

## 8. 보안

| 항목 | 상태 |
|---|---|
| CORS | `CORS_ORIGINS` env로 화이트리스트 |
| Internal API 토큰 | `INTERNAL_API_TOKEN` env 설정 시 `/webhook`, `/internal/collect/*`에서 `X-Internal-Token` 헤더 검증 |
| 비밀번호 정책 | 데모 — `id===password` (운영 시 Keycloak SSO 연동 예정) |
| 환경변수 | 모든 비밀(DB/SHUFFLE_API_KEY/…)은 `.env`에서 로드, 코드 하드코딩 금지 |
| HTTPS | 데모 단계 미적용. 운영 시 ALB 또는 Caddy 리버스 프록시 권장 |

---

## 9. 환경변수

`.env` (gitignore — `deploy.sh`로 동적 생성 가능)

```env
# DB
DB_HOST=mysql
DB_PORT=3306
DB_NAME=zt_assessment
DB_USER=readyz
DB_PASSWORD=readyz1234
MYSQL_ROOT_PASSWORD=readyz1234

# Backend
SECRET_KEY=readyzsecretkey123
SELF_BASE_URL=http://zt-backend:8000
INTERNAL_API_TOKEN=             # (선택) webhook 인증 토큰
CORS_ORIGINS=http://localhost:8080

# Frontend 빌드시 주입
VITE_API_BASE=http://localhost:8000

# Keycloak
KEYCLOAK_URL=http://keycloak:8443
KEYCLOAK_REALM=master
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=admin1234

# Wazuh
WAZUH_API_URL=https://wazuh:55000
WAZUH_API_USER=wazuh
WAZUH_API_PASS=wazuh1234
WAZUH_INDEXER_URL=https://wazuh:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=admin1234

# Wrappers
NMAP_WRAPPER_URL=http://nmap-wrapper:8001
NMAP_TARGET=127.0.0.1
TRIVY_WRAPPER_URL=http://trivy-wrapper:8002
TRIVY_TARGET=nginx:latest

# Shuffle SOAR (옵션)
SHUFFLE_URL=
SHUFFLE_API_KEY=
SHUFFLE_WORKFLOW_KEYCLOAK=
SHUFFLE_WORKFLOW_WAZUH=
SHUFFLE_WORKFLOW_NMAP=
SHUFFLE_WORKFLOW_TRIVY=
```

EC2 배포 시: `./deploy.sh <EC2_퍼블릭_IP>` 실행 → `VITE_API_BASE`/`CORS_ORIGINS` 자동 설정 후 `docker compose up -d --build`

---

## 10. 포트 매핑

| 호스트 | 컨테이너 | 서비스 |
|---|---|---|
| 8080 | 80   | Frontend (nginx) |
| 8000 | 8000 | Backend (FastAPI) |
| 3306 | 3306 | MySQL |
| 8443 | 8443 | Keycloak |
| 55000 | 55000 | Wazuh Manager API |
| 9201 | 9200 | Wazuh Indexer / Elasticsearch |
| 8001 | 5000 | Nmap Wrapper |
| 8002 | 5001 | Trivy Wrapper |
| 3001 | 80   | Shuffle UI (옵션) |

---

## 11. 빌드/배포

### 로컬
```bash
git clone https://github.com/Allright24Gr/zt-assessment
cd zt-assessment && git checkout dev
docker compose up -d
# http://localhost:8080
```

### EC2
```bash
git pull origin dev
./deploy.sh <EC2_IP>     # IP 인자 없으면 프롬프트로 물어봄
```
EC2 재시작 시 IP가 바뀌므로 `deploy.sh`에 새 IP를 다시 넣고 실행하면 됨.

### Shuffle 워크플로우 연동
1. `http://<IP>:3001`에서 도구별 워크플로우 4개 생성 (각 워크플로우의 HTTP Action이 `POST /api/assessment/internal/collect/{tool}` 호출)
2. 워크플로우 ID(UUID)를 `.env`의 `SHUFFLE_WORKFLOW_*`에 입력
3. `docker compose restart zt-backend`

---

## 12. 데모 데이터 (자동 시드)

컨테이너 첫 부팅 시 `seed_demo.py`가 다음을 자동 생성 (중복 시 skip):

| 리소스 | 내용 |
|---|---|
| Organization | "데모_조직" (금융, 중견기업, 하이브리드) |
| User | "데모 관리자" (admin, MFA 활성화) |
| Session #1 | **완료** 상태, 2시간 전 시작·30분 전 완료. 전체 결과 + PDF 리포트 즉시 확인 가능 |
| Session #2 | **진행 중** 상태, 자동수집 50% 진행 — InProgress 페이지 데모용 |

결과 분포는 `check_id % 10` 기반으로 고정되어 재배포해도 매번 동일:
- Keycloak 70% 충족 / Wazuh 65% / 수동 60% / Nmap 50% / Trivy 45%

---

## 13. 알려진 한계 (TODO)

- AuthContext가 데모용 4계정 하드코딩 — 운영 시 Keycloak OIDC 연동 필요
- Settings 페이지는 localStorage 저장만 — 백엔드 정책 반영 미구현
- 증적 파일 업로드(NewAssessment Step 1)는 UI만 동작, S3 등으로 영구 저장 미구현
- 임계값(`threshold`) 동적 조정 미지원 — 현재는 scoring engine 코드에 고정
- Shuffle workflow 정의 자체는 운영자가 UI에서 수동 생성 (export/import JSON 미제공)
- PDF는 NanumGothic 단일 폰트 — bold/italic 변형 없음

---

## 14. 브랜치 전략

| 브랜치 | 용도 |
|---|---|
| `master` | 최종 배포본 (직접 push 금지) |
| `dev` | 통합 테스트 브랜치 (현재 작업 기준) |
| `feature/backend-skeleton` | 서진우 |
| `feature/keycloak-collector` | 공나영 |
| `feature/wazuh-collector` | 공나영 (대리) |
| `feature/nmap-trivy-wrapper` | 송민희 |
| `feature/frontend-api-connect` | (통합 완료) |
| `feature/scoring-engine` | (통합 완료) |
| `feature/shuffle-workflow` | (통합 완료) |

작업 흐름: `feature/*` → PR → `dev` → 테스트 후 `master`

---

## 15. 주요 파일별 상세 책임

### Backend

| 파일 | 책임 |
|---|---|
| `main.py` | FastAPI 앱 생성, CORS, 6개 router 등록, `/health` |
| `database.py` | SQLAlchemy 엔진 + `get_db` 의존성 |
| `models.py` | 10개 ORM 모델 + 관계 정의 |
| `scoring/engine.py` | `score_single_item`, `score_session`, `determine_maturity_level`, `generate_recommendations` |
| `routers/assessment.py` | 진단 라이프사이클 전체 — run/status/finalize/internal/webhook/result/history + Shuffle dispatcher + collector dispatcher + dynamic errors |
| `routers/manual.py` | 수동 진단 — submit/upload/items/template, Excel `judgment_mapping` 시트 파싱, item 매칭 |
| `routers/report.py` | `_build_data` (JSON), `_make_pdf` (reportlab platypus, 4섹션, NanumGothic) |
| `routers/score.py` | summary/trend/checklist 별 점수 조회 |
| `routers/improvement.py` | 권고 목록/세션별/단건 |
| `routers/checklist.py` | 마스터 체크리스트 조회 |
| `collectors/keycloak_collector.py` | Keycloak Admin REST API 호출 — realm/users/IdP/auth-flow 정책 점검 |
| `collectors/wazuh_collector.py` | Wazuh Manager API + Indexer 호출 — alerts/SCA/agents/FIM |
| `collectors/nmap_collector.py` | `NMAP_WRAPPER_URL` 호출 — 14개 함수 |
| `collectors/trivy_collector.py` | `TRIVY_WRAPPER_URL` 호출 — 11개 함수 |
| `scripts/migrate_schema.py` | INFORMATION_SCHEMA 조회 → 누락 컬럼만 `ALTER TABLE ADD` |
| `scripts/seed_checklist.py` | `체크리스트_도구매핑` 시트 → Checklist (item_id 자동 생성) |
| `scripts/seed_improvement.py` | xlsx → ImprovementGuide (개선권고여부="있음"만) |
| `scripts/seed_demo.py` | 데모 조직/사용자/완료세션/진행세션 생성 |
| `entrypoint.sh` | MySQL 대기 → 마이그레이션 → seed 3개 → uvicorn |
| `Dockerfile` | python:3.11-slim + fonts-nanum + libmysqlclient-dev |

### Frontend

| 파일 | 책임 |
|---|---|
| `main.tsx` | React DOM render |
| `app/App.tsx` | RouterProvider + Toaster |
| `app/routes.tsx` | 7개 페이지 라우팅 |
| `app/context/AuthContext.tsx` | 데모용 인증 + localStorage 영속화 |
| `app/components/RootLayout.tsx` | 사이드바 + 메인 영역 + 로그아웃 |
| `app/lib/maturity.ts` | 점수 → 단계명, 색상 |
| `app/lib/pillar.ts` | 한글 ↔ 영문 필러 키 매핑 |
| `app/data/constants.ts` | PILLARS 정의 |
| `app/data/mockData.ts` | API 실패 시 fallback (삭제 금지) |
| `app/pages/Login.tsx` | 데모 계정 4개 자동 입력 |
| `app/pages/Dashboard.tsx` | 종합 점수 / trend / 취약 필러 / 우선 과제 / 레이더 / 최근 세션 |
| `app/pages/NewAssessment.tsx` | 3-step 위저드, 임시저장(localStorage), Step2는 안내 화면 |
| `app/pages/InProgress.tsx` | 5초 폴링, 웹설문/Excel 탭 전환, 즉시 1회 호출 |
| `app/pages/Reporting.tsx` | 4탭(종합/세부/로드맵/PDF), 동적 위험영역, GAP 동적 텍스트 |
| `app/pages/History.tsx` | 정렬 테이블, 세션 비교(실제 pillar score fetch) |
| `app/pages/Settings.tsx` | localStorage 저장 + 베타 배지 |
| `config/api.ts` | API_BASE, ApiError, apiFetch + 도메인별 함수 18개 |
| `types/api.ts` | 백엔드 enum과 1:1 일치하는 타입 정의 |

### Wrappers

| 파일 | 책임 |
|---|---|
| `nmap-wrapper/app.py` | nmap CLI subprocess + XML 파싱, 10개 엔드포인트 |
| `trivy-wrapper/app.py` | trivy CLI subprocess + JSON 파싱, 11개 엔드포인트 (Docker socket 마운트 필요) |

---

## 16. 트러블슈팅

| 증상 | 원인 / 해결 |
|---|---|
| 컨테이너 시작 시 seed 실패 | MySQL 준비 대기 로직(`entrypoint.sh`)이 자동 재시도. 그래도 실패하면 `docker compose logs zt-backend` |
| 자동수집 진행률이 영원히 안 끝남 | `selected_tools`가 세션에 안 저장되었거나 collector가 모두 실패. `/api/assessment/status/{id}` 응답의 `selected_tools` 확인 |
| Excel 업로드 0건 파싱 | `항목번호` 셀이 3단계 dot 형식인지 확인 (`1.1.1 사용자 인벤토리`). 응답의 `unmatched_count` 확인 |
| PDF 한글 깨짐 | Dockerfile의 `fonts-nanum` 설치 누락. 컨테이너 빌드 다시 실행 |
| 일반 사용자로 로그인 시 빈 이력 | AuthContext의 `orgName`이 백엔드 Organization.name과 일치하는지 확인 |
| EC2 재시작 후 API 호출 실패 | 퍼블릭 IP 변경 — `./deploy.sh <새IP>` 재실행 |
| Shuffle 워크플로우 트리거 안 됨 | `.env`의 `SHUFFLE_URL`, `SHUFFLE_API_KEY`, `SHUFFLE_WORKFLOW_*` 모두 채워졌는지 확인 후 `docker compose restart zt-backend` |
