<div align="center">

# 🛡️ Readyz-T

**KISA 제로트러스트 가이드라인 2.0 기반 보안 성숙도 진단 플랫폼**

6 Pillar × 4단계 성숙도를 *자동 수집 + 수동 증적* 하이브리드 방식으로 평가합니다.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#-라이선스)
![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![Node 20+](https://img.shields.io/badge/node-20+-green.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)
![React 18](https://img.shields.io/badge/React-18-61DAFB?logo=react)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)

[빠른 시작](#-빠른-시작) · [진단 흐름](#-진단-흐름) · [산출물](#-산출물-5종) · [아키텍처](#-아키텍처) · [개발 가이드](#-개발-가이드)

</div>

---

## 📋 목차

- [프로젝트 소개](#-프로젝트-소개)
- [주요 기능](#-주요-기능)
- [기술 스택](#-기술-스택)
- [아키텍처](#-아키텍처)
- [빠른 시작](#-빠른-시작)
- [진단 흐름](#-진단-흐름)
- [산출물 5종](#-산출물-5종)
- [디렉토리 구조](#-디렉토리-구조)
- [환경 변수](#-환경-변수)
- [운영 명령](#-운영-명령)
- [개발 가이드](#-개발-가이드)
- [보안 정책](#-보안-정책)
- [팀 & 라이선스](#-팀--라이선스)

---

## 🎯 프로젝트 소개

### 왜 만들었나

기존 보안 성숙도 진단은 외부 컨설팅 의존도가 높고, *조직에 직접 도구를 설치*해야 하는 침해형 평가가 대부분입니다. Readyz-T 는 **고객 시스템에 코드를 설치하지 않고** 우리 서버에서 *outbound 호출만으로* 진단하는 무침해 자동화 도구입니다.

- 🏛️ **KISA 제로트러스트 가이드라인 2.0** 기준 — 식별자·기기·네트워크·시스템·애플리케이션·데이터 6 Pillar
- 🎚️ **4단계 성숙도** — 기존(Legacy) → 초기(Initial) → 향상(Enhanced) → 최적화(Optimized)
- 🤖 **자동 + 수동 하이브리드** — 도구로 점검 가능한 항목은 자동, 정책·운영 이력은 수동 증적
- 📑 **6대 산출물 자동 생성** — PDF 보고서, 증적 목록, 판정 로그, 30/60/90일 로드맵 등

### 핵심 가치

| 가치 | 설명 |
|---|---|
| **비침해 (Non-intrusive)** | 고객 시스템에 agent·sidecar 설치 일체 없음. 우리 EC2 에서 원격 호출만. |
| **하이브리드 평가** | 자동 수집 가능 영역은 도구가 점검, 안 되는 영역은 운영자가 수동 증적으로 보강. |
| **증적 기반** | 모든 항목은 *증적 → 판정 기준 → 결과* 가 연결되어 추적 가능. |
| **데모/운영 분리** | 시연·테스트 모드와 실 운영 진단을 명확히 구분. |
| **자격 보호** | 진단 자격 비밀번호는 DB에 저장하지 않고 메모리 dict 로만 일시 보관 후 즉시 폐기. |

---

## ✨ 주요 기능

### 🔍 진단 엔진

- **6 Pillar × 4단계 = 310개 체크리스트** 자동 평가
- **자동 수집 도구 4종**
  - 🔐 **Keycloak** — IdP / SSO / MFA / 권한 관리 (65 항목)
  - 🛡️ **Wazuh** — SIEM / HIDS / 침입 탐지 (122 항목)
  - 🌐 **Nmap** — 외부 포트·TLS·서브넷 스캔 (14 항목)
  - 📦 **Trivy** — 컨테이너 이미지·SBOM·취약점 (11 항목)
- **보너스 자동 점검** — HTTP 보안 헤더, DNS (SPF/DMARC/CAA), TLS 인증서, `security.txt`, GitHub repo 보안 파일
- **수동 진단 폴백** — 환경에 맞춰 자동 미지원 항목을 Excel 양식으로 다운로드·작성·업로드

### 📊 결과 분석

- **종합 점수 + Pillar별 강·약점 레이더 차트**
- **30/60/90일 개선 로드맵** — Critical 우선 정렬
- **위험영역 대시보드** (관리자 뷰)
- **다른 세션과 비교** — 최대 4개 동시 비교
- **NIST 800-207 / CIS Controls v8 표준 매핑**

### 🔄 평가 메타 (SKT 가이드 §3 대응)

진단 시작 시 입력 → 보고서 첫 장 자동 표기:
- 평가 대상 버전 (Vercel/Railway deployment id, Git commit)
- 평가 범위 자산 목록 (Frontend URL·Backend API·Supabase·Notion·Drive·GitHub repo 등)
- 데이터 등급 분류 (영업 고객명·제안서·OAuth token 등 7종)
- 판정자 4역할 (App owner / Backend / Cloud / Security)
- 외부 스캔 승인 메타 (승인자·시간대·강도·제외경로·비상연락처)

### 🔔 알림 시스템

- 진단 완료, 시드 비번 사용, 수동 미완료 등 이벤트 알림
- localStorage 영속 + 종 아이콘 드롭다운

---

## 🛠 기술 스택

<table>
<tr>
<th>영역</th>
<th>스택</th>
</tr>
<tr>
<td>Frontend</td>
<td>
  <img src="https://img.shields.io/badge/React-18-61DAFB?logo=react"/>
  <img src="https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript"/>
  <img src="https://img.shields.io/badge/Vite-6-646CFF?logo=vite"/>
  <img src="https://img.shields.io/badge/Tailwind_CSS-3-06B6D4?logo=tailwindcss"/>
  <img src="https://img.shields.io/badge/recharts-2-FF6384"/>
</td>
</tr>
<tr>
<td>Backend</td>
<td>
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?logo=python"/>
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi"/>
  <img src="https://img.shields.io/badge/SQLAlchemy-2.0-D71F00"/>
  <img src="https://img.shields.io/badge/Pydantic-2.10-E92063"/>
  <img src="https://img.shields.io/badge/reportlab-PDF-FF6F00"/>
</td>
</tr>
<tr>
<td>DB / 인프라</td>
<td>
  <img src="https://img.shields.io/badge/MySQL-8.0-4479A1?logo=mysql"/>
  <img src="https://img.shields.io/badge/Docker_Compose-2496ED?logo=docker"/>
  <img src="https://img.shields.io/badge/AWS_EC2-FF9900?logo=amazonec2"/>
  <img src="https://img.shields.io/badge/Nginx-009639?logo=nginx"/>
</td>
</tr>
<tr>
<td>진단 도구</td>
<td>
  <img src="https://img.shields.io/badge/Keycloak-24-4D4D4D?logo=keycloak"/>
  <img src="https://img.shields.io/badge/Wazuh-4.7-1496FE"/>
  <img src="https://img.shields.io/badge/Nmap-Wrapper-4682B4"/>
  <img src="https://img.shields.io/badge/Trivy-Aqua-1904DA"/>
</td>
</tr>
</table>

---

## 🏗 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                       사용자 브라우저                              │
│            http://<EC2_IP>:8080                                  │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                  ┌────────────▼────────────┐
                  │  zt-web (Nginx + React)  │  :8080
                  └────────────┬────────────┘
                               │
                  ┌────────────▼─────────────┐
                  │ zt-backend (FastAPI)      │  :8000
                  │  - auth / assessment      │
                  │  - report / improvement   │
                  │  - manual evidence        │
                  └────┬───────┬──────────┬───┘
                       │       │          │
            ┌──────────▼──┐ ┌──▼────┐ ┌───▼──────┐
            │  MySQL 8    │ │Keycloak│ │  Wazuh  │
            │  3306       │ │ 8443  │ │ 55000   │
            └─────────────┘ └───────┘ └─────────┘
                       │
            ┌──────────┴──────────┐
            │                     │
   ┌────────▼──────┐    ┌────────▼──────┐
   │ nmap-wrapper  │    │ trivy-wrapper │
   │ Flask :8001   │    │ Flask :8002   │
   └────────┬──────┘    └───────────────┘
            │
            ▼
   ┌──────────────────────────────────────┐
   │ 외부 진단 대상 (고객 시스템)            │
   │ - tmarkovframework.vercel.app 등      │
   │ - 우리는 outbound 호출만, agent 설치 X │
   └──────────────────────────────────────┘
```

### 진단 데이터 흐름

```
POST /api/assessment/run
   ├─ validators 검증 (Nmap target, Trivy image, URL...)
   ├─ 권한 확인 (본인 조직만, admin 제외)
   ├─ session.extra ← URL/사용자명만 (비밀번호 제외)
   ├─ _store_session_secrets ← 비밀번호는 메모리 dict 로만
   └─ BackgroundTask._run_collectors(session_id, tools)
        ↓
        ↓ 직렬화 락(_collector_lock) — 동시 세션 충돌 방지
        ↓
        ├─ _pop_session_secrets ← 사용 후 즉시 폐기
        ├─ _tool_health(tool) → 미연결이면 일괄 "평가불가"
        ├─ collector 호출 → CollectedData / DiagnosisResult upsert
        └─ finally: set_session_creds(None) 폐기

POST /api/assessment/finalize/{id}
   └─ score_session → MaturityScore + ScoreHistory + recommendation
```

---

## 🚀 빠른 시작

### 사전 요구사항

- Docker 24+ & Docker Compose v2
- Linux/macOS 환경 (Windows 는 WSL2 권장)
- 메모리 8GB+ 권장 (Wazuh + Elasticsearch 포함)

### 1. 클론 & 환경 변수

```bash
git clone https://github.com/Allright24Gr/zt-assessment
cd zt-assessment
cp .env.example .env
# .env 의 INTERNAL_API_TOKEN, DB 비밀번호 등을 운영 환경에 맞춰 수정
```

### 2. 한 줄 배포

```bash
# 로컬 개발
./deploy.sh local

# EC2 (퍼블릭 IP 인자)
./deploy.sh 1.2.3.4

# 데이터 초기화 + 재배포
./deploy.sh local reset
```

`deploy.sh` 가 자동으로 처리하는 것:
- `.env` 의 `CORS_ORIGINS` 에 EC2 IP 자동 추가
- 우리 빌드 이미지 (`zt-backend`, `zt-web`, `*-wrapper`) 재빌드
- 외부 이미지 (MySQL, Keycloak, Wazuh, Elasticsearch) 는 재사용 (재다운로드 X)
- DB 시드 (`seed_checklist.py`, `seed_demo_examples.py`, `seed_improvement.py`) 자동 실행

### 3. 첫 접속

| 서비스 | URL | 비고 |
|---|---|---|
| **메인 사이트** | http://localhost:8080 | 진우님이 사용할 화면 |
| **API 헬스체크** | http://localhost:8000/health | `{"status":"ok"}` 응답 |
| **Keycloak (옵션)** | http://localhost:8443 | 진단 대상 — admin/admin |
| **Wazuh (옵션)** | https://localhost:55000 | 진단 대상 |

### 4. 시드 계정으로 로그인

| 계정 | 비번 | 역할 | 용도 |
|---|---|---|---|
| `admin` | `admin` | 관리자 | 전체 진단 이력 조회 |
| `user1` | `user1` | 사용자 (박기웅, 세종대학교) | 데모 모드 시연 |
| `user2` | `user2` | 사용자 (서진우, T-Markov Framework) | 실 운영 평가 시연 |

> ⚠️ 시드 비밀번호는 *시연 편의* 를 위한 4자입니다. 운영 환경에서는 로그인 즉시 변경 권장. Dashboard 에 노란 배너로 안내합니다.

---

## 🔁 진단 흐름

### Step 0 — 사전 환경 프로파일링

NewAssessment 첫 화면에서 선택:

- **IdP 선택** — Keycloak / Google Workspace / MS Entra ID / Okta / 자체 LDAP·AD / 사용 안 함
- **SIEM 선택** — Wazuh / Splunk / Elastic / 사용 안 함
- **외부 자동 스캔** — Nmap / Trivy 토글
- **데모/실 스캔 모드** — 안전한 시연 vs 실제 외부 호출

> 미지원 옵션을 선택하면 그 분야 자동 항목은 *수동 진단으로 자동 폴백* 됩니다.

### Step 1 — 기관 정보 입력

- 부서, 산업군, 인프라 유형 (온프레/AWS/Azure/GCP/**SaaS형**/하이브리드)
- 직원·서버·애플리케이션 수
- 평가 착수 전 확정사항 **4 카드** (가이드 §3)
  - **평가 대상 버전** — Vercel/Railway deployment id, Git commit
  - **평가 범위 자산 목록** — 8개 기본 항목 (Frontend URL ~ 운영자 계정)
  - **데이터 등급 분류** — 7개 항목 × 민감도(낮음·중간·높음) × 보관 위치
  - **판정자 4역할** — App owner / Backend / Cloud / Security reviewer

### Step 2 — 진단 범위 선택

6 Pillar 중 진단할 영역 체크박스. 첫 평가는 6 Pillar 전체 권장.

선택 후, *수동 진단 양식 미리 작성* 옵션:
- 세션 미리 생성 (`prepareAssessment`) → 환경에 맞춘 xlsx 양식 다운로드
- 작성 후 업로드하면 자동 채점됨
- 양식의 비고 컬럼에 *공개 URL 자동 점검 결과* (HTTP 헤더·DNS·TLS·GitHub repo) 미리 채워짐

### Step 3 — 외부 스캔 동의 + 진단 시작

- **외부 스캔 동의 메타 5필드** (가이드 §3·§4)
  - 승인자, 시간대, 강도(light/standard), 제외 경로, 비상 연락처
- **진단 시작** → 자동 collector 실행

### InProgress 페이지

- 도구별·필러별 진행률
- 평균 속도 기반 ETA 동적 추정
- 250ms 폴링
- **§5 6 Pillar 증적 준비표** 토글 안내
- 수동 양식 다운로드/업로드 + 항목별 증적 파일 (PDF/이미지) 첨부
- 완료 시 자동으로 `/reporting/{id}` 이동

### Reporting 페이지

- **종합 결과** — 점수, 등급, AS-IS/TO-BE 비교, 위험영역
- **세부 항목** — 카테고리(예 "1.2.1 다중인증") 카드 → 4단계 row 펼침
- **개선 로드맵** — 30/60/90일 칸반 + 가이드 §8 권장 활동
- **표준 매핑** — NIST 800-207 / CIS Controls v8
- **OCSF** — 1.1.0 표준 이벤트
- **보고서 출력** — PDF / 증적 목록 xlsx / 판정 로그 md 다운로드

---

## 📦 산출물 5종

| 산출물 | 형식 | 다운로드 위치 |
|---|---|---|
| **범위 선언서** | PDF 표지에 자동 포함 | 결과 PDF 첫 장 |
| **결과 보고서** | PDF (한글 NanumGothic) | Reporting → 보고서 출력 |
| **증적 목록** | xlsx (메인 시트 + 메타 + 자산 + 데이터등급) | Reporting → 보고서 출력 |
| **판정 로그** | Markdown (`.md`) | Reporting → 보고서 출력 |
| **개선 로드맵** | PDF 내 30/60/90일 카드형 | 결과 PDF 끝 부분 |

다운로드 파일명 규칙: **`Readyz-T_<사용자명>_<날짜>_<용도>.<ext>`**
예: `Readyz-T_서진우_2026-05-25_결과보고서.pdf`

---

## 📁 디렉토리 구조

```
zt-assessment/
├── frontend/                    React 18 + TypeScript + Vite
│   ├── src/
│   │   ├── app/
│   │   │   ├── pages/           Login, Dashboard, NewAssessment, InProgress, Reporting, History, Settings
│   │   │   ├── components/      RootLayout 등
│   │   │   ├── context/         AuthContext, NotificationContext
│   │   │   ├── data/            mockData, evidenceGuide, checklistItems, constants
│   │   │   └── lib/             maturity, pillar, settingsStore
│   │   ├── config/              api.ts (apiFetch, 다운로드 헬퍼)
│   │   └── types/               api.ts (TypeScript 인터페이스)
│   └── package.json
│
├── backend/                     Python 3.11 + FastAPI
│   ├── routers/                 8 라우터
│   │   ├── auth.py              인증·회원·비밀번호 정책·잠금
│   │   ├── assessment.py        진단 실행·결과·OCSF
│   │   ├── score.py             점수 요약·추이
│   │   ├── report.py            PDF·xlsx·md 산출물 생성
│   │   ├── improvement.py       개선 권고
│   │   ├── manual.py            수동 양식 다운로드·업로드·증적
│   │   ├── checklist.py         체크리스트 조회
│   │   └── validators.py        Nmap/Trivy target·URL·자격 검증
│   ├── collectors/              자동 수집기
│   │   ├── keycloak_collector.py     65 함수
│   │   ├── wazuh_collector.py        122 함수
│   │   ├── nmap_collector.py         14 함수
│   │   ├── trivy_collector.py        11 함수
│   │   ├── http_headers_collector.py 보안 헤더 8종
│   │   └── web_evidence_collector.py DNS/TLS/security.txt/GitHub repo
│   ├── scoring/engine.py        결과 → MaturityScore 계산
│   ├── scripts/                 seed_checklist, seed_demo_examples, seed_improvement, validate_checklist_mapping, cleanup_old_sessions
│   ├── models.py                SQLAlchemy 모델 (12 테이블)
│   ├── database.py              DB 연결
│   ├── main.py                  FastAPI 앱 + lifespan
│   ├── zt-checklist.xlsx        체크리스트 원본 (310 항목)
│   ├── zt-improvement-guide.xlsx 개선 권고 원본
│   └── manual-checklist.xlsx    수동 진단 양식 베이스
│
├── nmap-wrapper/                Flask 컨테이너 (8001)
├── trivy-wrapper/               Flask 컨테이너 (8002)
├── docker-compose.yml           9개 컨테이너 정의
├── deploy.sh                    배포 자동화 스크립트
├── stop.sh                      안전 정지 스크립트
└── .env.example                 환경 변수 템플릿
```

---

## 🔧 환경 변수

`.env` 파일 (`.env.example` 참고):

### 필수 — 운영

```bash
INTERNAL_API_TOKEN=             # 미설정 시 webhook 503 (fail-closed)
DB_HOST=mysql
DB_PORT=3306
DB_NAME=zt_assessment
DB_USER=readyz
DB_PASSWORD=                    # 강한 비번 설정
CORS_ORIGINS=                   # 명시적 도메인 콤마 구분, wildcard 금지
```

### 도구 fallback (사용자 입력 없을 때)

```bash
# IdP
KEYCLOAK_URL=http://keycloak:8080
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=admin

# SIEM
WAZUH_URL=https://wazuh:55000
WAZUH_USER=wazuh
WAZUH_PASSWORD=wazuh

# 외부 스캔
NMAP_WRAPPER_URL=http://nmap-wrapper:8001
TRIVY_WRAPPER_URL=http://trivy-wrapper:8002
NMAP_TARGET=127.0.0.1
TRIVY_TARGET=nginx:latest
```

### 운영 토글

```bash
ZTA_SESSION_RETENTION_DAYS=90            # 90일 후 세션 자동 삭제
ZTA_PROTECT_DEMO_DATA=true               # 시드 데이터 보호
ZTA_CLEANUP_DISABLE=                     # cleanup 비활성
ZTA_CLEANUP_INTERVAL_HOURS=24
ZTA_DEV_ALLOW_UNAUTH_WEBHOOK=            # 운영 금지 — dev 한정
```

---

## 🛠 운영 명령

### 시작 / 정지

```bash
# 시작 (재빌드 포함)
./deploy.sh local                # 로컬
./deploy.sh 1.2.3.4              # EC2 (퍼블릭 IP)

# 정지 (DB 데이터 100% 보존)
./stop.sh                        # 컨테이너만 정지 — 빠른 재시작 가능
./stop.sh down                   # 컨테이너+네트워크 제거 (볼륨 보존)
./stop.sh wipe                   # 전부 삭제 ("YES" 확인)

# 빠른 재시작 (코드 변경 없을 때)
docker compose start
```

### 상태 확인

```bash
docker compose ps                            # 컨테이너 상태
curl -s http://localhost:8000/health         # backend health
docker logs zt-assessment-zt-backend-1 -f    # backend 로그
```

### DB 직접 접근

```bash
docker exec -it zt-assessment-mysql-1 \
  mysql -ureadyz -p<DB_PASSWORD> zt_assessment
```

### 시드 재실행

```bash
docker exec zt-assessment-zt-backend-1 python /app/scripts/seed_checklist.py
docker exec zt-assessment-zt-backend-1 python /app/scripts/seed_demo_examples.py
docker exec zt-assessment-zt-backend-1 python /app/scripts/seed_improvement.py
```

### 검증

```bash
# xlsx ↔ 매핑 정합성 (자동 진단 212 항목 1:1)
docker exec zt-assessment-zt-backend-1 python /app/scripts/validate_checklist_mapping.py
```

---

## 🧑‍💻 개발 가이드

### 브랜치 전략

| 브랜치 | 역할 |
|---|---|
| `master` | 최종 배포본. 직접 push 금지 — dev fast-forward 또는 PR. |
| `semi-final` | 통합 베타. dev 의 변경을 검증하는 단계. |
| `dev` | 통합 개발. 모든 feature/* 작업이 합쳐지는 곳. |
| `feature/*` | 개발자별 작업 브랜치 (서진우, 공나영, 서정우, 송민희). |

### 개발 워크플로

```bash
# 1. dev 에서 feature 브랜치 시작
git checkout dev && git pull
git checkout -b feature/my-task

# 2. 작업 후 dev 에 머지
git checkout dev
git merge feature/my-task

# 3. semi-final 통합 테스트
git checkout semi-final
git merge dev
./deploy.sh local  # 검증

# 4. master 릴리스 (PR 또는 fast-forward)
git checkout master
git merge semi-final --ff-only
```

### 코드 규칙

1. **민감 정보는 `.env` 에서만 읽음** — 하드코딩 금지
2. **frontend ↔ backend 영역 분리** — 한쪽에서 다른 쪽 수정 금지
3. **모든 collector 반환은 공통 포맷 준수**:
   ```python
   {
     "item_id": "1.2.1.1_1", "maturity": "기존", "tool": "keycloak",
     "result": "충족" | "부분충족" | "미충족" | "평가불가",
     "metric_key": str, "metric_value": float, "threshold": float,
     "raw_json": dict, "collected_at": isoformat, "error": str | None,
   }
   ```
4. **세션 자격 비밀번호 절대 DB·로그·응답에 노출 금지**
5. **모든 입력은 `validators.py` 통과** — shell metachar 차단
6. **보호 엔드포인트는 `X-Login-Id` 의존성 + 세션·조직 권한 검증**

### 자체 검증

```bash
# Python 문법
python3 -c "import ast; ast.parse(open('파일').read())"

# frontend 빌드
cd frontend && npm run build

# 매핑 1:1 정합성
docker exec zt-assessment-zt-backend-1 python /app/scripts/validate_checklist_mapping.py

# 큰 변경 후 e2e
./deploy.sh local && curl -s http://localhost:8000/health
```

### 문서

- `CLAUDE.md` — 프로젝트 전반 가이드 + 시스템 상세 (개발자용)
- `STATUS.md` — 현재 상태 스냅샷
- `PLAN.md` — 작업 로드맵
- `README.md` — **이 파일** (외부용 소개)

---

## 🔒 보안 정책

### 인증

- **비밀번호 해싱**: PBKDF2-SHA256 600,000 라운드 (OWASP 2023)
- **정책**: 8자 이상 + 영문+숫자 (Pydantic field_validator)
- **Lazy upgrade**: 로그인 성공 시 저장 라운드가 600k 미만이면 자동 재해싱
- **로그인 잠금**: 5회 실패 → 60초 (HTTP 423 + Retry-After)

### 권한

- 모든 보호 엔드포인트 `X-Login-Id` 헤더 검증
- frontend apiFetch 자동 첨부 (register/login 제외)
- 세션 접근 — 본인 / 자기 조직 / admin
- `/history` — 일반 user 는 자기 조직 강제 필터
- `/run` — 본인 조직 외 진단 차단 (admin 제외)
- 보호 조직 (`시스템관리`, `세종대학교` 등) 자동 join 차단

### 자격 비밀번호 보호

- DB 평문 저장 **금지**. `session.extra` 에는 URL·사용자명만
- `_store_session_secrets` → 메모리 dict → `_pop_session_secrets` 즉시 폐기
- collector 호출 후 `set_session_creds(None)`
- 응답 마스킹: `admin_pass` / `api_pass` / `client_secret` → `"***"`
- 로깅 채널에 자격 절대 미포함

### 데이터 보관

- DiagnosisSession + 자식 5 테이블 **90일** 자동 삭제 (`ZTA_SESSION_RETENTION_DAYS`)
- FastAPI lifespan task 가 24h 주기 cleanup
- 시드 데이터 보호 (`ZTA_PROTECT_DEMO_DATA=true`)
- 스탠드얼론: `python backend/scripts/cleanup_old_sessions.py --days 90 [--dry-run]`

### 감사 로그

- 채널: `zt.audit` (stdlib logger)
- 이벤트: register / login(성공·실패·잠금) / profile update / change-password / cleanup
- 현재는 콘솔, 추후 DB 테이블화 예정

### 웹훅 보안

- `INTERNAL_API_TOKEN` 미설정 시 webhook **503 fail-closed**
- 로컬 dev 우회: `ZTA_DEV_ALLOW_UNAUTH_WEBHOOK=true` (운영 금지)

---

## 👥 팀 & 라이선스

### 캡스톤 팀 — 신뢰많이된다

- **서진우** (Lead) — 백엔드·진단 엔진·collector·PDF 산출물
- **공나영** (CISO) — 보안 정책·인증·권한
- **서정우** (CIO) — 인프라·CI/CD·EC2
- **송민희** (CTO) — 프론트엔드·UX

세종대학교 정보보호학과 캡스톤 2026.

### 외부 협력

- **SKT** — 최주용 팀장 (T-Markov Framework 평가 시연 지원)
- **앱엑스네트웍스** — 가원호 이사, 유병재 이사

### 라이선스

MIT License — 자유롭게 사용·수정·재배포 가능. 자세한 내용은 [`LICENSE`](LICENSE) 참조.

---

<div align="center">

**Made with 🛡️ by 신뢰많이된다 캡스톤팀**

[Issues](https://github.com/Allright24Gr/zt-assessment/issues) · [Discussions](https://github.com/Allright24Gr/zt-assessment/discussions)

</div>
