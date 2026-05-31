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
- **자동 수집 도구 8종 (265 자동 항목)** — 사용자 환경(Step 0 프로파일링)에 따라 선택
  - 🔐 **Keycloak** (65) · **Supabase** (14) — IdP / 인증 / MFA / 권한 관리
  - 🛡️ **Wazuh** (122) — SIEM / HIDS / 침입 탐지
  - 🌐 **Nmap** (14) · **Trivy** (15) · **web_probe** (24) — 외부 포트·TLS·이미지·SBOM·OIDC/DNS/CT log 스캔
  - 🚀 **Vercel** (6) · **Railway** (5) — SaaS 배포 플랫폼 보안 설정 점검
- **도구 무관 평가** — 가이드라인은 통제 요건 기준. 미지원 영역은 **수동 진단으로 자동 폴백**
- **보너스 자동 점검** — HTTP 보안 헤더, DNS (SPF/DMARC/CAA), TLS 인증서, `security.txt`, GitHub repo 보안 파일
- **수동 진단 폴백** — 환경에 맞춰 자동 미지원 항목을 Excel 양식으로 다운로드·작성·업로드

### 📊 결과 분석

- **종합 점수 + Pillar별 강·약점 레이더 차트**
- **30/60/90일 개선 로드맵** — Critical 우선 정렬
- **위험영역 대시보드** (관리자 뷰)
- **다른 세션과 비교** — 최대 4개 동시 비교
- **NIST 800-207 / CIS Controls v8 표준 매핑**

### 🔄 평가 착수 메타 (가이드 §3)

진단 시작 시 입력 → 보고서 첫 장 자동 표기:
- 평가 대상 버전 (Vercel/Railway deployment id, Git commit)
- 평가 범위 자산 목록 (Frontend URL·Backend API·Supabase·Notion·Drive·GitHub repo 등)
- 데이터 등급 분류 (영업 고객명·제안서·OAuth token 등 7종)
- 판정자 4역할 (App owner / Backend / Cloud / Security)
- 외부 스캔 승인 메타 (승인자·시간대·강도·제외경로·비상연락처)

### 🔔 알림 시스템

- 진단 완료, 시드 비번 사용, 수동 미완료 등 이벤트 알림
- localStorage 영속 + 종 아이콘 드롭다운

### 🛡️ 운영·보안 강화

- **운영 콘솔 (관리자)** — 시스템 상태 모니터링, 동적 운영 설정(재시작 없이 변경), DB 백업, 감사 로그 조회를 한 화면에서
- **위변조 방지 (무결성)**
  - 평가 결과 — 행 단위 SHA-256 해시. DB 직접 수정 시 `/api/assessment/verify` 가 탐지
  - 감사 로그 — 해시 체인. 중간 행 변조·삭제 시 `/api/admin/audit/verify` 가 위치까지 식별
- **목표 대비 분석** — 조직별 Pillar 목표 성숙도 설정 + 현재 점수와의 gap 자동 계산
- **주기 평가 스케줄링** — 지정 주기로 진단 자동 실행 (데모 모드)
- **시스템 모니터링** — Prometheus 텍스트 메트릭(`/metrics`) + JSON 상태 지표
- **증적 파일 at-rest 암호화** — 업로드 증적을 Fernet(AES) 로 디스크 암호화 저장
- **결과/리포트 캐싱** — 동일 세션 반복 조회 시 재계산 생략 (세션 변경 시 자동 무효화)
- **평가 소요시간·SLA** — 진단 수행 시간 측정 + SLA 충족 여부 표기
- **결과 검색 / 항목 커스터마이징** — 이력 검색 + 조직별 체크리스트 항목 enable·가중치 조정

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
  <img src="https://img.shields.io/badge/Supabase-3FCF8E?logo=supabase"/>
  <img src="https://img.shields.io/badge/Vercel-000000?logo=vercel"/>
  <img src="https://img.shields.io/badge/Railway-0B0D0E?logo=railway"/>
  <img src="https://img.shields.io/badge/web__probe-OIDC/DNS/TLS-4682B4"/>
</td>
</tr>
<tr>
<td>보안</td>
<td>
  <img src="https://img.shields.io/badge/JWT-access/refresh-000000?logo=jsonwebtokens"/>
  <img src="https://img.shields.io/badge/PBKDF2-600k-green"/>
  <img src="https://img.shields.io/badge/Fernet-at--rest-yellow"/>
  <img src="https://img.shields.io/badge/SHA--256-hash_chain-orange"/>
  <img src="https://img.shields.io/badge/Prometheus-metrics-E6522C?logo=prometheus"/>
</td>
</tr>
</table>

---

## 🏗 아키텍처

```
┌──────────────────────────────────────────────────────────────────┐
│         사용자 브라우저   http://<host>:8080                        │
│  Dashboard · 진단신청 · InProgress · Reporting · 운영콘솔(admin)    │
└──────────────────────────────┬───────────────────────────────────┘
                  ┌────────────▼────────────┐
                  │  zt-web (Nginx + React)  │  :8080
                  └────────────┬────────────┘
       ┌─────────────────────────▼─────────────────────────────────┐
       │ zt-backend (FastAPI)  :8000                                │
       │  routers: auth·assessment·score·report·improvement·        │
       │           manual·checklist·admin·settings                  │
       │  lifespan: 90일 cleanup · 주기 평가 스케줄러 · 자동 백업       │
       └────┬───────────┬──────────┬───────────┬───────────────────┘
            │           │          │           │
   ┌────────▼┐  ┌───────▼┐  ┌──────▼┐   ┌──────▼──────────┐
   │ MySQL 8 │  │Keycloak│  │ Wazuh │   │ SaaS API        │
   │ 3306    │  │ 8443   │  │ 55000 │   │ Supabase·Vercel │
   └─────────┘  └────────┘  └───────┘   │ ·Railway        │
                     │                  └─────────────────┘
       ┌─────────────┼──────────────┐
   ┌───▼───────┐ ┌───▼────────┐ ┌───▼──────────┐
   │nmap-wrapper│ │trivy-wrapper│ │ web_probe    │
   │Flask :8001 │ │Flask :8002  │ │ OIDC/DNS/TLS │
   └───┬────────┘ └─────────────┘ └───┬──────────┘
       │                              │
       ▼                              ▼
   ┌──────────────────────────────────────────────────┐
   │ 외부 진단 대상 (고객 시스템)                        │
   │ - 공개 도메인 / 배포본 (예: example.com)            │
   │ - 우리는 outbound 호출만 — agent/sidecar 설치 X     │
   └──────────────────────────────────────────────────┘
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
        + DiagnosisResult.row_hash (SHA-256 무결성, SER-010) + 결과 캐시 무효화

[주기 실행] lifespan 스케줄러가 도래한 ScheduledAssessment 를 데모 모드로 자동 재진단
[운영]     /metrics(Prometheus) · /api/admin/{audit,config,backup,metrics}
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
# .env 는 선택사항 — 없으면 docker-compose 데모 기본값으로 그대로 실행된다(무설정 제출본 대응).
# 운영·외부 도구 연동 시에만 .env 를 만들어 SECRET_KEY·DB 비밀번호 등을 채운다:
cp .env.example .env   # (선택) 운영 시에만
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
| **메인 사이트** | http://localhost:8080 | 사용자용 진단 화면 |
| **API 헬스체크** | http://localhost:8000/health | `{"status":"ok"}` 응답 |
| **Keycloak (옵션)** | http://localhost:8443 | 진단 대상 — admin/admin |
| **Wazuh (옵션)** | https://localhost:55000 | 진단 대상 |

### 4. 시드 계정으로 로그인

| 계정 | 비번 | 역할 | 용도 |
|---|---|---|---|
| `admin` | `admin` | 관리자 | 전체 진단 이력 조회 |
| `user1` | `user1` | 사용자 (박기웅, 세종대학교) | 데모 모드 시연 |
| `user2` | `user2` | 사용자 (서진우, 데모 기업) | 실 스택 평가 시연 |

> ⚠️ 시드 비밀번호는 *시연 편의* 를 위한 4자입니다. 운영 환경에서는 로그인 즉시 변경 권장. Dashboard 에 노란 배너로 안내합니다.

---

## 🔁 진단 흐름 — 진단 전 · 중 · 후

진단은 **준비(전) → 실시간 수집(중) → 결과·활용(후) → 운영·지속** 의 라이프사이클로 진행된다.

### 1️⃣ 진단 전 — 준비 (NewAssessment, Step 0~3)

- **Step 0 · 사전 환경 프로파일링** — IdP(Keycloak/Supabase/Entra/Okta/LDAP/없음) · SIEM(Wazuh/Splunk/Elastic/없음) · 외부 스캔(Nmap/Trivy) · **데모 ↔ 실 스캔** 토글. 미지원 옵션은 *수동 진단 자동 폴백*.
- **Step 1 · 기관 정보** — 부서·산업군·인프라(온프레/AWS/Azure/GCP/**SaaS형**/하이브리드)·규모 + 가이드 §3 착수 전 확정 **4카드**(평가 대상 버전 / 범위 자산 / 데이터 등급 / 판정자 4역할).
- **Step 2 · 진단 범위** — 6 Pillar 선택(첫 평가는 전체 권장). *수동 양식 미리 작성* 옵션 — 세션 선생성 → 환경 맞춤 xlsx, 비고에 공개 URL 자동점검 결과(HTTP 헤더·DNS·TLS·GitHub) prefill.
- **Step 3 · 외부 스캔 동의 + 시작** — 승인자·시간대·강도·제외경로·비상연락처(가이드 §3·§4) 입력 → 자동 collector 실행.

### 2️⃣ 진단 중 — 실시간 수집 (InProgress)

- **실시간 진행률** — 도구별·필러별 카운트 + 250ms 폴링 + 평균 속도 기반 **동적 ETA**
- **병행 작업** — 진행 중에도 수동 양식 다운로드/업로드 + 항목별 증적 파일(PDF/이미지) 첨부 (증적은 **at-rest 암호화** 저장)
- **무침해 수집** — 우리 서버에서 outbound 호출만(agent/sidecar 설치 X). 미연결 도구는 일괄 "평가불가"로 안전 처리, collector 실패는 재시도 후 부분 결과
- **자동 채점** — 수집 완료 시 `score_session` → 점수·등급 + **결과 무결성 해시** 생성 → `/reporting/{id}` 자동 이동

### 3️⃣ 진단 후 — 결과·활용 (Reporting)

- **종합 결과** — 점수·등급·AS-IS/TO-BE 레이더·위험영역 + **목표 대비 gap**(조직별 목표 성숙도) + **소요시간·SLA**
- **세부 항목** — 카테고리 카드 → 4단계 펼침, 판정 근거·출처·평가불가 사유 표기
- **개선·표준** — 30/60/90일 개선 로드맵(가이드 §8) · NIST 800-207 / CIS v8 매핑 · OCSF 1.1.0 이벤트
- **산출물 출력** — PDF 보고서 / 증적 목록 xlsx / 판정 로그 md (아래 §산출물 참조)
- **결과 활용**
  - 🔗 **공유 링크** — 인증 없이 조회 가능한 토큰 링크 (만료·취소 가능)
  - 📊 **세션 비교** — 최대 4개 동시 비교로 추이 분석
  - 🔎 **이력 검색** — 조직·담당자·레벨·상태로 과거 진단 검색
  - 🛡️ **무결성 검증** — `/api/assessment/verify` 로 결과 위변조 확인
  - 🔁 **재진단** — 보완 양식 업로드 후 재채점, 점수 변화 추적

### 4️⃣ 운영·지속 (관리자)

- **주기 평가 스케줄링** — 지정 주기로 자동 재진단(데모 모드)하여 성숙도 변화를 지속 추적
- **운영 콘솔** — 시스템 상태 모니터링 · 동적 설정(재시작 없이) · DB 백업/복구 · 감사 로그 + 해시 체인 검증
- **데이터 보관** — 90일 자동 삭제(시드 보호) · 감사 로그 DB 영속화 · `/metrics` Prometheus 노출

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
│   │   │   ├── pages/           Login·Signup·Dashboard·NewAssessment·InProgress·
│   │   │   │                    AssessmentNext·Reporting·History·Compare·Settings·
│   │   │   │                    AdminConsole·SharedResult·PasswordReset*
│   │   │   ├── components/      RootLayout 등
│   │   │   ├── context/         AuthContext, NotificationContext
│   │   │   ├── data/            mockData, evidenceGuide, checklistItems, constants
│   │   │   └── lib/             maturity, pillar, settingsStore, datetime, toolLabel
│   │   ├── config/              api.ts (apiFetch, 다운로드 헬퍼)
│   │   └── types/               api.ts (TypeScript 인터페이스)
│   └── package.json
│
├── backend/                     Python 3.11 + FastAPI
│   ├── routers/                 10 라우터
│   │   ├── auth.py              인증·회원·JWT·비밀번호 정책·잠금
│   │   ├── assessment.py        진단 실행·결과·스케줄·무결성검증·OCSF
│   │   ├── score.py             점수 요약·추이
│   │   ├── report.py            PDF·xlsx·md 산출물 생성
│   │   ├── improvement.py       개선 권고
│   │   ├── manual.py            수동 양식·업로드·증적(at-rest 암호화)
│   │   ├── checklist.py         체크리스트 조회
│   │   ├── admin.py             체크리스트 관리·감사조회·메트릭·동적설정·백업
│   │   ├── settings.py          조직 목표 성숙도·체크리스트 커스터마이징
│   │   └── validators.py        target·URL·자격 입력 검증(메타문자 차단)
│   ├── collectors/              자동 수집기 10종 (265 자동 항목)
│   │   ├── keycloak(65)·wazuh(122)·nmap(14)·trivy(15)
│   │   ├── web_probe(24)·supabase(14)·vercel(6)·railway(5)
│   │   └── http_headers·web_evidence (보안헤더·DNS·TLS·GitHub repo)
│   ├── services/                crypto·integrity·cache·config_store·metrics·
│   │                            email_sender·ocsf_transformer·standards_mapping 등
│   ├── scoring/engine.py        결과 → MaturityScore 계산
│   ├── scripts/                 seed_*·migrate_schema·backup_db·cleanup_old_sessions·
│   │                            validate_checklist_mapping
│   ├── tests/                   pytest (auth·IDOR·cleanup·validators·매핑·도구해석)
│   ├── models.py                SQLAlchemy 모델 (17 테이블)
│   ├── database.py              DB 연결
│   ├── main.py                  FastAPI 앱 + lifespan(cleanup·스케줄러·백업) + /metrics
│   ├── zt-checklist.xlsx        체크리스트 원본 (310 항목)
│   ├── zt-improvement-guide.xlsx 개선 권고 원본
│   └── manual-checklist.xlsx    수동 진단 양식 베이스
│
├── nmap-wrapper/                Flask 컨테이너 (8001)
├── trivy-wrapper/               Flask 컨테이너 (8002)
├── docker-compose.yml           컨테이너 정의 (web·backend·mysql·keycloak·wazuh·es·wrappers)
├── deploy.sh                    배포 자동화 (.env 없으면 데모 기본값 자동 생성)
├── stop.sh                      안전 정지 스크립트
└── .env.example                 환경 변수 템플릿 (선택)
```

---

## 🔧 환경 변수

> **`.env` 는 선택사항** — 없으면 `docker-compose.yml` 의 데모 기본값(`DB_USER=zt_user` / `DB_PASSWORD=ztDemo1234` 등)으로 그대로 실행된다. 운영 시에만 아래 값을 `.env` 로 덮어쓴다. (`.env.example` 참고)

### 운영 — 기본값 덮어쓰기 (권장)

```bash
SECRET_KEY=                     # JWT 서명 + 증적 암호화 키 파생. 32+ char (미설정 시 부팅마다 임시키)
DB_HOST=mysql
DB_PORT=3306
DB_NAME=zt_assessment
DB_USER=zt_user
DB_PASSWORD=                    # 강한 비번 (데모 기본값 ztDemo1234)
CORS_ORIGINS=                   # 명시적 도메인 콤마 구분, wildcard 금지
ZTA_ENCRYPTION_KEY=             # (선택) 증적 at-rest 전용 Fernet 키. 미설정 시 SECRET_KEY 파생
ZTA_FORCE_HTTPS=                # true 면 http→https 리다이렉트 (프록시 뒤 X-Forwarded-Proto 존중)
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
# 신규 기능 (모두 admin 운영 콘솔에서 재시작 없이 동적 변경 가능)
ZTA_ASSESSMENT_SLA_SECONDS=600           # 평가 수행 시간 SLA 기준(초)
ZTA_SCHEDULER_ENABLE=true                # 주기 평가 스케줄러
ZTA_BACKUP_INTERVAL_HOURS=0              # 자동 DB 백업 주기(0=비활성)
ZTA_RESULT_CACHE_TTL=300                 # 결과/리포트 캐시 TTL(초)
ZTA_COLLECTOR_RETRY=3                    # collector 실패 재시도 횟수
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
  mysql -uzt_user -p<DB_PASSWORD> zt_assessment   # 데모 기본 비번: ztDemo1234
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

### 감사 로그 · 무결성

- 채널: `zt.audit` (stdlib logger) + **`AuthAuditLog` DB 테이블 영속화**
- 이벤트: register / login(성공·실패·잠금) / profile update / change-password / cleanup
- **해시 체인** — 각 행이 직전 행 해시를 묶어 SHA-256. 위변조·삭제 시 `/api/admin/audit/verify` 가 탐지
- **평가 결과 무결성** — 결과 행별 해시 저장 → `/api/assessment/verify/{id}` 로 변조 검증
- **민감 데이터 암호화** — 업로드 증적 파일 Fernet at-rest 암호화 (키: `ZTA_ENCRYPTION_KEY` 또는 `SECRET_KEY` 파생)

### 전송 보안

- 운영 nginx 가 80→443 강제 + HSTS. 앱 레벨에서도 보안 헤더 부착(HSTS·X-Frame-Options·nosniff 등)
- `ZTA_FORCE_HTTPS=true` 시 http 요청을 https 로 리다이렉트 (프록시 뒤 `X-Forwarded-Proto` 존중)

---

## 👥 팀 & 라이선스

### 캡스톤 팀 — 신뢰많이된다

- **서진우** (Lead) — 백엔드·진단 엔진·collector·PDF 산출물
- **공나영** (CISO) — 보안 정책·인증·권한
- **서정우** (CIO) — 인프라·CI/CD·EC2
- **송민희** (CTO) — 프론트엔드·UX

세종대학교 정보보호학과 캡스톤 2026.

### 라이선스

MIT License — 자유롭게 사용·수정·재배포 가능. 자세한 내용은 [`LICENSE`](LICENSE) 참조.

---

<div align="center">

**Made with 🛡️ by 신뢰많이된다 캡스톤팀**

[Issues](https://github.com/Allright24Gr/zt-assessment/issues) · [Discussions](https://github.com/Allright24Gr/zt-assessment/discussions)

</div>
