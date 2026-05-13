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

IP: 3.35.200.145

OS: Ubuntu 24.04

Spec: t3a.xlarge (4vCPU / 16GB)

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
