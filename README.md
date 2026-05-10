# Readyz-T - Zero Trust 성숙도 진단 시스템

제로트러스트 가이드라인 2.0 기반 성숙도 진단 자동화 플랫폼.

## 프로젝트 구조

zt-assessment/
├── frontend/        React + Vite 프론트엔드
├── backend/         FastAPI 백엔드
├── nmap-wrapper/    Nmap CLI 래퍼 서버 (Flask)
├── trivy-wrapper/   Trivy CLI 래퍼 서버 (Flask)
└── docker-compose.yml

## 기술 스택

| 구분 | 기술 |
|---|---|
| 프론트엔드 | React, TypeScript, Vite, shadcn/ui, recharts |
| 백엔드 | Python, FastAPI, SQLAlchemy |
| 오케스트레이션 | Shuffle (SOAR) |
| 인증 진단 | Keycloak |
| 로그/엔드포인트 진단 | Wazuh |
| 네트워크 진단 | Nmap |
| 컨테이너 취약점 진단 | Trivy |
| 데이터 저장 | MySQL, Elasticsearch |
| 인프라 | Docker, Docker Compose, AWS EC2 |

## 로컬 개발 환경 세팅

### 사전 준비

- Docker, Docker Compose 설치
- Git 설치

### 실행 방법

git clone https://github.com/Allright24Gr/zt-assessment
cd zt-assessment
git checkout dev

# 환경변수 설정
cp .env.example .env
# .env 파일 열어서 값 채우기

# 전체 실행
docker compose up -d

### 서비스 접속 주소 (로컬)

프론트엔드:    http://localhost:8080
백엔드 API:    http://localhost:8000/docs
Shuffle:       http://localhost:3000
Keycloak:      http://localhost:8443
Elasticsearch: http://localhost:9200
Wazuh API:     https://localhost:55000
Nmap 래퍼:    http://localhost:5000
Trivy 래퍼:   http://localhost:5001

### 단계별 실행 (메모리 절약)

한 번에 전부 띄우면 메모리가 부족할 수 있다. 아래 순서로 단계별로 띄운다.

# 1단계 - DB + 백엔드
docker compose up -d mysql zt-backend

# 2단계 - Keycloak
docker compose up -d keycloak

# 3단계 - Wazuh + Elasticsearch
docker compose up -d elasticsearch wazuh

# 4단계 - 나머지
docker compose up -d shuffle nmap-wrapper trivy-wrapper zt-web

### 종료

docker compose down

## 브랜치 전략

main    최종 배포본 (직접 push 금지)
dev     통합 테스트 브랜치

feature/backend-skeleton
feature/keycloak-collector
feature/wazuh-collector
feature/nmap-trivy-wrapper
feature/frontend-api-connect
feature/shuffle-workflow
feature/scoring-engine

작업 흐름: feature 브랜치 → PR → dev 머지 → 테스트 완료 후 main 머지

## 환경변수

.env.example 파일을 복사해서 .env 파일을 만들고 값을 채운다.

cp .env.example .env

.env 파일은 절대 GitHub에 올리지 않는다.

