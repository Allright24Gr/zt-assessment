# Readyz-T - Zero Trust 성숙도 진단 시스템

제로트러스트 가이드라인 2.0 기반 성숙도 진단 자동화 플랫폼.

## 프로젝트 구조

```
zt-assessment/
├── frontend/        React + Vite 프론트엔드
├── backend/         FastAPI 백엔드
├── nmap-wrapper/    Nmap CLI 래퍼 서버 (Flask)
├── trivy-wrapper/   Trivy CLI 래퍼 서버 (Flask)
├── deploy.sh        EC2 배포 스크립트
└── docker-compose.yml
```

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

---

## EC2 배포

### 1. 코드 받기

```bash
git clone https://github.com/Allright24Gr/zt-assessment
cd zt-assessment
git checkout dev
```

### 2. 배포 실행

EC2 퍼블릭 IP를 인자로 넘기면 끝. IP는 EC2 재시작마다 바뀌므로 매번 확인 후 입력.

```bash
./deploy.sh <EC2_퍼블릭_IP>
# 예: ./deploy.sh 1.2.3.4
```

인자 없이 실행하면 프롬프트로 물어봄:

```bash
./deploy.sh
# EC2 퍼블릭 IP를 입력하세요 (예: 1.2.3.4):
```

내부적으로 `VITE_API_BASE`, `CORS_ORIGINS`를 해당 IP로 세팅하고 `docker compose up -d --build` 실행.

### 3. 서비스 접속 주소 (EC2)

| 서비스 | 주소 |
|---|---|
| 프론트엔드 | `http://<EC2_IP>:8080` |
| 백엔드 API 문서 | `http://<EC2_IP>:8000/docs` |
| Shuffle UI | `http://<EC2_IP>:3001` |
| Keycloak | `http://<EC2_IP>:8443` |
| Wazuh API | `https://<EC2_IP>:55000` |

### 4. Shuffle 워크플로우 연동 (자동수집 사용 시)

1. `http://<EC2_IP>:3001` 에서 Shuffle UI 접속
2. 도구별 워크플로우 4개 생성 (Keycloak, Wazuh, Nmap, Trivy)
3. 각 워크플로우 ID를 `.env`에 입력:

```env
SHUFFLE_URL=http://shuffle-backend:5001
SHUFFLE_API_KEY=<Shuffle에서 발급>
SHUFFLE_WORKFLOW_KEYCLOAK=<워크플로우 ID>
SHUFFLE_WORKFLOW_WAZUH=<워크플로우 ID>
SHUFFLE_WORKFLOW_NMAP=<워크플로우 ID>
SHUFFLE_WORKFLOW_TRIVY=<워크플로우 ID>
```

4. 백엔드 재시작:

```bash
docker compose restart zt-backend
```

---

## 로컬 개발 환경

### 사전 준비

- Docker, Docker Compose 설치
- Git 설치

### 실행

```bash
git clone https://github.com/Allright24Gr/zt-assessment
cd zt-assessment
git checkout dev
docker compose up -d
```

### 서비스 접속 주소 (로컬)

| 서비스 | 주소 |
|---|---|
| 프론트엔드 | `http://localhost:8080` |
| 백엔드 API 문서 | `http://localhost:8000/docs` |
| Shuffle UI | `http://localhost:3001` |
| Keycloak | `http://localhost:8443` |
| Wazuh API | `https://localhost:55000` |
| Nmap 래퍼 | `http://localhost:8001` |
| Trivy 래퍼 | `http://localhost:8002` |

### 종료

```bash
docker compose down
```

---

## 브랜치 전략

| 브랜치 | 용도 |
|---|---|
| `main` | 최종 배포본 (직접 push 금지) |
| `dev` | 통합 테스트 브랜치 |
| `feature/*` | 기능 개발 브랜치 |

작업 흐름: `feature` 브랜치 → PR → `dev` 머지 → 테스트 후 `main` 머지

---

## 환경변수

`.env` 파일은 `.gitignore`에 포함되어 있어 GitHub에 올라가지 않음.
민감 정보(DB 비밀번호, API 키 등)는 절대 코드에 하드코딩하지 않는다.
