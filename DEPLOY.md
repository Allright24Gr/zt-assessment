# DEPLOY — 운영 배포 가이드

> 본 문서는 dev 단계에서 운영 EC2로 배포할 때의 단계별 가이드.
> 코드 동작 흐름·아키텍처는 `CLAUDE.md`, 현재 상태는 `STATUS.md`, 로드맵은 `PLAN.md`.

---

## 0. 사전 준비

| 항목 | 책임 | 비고 |
|---|---|---|
| EC2 인스턴스 (t3a.xlarge 권장) | 너 | Ubuntu 24.04 |
| 도메인 + DNS (A 레코드 → EC2 IP) | 너 | 예: `readyz-t.example.com` |
| AWS SES 프로덕션 모드 신청 | 너 | 1~3일 심사. 발신 도메인 + DKIM 검증 필요 |
| 발신 이메일 주소 + DKIM TXT 레코드 | 너 | SES 콘솔에서 발급된 값 DNS에 추가 |
| Let's Encrypt 인증서 (또는 ACM/사설 CA) | 너 | certbot으로 90일 자동 갱신 권장 |

---

## 1. 한 줄 배포 (개발 모드)

```bash
git clone https://github.com/Allright24Gr/zt-assessment.git
cd zt-assessment
cp .env.example .env
# .env 편집 (SECRET_KEY, DB_PASSWORD, INTERNAL_API_TOKEN 등 채우기)
docker compose up -d
```

이후 `http://localhost:8080` 접속. 시드 진단 데이터를 보려면:

```bash
docker compose exec zt-backend python scripts/seed_demo_examples.py --force
```

---

## 2. 운영 배포

### 2-1. `.env` 운영값 작성

다음 값들을 반드시 운영 값으로 교체:

```bash
# 보안 키
SECRET_KEY=$(openssl rand -hex 48)              # JWT 서명 (P0-1)
INTERNAL_API_TOKEN=$(openssl rand -hex 32)      # Shuffle webhook (운영 필수)

# DB
DB_PASSWORD=<강력한 비밀번호>
MYSQL_ROOT_PASSWORD=<강력한 비밀번호>

# CORS — wildcard 금지. 도메인 명시
CORS_ORIGINS=https://readyz-t.example.com

# 이메일 (AWS SES 프로덕션)
EMAIL_FROM=noreply@readyz-t.example.com
EMAIL_DRY_RUN=false
AWS_REGION=ap-northeast-2
# EC2 IAM role 사용 시 AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY 비워둠

# Frontend → backend
FRONTEND_BASE_URL=https://readyz-t.example.com
```

### 2-2. SSL 인증서 발급 (Let's Encrypt)

```bash
sudo apt-get update && sudo apt-get install -y certbot

# 임시로 80 포트 점유한 컨테이너 멈춤
docker compose stop nginx 2>/dev/null

# 인증서 발급
sudo certbot certonly --standalone \
    -d readyz-t.example.com \
    --email admin@readyz-t.example.com \
    --agree-tos --non-interactive

# 인증서를 nginx 컨테이너가 읽을 수 있는 경로로 복사
mkdir -p nginx/certs
sudo cp /etc/letsencrypt/live/readyz-t.example.com/fullchain.pem nginx/certs/
sudo cp /etc/letsencrypt/live/readyz-t.example.com/privkey.pem   nginx/certs/
sudo chmod 644 nginx/certs/*.pem
```

자동 갱신용 cron:

```bash
sudo crontab -e
# 매월 1일 03:00 갱신 시도 + nginx reload
0 3 1 * * certbot renew --quiet --post-hook "cp /etc/letsencrypt/live/readyz-t.example.com/*.pem /home/ubuntu/zt-assessment/nginx/certs/ && docker compose -f /home/ubuntu/zt-assessment/docker-compose.yml -f /home/ubuntu/zt-assessment/docker-compose.prod.yml exec nginx nginx -s reload"
```

도메인이 아직 없으면 self-signed로 시작:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout nginx/certs/privkey.pem \
    -out  nginx/certs/fullchain.pem \
    -subj "/CN=$(curl -s ifconfig.me)"
```

### 2-3. 운영 모드 기동

```bash
# 운영 stack — nginx 추가 + 외부 포트 보호 + 로깅
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# 진단 데모 도구 함께 띄우려면(시연용):
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile demo up -d
```

확인:

```bash
curl -sk https://readyz-t.example.com/health
# {"status":"ok"}
```

### 2-4. 시드 데이터 적재 (최초 1회)

```bash
docker compose exec zt-backend python scripts/seed_checklist.py
docker compose exec zt-backend python scripts/seed_improvement.py
docker compose exec zt-backend python scripts/seed_demo_examples.py
docker compose exec zt-backend python scripts/migrate_schema.py
```

기본 시드 계정:
- `admin / admin` — 관리자
- `user1 / user1` — 박기웅 (세종대학교)

> 운영 직후 두 계정 비번 즉시 변경 (frontend 노란 배너로 안내됨)

### 2-5. AWS SES 프로덕션 모드 신청

SES 콘솔 → "Request production access"
- 사용 사례: B2B 보안 진단 서비스 (회원 가입·비번 재설정·진단 완료 알림)
- 발신 도메인: `readyz-t.example.com`
- DKIM 검증: TXT 레코드 3개 DNS에 추가
- 1~3일 심사

심사 통과 전까지는 검증된 발신·수신 주소만 가능 (`EMAIL_DRY_RUN=false` 상태에서 메일이 실패해도 백엔드는 best-effort라 다른 흐름은 정상).

---

## 3. 운영 점검 체크리스트

배포 직후 한 번씩 확인:

- [ ] `curl -sk https://도메인/health` → `{"status":"ok"}`
- [ ] 회원가입 → 약관 동의 체크박스 노출 + 미체크 시 가입 불가
- [ ] 로그인 → JWT 토큰 받음 (개발자 도구 Network 탭에서 응답 확인)
- [ ] 비밀번호 변경 모달 → 8자+영문+숫자 정책 적용
- [ ] NewAssessment Step 0 → 데모 모드 토글 기본 ON 확인
- [ ] 데모 진단 1회 → 결과 페이지 출처 배지 (자동 외부/자동 API/수동) 표시
- [ ] InProgress → 동적 ETA 동작 (90초 고정 X)
- [ ] Reporting → 공유 링크 발급 + 익명 접근 가능
- [ ] PDF 다운로드 → 한글 폰트 깨짐 없음
- [ ] Settings → 비번 변경 + 회원 탈퇴 모달 동작
- [ ] `docker compose logs zt-backend | grep "zt.audit"` → 로그인/가입 이벤트 기록
- [ ] 90일 cleanup 동작: `docker compose exec zt-backend python scripts/cleanup_old_sessions.py --dry-run`

---

## 4. 운영 중 자주 쓰는 명령

```bash
# 로그 보기 (실시간)
docker compose logs -f zt-backend
docker compose logs -f nginx

# audit log만 필터
docker compose logs zt-backend | grep "zt.audit"

# 백엔드 재시작 (코드 배포 후)
git pull && docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build zt-backend

# DB 백업 (수동)
docker compose exec mysql mysqldump -u root -p$MYSQL_ROOT_PASSWORD zt_assessment > backup_$(date +%Y%m%d).sql

# 임의로 90일 cleanup 즉시 실행
docker compose exec zt-backend python scripts/cleanup_old_sessions.py

# audit log 조회 (DB)
docker compose exec mysql mysql -u root -p$MYSQL_ROOT_PASSWORD -e "SELECT event_type,login_id,source_ip,created_at FROM zt_assessment.AuthAuditLog ORDER BY created_at DESC LIMIT 20"
```

---

## 5. 비상 대응

### 디스크 풀
```bash
docker system prune -af --volumes  # 캐시 정리 (주의 — 데이터 볼륨도 영향 가능)
# 또는 evidence 디렉토리 점검
du -sh evidence/
```

### MySQL 깨짐
```bash
docker compose down
docker volume rm zt-assessment_mysql-data  # 데이터 손실 — 백업 필수
docker compose up -d
docker compose exec zt-backend python scripts/seed_checklist.py
```

### JWT 키 유출 의심
```bash
# 새 SECRET_KEY 발급 + .env 갱신
SECRET_KEY=$(openssl rand -hex 48)
docker compose restart zt-backend
# 모든 기존 토큰 무효화. 모든 사용자 강제 재로그인됨.
```

### nginx SSL 인증서 만료
```bash
sudo certbot renew --force-renewal
cp /etc/letsencrypt/live/readyz-t.example.com/*.pem nginx/certs/
docker compose exec nginx nginx -s reload
```

---

## 6. 운영 권장 사양

| 항목 | 권장 |
|---|---|
| EC2 인스턴스 | t3a.xlarge (4vCPU / 16GB). 진단 동시 수 ≤ 5 |
| 디스크 | 100GB gp3. 증적 파일 누적 + DB |
| 백업 | DB 일일 자동 백업 → S3 (PLAN.md P3-29) |
| 모니터링 | CloudWatch 또는 Prometheus (PLAN.md P2-15) |
| 보안 그룹 | inbound: 80, 443 만. SSH는 운영 IP에서만 |
| Fail2ban | 22번 포트 brute force 방어 |

---

## 7. 환경 분리

| 환경 | 명령 | 용도 |
|---|---|---|
| 개발 (로컬) | `docker compose up` | 빠른 반복, 8080 직접 |
| 시연 (EC2 + 데모 도구) | `docker compose -f .. -f docker-compose.prod.yml --profile demo up -d` | 영상 촬영. Keycloak·Wazuh도 띄움 |
| 운영 (EC2 + 실 고객) | `docker compose -f .. -f docker-compose.prod.yml up -d` | 데모 도구 X. 사용자 환경 자격 입력만 |

---

## 8. 트러블슈팅

| 증상 | 원인 | 조치 |
|---|---|---|
| 회원가입 400 "약관에 동의해야" | tos_agreed/privacy_agreed 미전송 | frontend 빌드 최신화 |
| 로그인 후 401 무한 루프 | JWT 토큰 만료 + refresh 실패 | localStorage `zt_tokens` 지우고 재로그인 |
| 진단 시작 후 collector 모두 평가불가 | 도구 자격 미입력 (placeholder URL) | Step 0에서 사용 도구 선택 + 자격 입력 |
| 비번 재설정 메일 안 옴 | SES 샌드박스 (검증된 주소만) 또는 SES 미설정 | SES 프로덕션 모드 신청. 임시: EMAIL_DRY_RUN=true |
| nginx 502 Bad Gateway | zt-backend 미기동 또는 healthcheck 실패 | `docker compose logs zt-backend` 확인 |
| 90일 자동 삭제 안 됨 | `ZTA_CLEANUP_DISABLE=true` 또는 lifespan task 미동작 | env 확인 + 백엔드 재기동 |
