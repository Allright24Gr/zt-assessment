# Readyz-T — SKT 미팅 브리프 & PPT 작성 지시서

> 작성: 2026-05-17 / 대상: SKT 부장님 미팅 (2026-05-18) / 용도: Claude 앱에 PPT 작성 지시
> 본 문서는 ① 미팅 컨텍스트, ② PPT 슬라이드 12장 구성안(슬라이드별 핵심 메시지 + 데이터),
> ③ 라이브 데모 시나리오, ④ Q&A 예상·답변 으로 구성. PPT 만들 때 슬라이드 단위로 그대로 옮겨 쓰면 됨.

---

## 0. 미팅 컨텍스트

| 항목 | 내용 |
|---|---|
| 일시 | 2026-05-18 |
| 상대 | SKT 부장님 (보안/통신/SK쉴더스 인접) |
| 우리 측 | 서진우 (lead) |
| 주제 | Readyz-T — 제로트러스트 가이드라인 2.0 진단 자동화 플랫폼 |
| 가능한 협업 모델 | (a) SKT 내부 보안 부서 도입 / (b) SKT 그룹사·고객사 진단 컨설팅 도구로 OEM / (c) SK쉴더스 매니지드 서비스 연계 |
| 발표 시간 | 15~20분 + Q&A 10분 가정 |

**한 줄 메시지 (Elevator Pitch)**
> "제로트러스트 가이드라인 2.0 진단을 **고객 인프라에 코드 한 줄도 설치하지 않고 outbound API 호출만으로** 자동화하는 SaaS — 14개 보안 도구 통합, 자동 진단 212개 항목, xlsx 학술 검증 1:1 정합, 시연 즉시 점수·권고 표시."

---

## 1. 핵심 차별점 (3가지만 강조)

1. **무침해 진단 (Agentless)** — 고객 EC2/온프레미스에 우리 코드·에이전트 절대 설치 안 함.
   우리 인프라에서 outbound HTTPS 호출 + 외부 스캔(nmap/trivy)만 사용.
   → 보안팀 거부감 ↓, 도입 시간 ↓ (계정만 발급하면 끝).

2. **도구 무관 (Tool-Agnostic)** — 고객이 어떤 도구를 쓰든 14종 중 골라 선택.
   - IdP 4종: Keycloak / **MS Entra ID** / Okta / 자체 LDAP·AD
   - SIEM 2종: Wazuh / Splunk
   - EDR 2종: CrowdStrike Falcon / MS Defender for Endpoint
   - 클라우드 자세(CSPM) 2종: AWS Security Hub / Azure Defender for Cloud
   - ZTNA 2종: Zscaler / Cloudflare Access
   - 외부 스캔(도구 무관) 2종: Nmap / Trivy
   미선택 영역은 자동으로 수동 진단으로 폴백 — 어떤 환경도 진단 가능.

3. **학술 검증된 매핑 (Verifiable)** — 우리가 임의로 "체크리스트 만들어 점수 매기는" 게 아니라
   가이드라인 2.0 공식 항목 212개 ↔ 14 도구의 측정 함수 212개를 **1:1 정합 검증 스크립트로 보증**.
   누락 0건, 잘못된 매핑 0건, 충돌 0건. (`validate_checklist_mapping.py` 자동 실행)

---

## 2. 숫자로 보는 현황 (2026-05-17 기준)

| 영역 | 수치 |
|---|---|
| **자동 진단 항목** | **212개** (제로트러스트 가이드라인 2.0 6 Pillar × 4 성숙도) |
| **수동 진단 항목** | 98개 (정책·문서·증적 기반) |
| **통합 도구 수** | **14개** (IdP 4 + SIEM 2 + EDR 2 + CSPM 2 + ZTNA 2 + 외부 스캔 2) |
| **collector 함수** | 357개 (base 243 + autodiscover 114) |
| **매핑 정합성** | xlsx 자동 진단 212 ↔ 매핑 unique 212 (1:1 정합) |
| **잘못된 매핑** | 0건 |
| **자동 테스트 케이스** | pytest 66 케이스 (auth 15 / IDOR 10 / mapping 14 / resolve 6 / validators 17 / cleanup 4) |
| **코드 규모** | backend ~14,000줄 / frontend src ~10,500줄 / 합 ~24,000줄 |
| **API 엔드포인트** | 40+ (auth / assessment / score / improvement / report / manual / admin) |
| **DB 테이블** | 12개 (User/Organization/Session/Checklist/CollectedData/Evidence/Result/MaturityScore/ImprovementGuide/ScoreHistory/AuthAuditLog/PasswordResetToken/SharedResult) |
| **개발 기간** | 최근 1개월 commit 25개+, 누적 commit 100+ |

---

## 3. PPT 슬라이드 12장 구성안

> 각 슬라이드는 한 페이지 한 메시지. 슬라이드 제목 + 본문 3~5 bullet + 시각 자료 1개 권장.

### 슬라이드 1 — 표지
- **제목**: Readyz-T
- **부제**: 제로트러스트 가이드라인 2.0 진단 자동화 플랫폼
- **하단**: 발표자명 / 날짜 / SKT 미팅
- **시각**: 단순 로고 또는 6 Pillar 다이어그램 미니멀

### 슬라이드 2 — 문제 정의 (Why Now)
**Title**: 왜 지금 제로트러스트 진단 자동화인가
- KISA "제로트러스트 가이드라인 2.0" 공표 (2024) → 공공·금융·통신 전반 적용 권고
- 현재 진단은 100% **수동 컨설팅** — 1회당 수주~수개월·수천만~수억원
- 도구 종속 (예: "Wazuh 안 쓰면 진단 못 함")으로 도입 거부감
- **공급 부족 + 단가 높음 + 도구 종속** = 자동화의 기회

### 슬라이드 3 — 솔루션 한눈에
**Title**: Readyz-T 가 풀어주는 것
- 무침해 자동 진단 — 고객 인프라에 우리 코드 0줄
- 도구 무관 — 14개 보안 도구 중 고객 환경에 맞춰 선택
- 가이드라인 2.0 공식 212항목 1:1 매핑 + 자동 점수·권고
- **데모 모드** 토글로 시연 즉시 점수·차트·로드맵 시각화
- 결과는 NIST 800-207 / CIS Controls v8 매핑까지 export
- **시각**: 사용자 → 우리 SaaS → outbound HTTPS → 고객 IdP/SIEM/EDR/Cloud (화살표 다이어그램)

### 슬라이드 4 — 진단 흐름 (Step 0~4)
**Title**: 사용자가 진단 1회를 끝내는 방법
1. **Step 0** 사전 프로파일링 — 우리 도구 환경 선택 (IdP/SIEM/EDR/Cloud/ZTNA) + 데모↔실 토글
2. **Step 1** 기관 정보 (가입 시 prefill)
3. **Step 2** 6 Pillar 진단 범위 체크
4. **Step 3** live 모드면 도구별 자격(URL/계정·시크릿) 입력
5. **Step 4** 외부 스캔 동의 → 진단 시작
- 모든 단계 5분 내. 진단 자체는 30초~수 분.
- **시각**: NewAssessment 페이지 스크린샷

### 슬라이드 5 — 14개 도구 통합 매트릭스
**Title**: 어떤 도구도 진단 가능
| 카테고리 | 도구 | 자동 항목 수 |
|---|---|---|
| IdP (4) | Keycloak / MS Entra ID / Okta / 자체 LDAP·AD | 65 / 20 / 15 / 15 |
| SIEM (2) | Wazuh / Splunk | 122 / 15 |
| EDR (2) | CrowdStrike Falcon / MS Defender for Endpoint | 15 / 15 |
| CSPM (2) | AWS Security Hub / Azure Defender for Cloud | 15 / 15 |
| ZTNA (2) | Zscaler / Cloudflare Access | 10 / 10 |
| 외부 스캔 (2) | Nmap / Trivy | 14 / 11 |
| **합계** | **14 도구** | **357 collector 함수** |
- 미선택 영역 → 수동 진단 자동 폴백

### 슬라이드 6 — 매핑 학술 검증 (차별점 강화)
**Title**: 우리가 임의로 만든 게 아니다
- 가이드라인 2.0 공식 체크리스트 (xlsx) 310행
  · 자동 진단 가능: 212행
  · 수동 진단: 98행
- 우리 14 도구가 **xlsx 자동 진단 212항목 ↔ unique item_id 212개 1:1 매핑**
- **검증 스크립트** `validate_checklist_mapping.py`:
  · 누락 0건 / 잘못된 매핑 0건 / 수동 충돌 0건 / 다중 매핑 54건(의도된 카테고리 다중)
- 모든 collector 함수 docstring 첫 줄에 `<item_id>:` 패턴 명시 → 회귀 가드 자동
- **시각**: 검증 스크립트 출력 캡처

### 슬라이드 7 — 점수 알고리즘 (학술적 정당성)
**Title**: 어떻게 채점하는가
- 4단계 성숙도 = `기존(1) → 초기(2) → 향상(3) → 최적화(4)`
- 결과 weight: 충족=1.0 / 부분충족=0.5 / 미충족=0.0 / **평가불가는 분모 제외**
- pillar 점수 = `Σ(maturity_score × weight) / Σ(maturity_score) × 4`
- **신뢰도(Confidence)**: 평가 가능 항목 / 전체 — 도구 미연결 시 점수 폭락 대신 신뢰도로 표시
- 최종 level: 모든 pillar가 N 이상 만족 → N 단계 (보수적 평가)
- **시각**: 6 Pillar 레이더 차트 + 신뢰도 카드 스크린샷

### 슬라이드 8 — 결과/보고서 (사용자가 받는 것)
**Title**: 진단 끝나면 무엇을 받나
- 6 Pillar 레이더 차트 (현재 vs 목표)
- 항목별 충족/부분/미충족/평가불가 상세 + 도구별 출처 배지
- **개선 로드맵** — 항목별 사용자 환경 맞춤 권고 (IdP/SIEM/EDR 12 프로파일 자동 치환)
- **위험-노력 매트릭스** — Quick Win / Major Project / Fill-in / Thankless 분류
- **표준 매핑 export** — NIST 800-207 7 tenets / CIS Controls v8 18 controls
- **PDF 보고서** — NanumGothic, 임원 보고용 (현재 디자인 1차, 고도화 보류)
- **공유 링크** — 토큰 기반 인증 없는 결과 조회 (만료 7일)
- **시각**: Reporting 페이지 스크린샷 (탭 4개 — 종합/세부/로드맵/출력)

### 슬라이드 9 — 보안·운영 수준 (B2B에 필요한 것)
**Title**: SaaS 운영 준비도
- **인증**: PBKDF2-SHA256 600,000 라운드 + JWT(8h/30d) + 비번 8자+영숫 + lazy upgrade
- **인증 방어**: login_id 5회 / IP 50회 잠금 (재시도 지수 백오프)
- **IDOR 차단**: 모든 보호 엔드포인트에 `assert_session_access` / `assert_org_access` 의존성 (pytest 10 케이스 회귀 가드)
- **자격 비밀번호**: DB 평문 저장 0 — 메모리 dict + Lock + 사용 후 즉시 폐기. 응답은 `***` 마스킹
- **감사 로그**: `zt.audit` 채널 + `AuthAuditLog` DB 테이블 영속화 (register / login / profile / password / cleanup)
- **데이터 보관**: 90일 자동 삭제 + 시드 보호 옵션
- **약관 동의**: 정보통신망법·개인정보보호법 대응 (가입 시 tos_agreed_at·privacy_agreed_at 기록)
- **회원 탈퇴**: 즉시 cascade 삭제 (DiagnosisSession + 자식 5 테이블 + 개인 조직)
- **무한 외부 스캔 방지**: live 모드 자격 미입력 가드 + finalize 수집 미완료 가드
- **자동 테스트**: pytest 66 케이스 (CI 자동화는 P2-16 보류)

### 슬라이드 10 — 아키텍처 다이어그램
**Title**: 시스템 구성 (Docker Compose, EC2 t3a.xlarge 1대)
```
[브라우저] ──HTTPS──→ [nginx 8443] ──→ [zt-web (Frontend)]
                                       └─→ [zt-backend (FastAPI 8000)]
                                            ├─→ [MySQL 8]
                                            ├─→ [nmap-wrapper] ── nmap CLI
                                            ├─→ [trivy-wrapper] ── trivy CLI
                                            └─(옵션)→ [Shuffle SOAR] ── Orborus worker
                                                              │
                                            outbound HTTPS ───┴──→ [고객 IdP/SIEM/EDR/Cloud/ZTNA]
```
- 단일 EC2(4vCPU/16GB)에 11 컨테이너 통합
- **배포 자동화**: `./scripts/bootstrap.sh <EC2_IP>` 한 줄 → swarm init + 컨테이너 + Shuffle 자동 가입 + 워크플로우 import + .env 자동 발급

### 슬라이드 11 — 시연 가능 / 운영 준비도
**Title**: 어디까지 됐나
| 영역 | 상태 |
|---|---|
| Core 진단 흐름 (Step 0~4 + 점수 + 결과) | ✅ 동작 (e2e session 31 overall 2.81 / 향상) |
| 14 도구 collector | ✅ 357 함수 통합, 매핑 1:1 검증 |
| **데모 모드 (즉시 시연)** | ✅ 토글로 충족 60% / 부분 25% / 미충족 15% 자동 생성 → 자동 채점 |
| 실 스캔 모드 | ✅ 자격 입력 시 외부 호출 (live), 누락 시 400 가드 |
| 인증·약관·탈퇴 | ✅ 완료 (P0 6개 모두) |
| 비교·공유·증적 업로드 | ✅ 완료 (P1 6개 모두) |
| 자동 테스트 / e2e 스크립트 | ✅ pytest 66 + e2e_smoke.sh |
| 운영 배포 (bootstrap.sh) | ✅ 완료 |
| **남은 작업** | Redis(다중 인스턴스) / CI·CD / Prometheus / Alembic / 운영 throttling (P2 - 1~3개월 내) |

### 슬라이드 12 — 다음 단계 (Ask)
**Title**: SKT와 가능한 협업
- **(a) 내부 도입 PoC** — SKT 그룹 내 1개 부서 진단 1건, 4주 소요. 결과로 정량적 ROI 산출.
- **(b) SK쉴더스 매니지드 서비스 연계** — 컨설팅 도구로 OEM/화이트라벨
- **(c) 공동 고객 진단** — SKT 고객사(공공·금융) 진단 대행
- **(d) 표준 기여** — KISA 가이드라인 후속(2.1, 3.0) 매핑 검증 파트너십
- **요청**: PoC 시작을 위한 미팅 1회 추가 / 데모 가능한 환경 셋업 (1시간)

---

## 4. 라이브 데모 시나리오 (5분, 화면 공유 가정)

> **준비**: bootstrap.sh 로 띄운 EC2 또는 localhost:8080. 미리 user1/user1 로 로그인 상태.

1. **(30초)** Dashboard — "이건 user1이 지금까지 진행한 3건 + 진행중 1건. 1920px 풀폭 활용, 가시성 강화"
2. **(60초)** New Assessment 클릭 → Step 0 "데모 모드" 라디오 그대로 → IdP=Keycloak, SIEM=Wazuh 선택 → Step 1~2 그대로 → Step 4 진단 시작
3. **(90초)** InProgress — "진행률이 자연스럽게 차오릅니다. 데모 모드는 외부 호출 0 — 시연 안전. 실 스캔이면 여기서 도구별 자격으로 외부 호출"
4. **(60초)** 완료 → Reporting "종합 결과" 탭 — 점수 2.81 / 향상 / 6 Pillar 레이더 / 신뢰도 100%
5. **(60초)** "세부 항목" 탭 — 항목별 충족 근거 + 도구 출처 배지 보여주기
6. **(60초)** "개선 로드맵" 탭 — 위험-노력 매트릭스 + 환경 맞춤 권고 (Keycloak 사용자에게는 Keycloak 가이드 첨부)
7. **(30초)** "보고서 출력" 탭 → PDF 다운로드 보여주기 + NIST 800-207 매핑 export
8. **(30초)** Settings → 진단 프로필 / 회원 탈퇴 / 비번 변경 모달

**대안 시연 (네트워크 안 될 때)**: 위 흐름의 정적 스크린샷 5장 + e2e 자동 검증 결과 JSON 출력.

---

## 5. 예상 Q&A

### Q1. "Wazuh/Keycloak 같은 오픈소스만 되는 거 아닌가?"
A. IdP 4종 / SIEM 2종 / EDR 2종 / CSPM 2종 / ZTNA 2종 — **상용·SaaS 글로벌 1위 제품(Okta/Splunk/CrowdStrike/MS Defender/AWS Security Hub/Azure/Zscaler/Cloudflare) 모두 포함**. 오픈소스 종속 아닙니다.

### Q2. "고객 자격을 받는데 보안은?"
A. (1) DB에 평문 저장 0 — 메모리 dict + Lock으로만 보관. (2) 사용 후 즉시 폐기 (`set_session_creds(None)` finally 블록). (3) API 응답은 `_mask_creds` 가 `admin_pass / api_pass / client_secret / api_token` 자동 마스킹. (4) HTTPS + JWT Bearer + IDOR 차단 의존성. (5) audit log DB 영속화로 추적성 확보.

### Q3. "212개 항목 매핑이 정말 정확한가? 임의 아닌가?"
A. `validate_checklist_mapping.py` 자동 검증 스크립트가 xlsx 공식 항목 ↔ 우리 매핑을 비교 — 누락 0 / 잘못 0 / 충돌 0 / 다중 매핑 54건은 의도된 카테고리 다중(같은 항목을 IdP 4종/SIEM 2종 등이 각자의 신호로 측정). 검증 스크립트가 매 빌드에서 회귀 차단 가능 (P2-16 CI에 추가 예정).

### Q4. "현재 한계는?"
A. 솔직하게 말씀드리면 (1) 다중 EC2 동시 운영을 위한 Redis 미도입 (현재 단일 인스턴스), (2) Prometheus/Grafana 모니터링 미설정, (3) PDF 디자인 임원 보고용 고도화 보류, (4) 증적 OCR/LLM 자동 파싱은 P3 보류. **모두 P2~P3 로드맵에 명시되어 있고 베타 1~3사 운영 1개월 동안 P2 완료 예정.**

### Q5. "도입 비용·기간은?"
A. **시연 PoC**: 1시간 내 EC2 띄우면 즉시 진단 1건 가능 (bootstrap.sh 한 줄). **정식 도입**: 고객별 IdP/SIEM 자격 발급(보안팀 절차 1~2주) + 도구별 권한 정책 검토 → 운영. SaaS 형태 / 온프레미스 둘 다 지원. 단가는 미팅 후 SKT 협의.

### Q6. "기존 컨설팅사·MSP와 어떻게 다른가?"
A. (1) **자동화** — 사람이 인터뷰·검토하는 일을 도구 API가 직접 측정. 진단 1건 30초~수 분. (2) **재현성** — 같은 환경에 진단을 N번 돌리면 같은 점수 (deterministic). (3) **추적성** — 모든 결과에 raw_json + 도구 출처 + 신뢰도 노출. (4) **컨설팅 대체 아님 — 보강** — 자동으로 잡히는 부분을 처리하고 컨설턴트는 인터뷰·정책 검토 같은 고부가가치에 집중.

### Q7. "SKT/SK쉴더스가 이미 비슷한 도구 있지 않나?"
A. (가능한 답) 보안 모니터링·SOAR(IBM QRadar, Splunk, Sentinel)는 다르지만, **가이드라인 2.0 공식 체크리스트 자동 매핑** 도구는 국내에서 보지 못했음. KISA 가이드라인이 2024년 공표라 시장이 막 형성 중. SKT 보안팀이 가진 운영 데이터·고객 접근성과 우리의 진단 자동화가 결합되면 강력한 차별점.

### Q8. "한국 KISA 가이드라인만 되나? 글로벌 표준은?"
A. 1차 구현은 KISA 가이드라인 2.0 기반. 이미 결과를 **NIST SP 800-207 (Zero Trust Architecture) 7 tenets** + **CIS Controls v8 18 controls** 로 export 합니다. 글로벌 진단 표준 매핑은 추가 항목 정의만 하면 즉시 확장 가능 (collector 자체는 도구 API 기반이라 표준에 무관).

---

## 6. PPT 작성 시 강조 톤

| 강조 | 회피 |
|---|---|
| 정량 지수(212/0/100%/2.81) | "최첨단" "AI" 같은 vague 단어 |
| 도구·표준 정확한 이름 (Keycloak/Splunk/NIST 800-207) | 줄임말 / 사내 약어 |
| 시연 가능한 화면 스크린샷 | 디자인 미완성된 화면 (남은 P2/P3 슬라이드는 12에 솔직히 명시) |
| 한계 솔직 인정 (Slide 11/12, Q4) | 모르는데 추측 답변 |
| SKT 측 시점 협업 옵션 3~4개 | 우리 요구만 일방적으로 |

**디자인 컨셉**: 미니멀 / 데이터 우선 / 색상은 진단 결과 색상(파랑=현재, 초록=목표, 빨강=위험)과 일관.

---

## 7. 부록 — 더 깊이 들어갈 때 (선택 자료)

- **운영 정책 / 시스템 상세** → `CLAUDE.md` (661줄)
- **현재 상태 스냅샷 / 디렉토리·DB·API 전체** → `STATUS.md`
- **로드맵 (Done / P0~P3 TODO)** → `PLAN.md`
- **배포 자동화** → `scripts/bootstrap.sh` + `DEPLOY.md`
- **자동 테스트** → `backend/tests/` (66 케이스)
- **매핑 검증 스크립트** → `backend/scripts/validate_checklist_mapping.py`
- **데모 진단 시드** → `python backend/scripts/seed_demo_examples.py`

---

## 8. 클로드 앱에 PPT 작성 지시할 때

위 §3 (슬라이드 12장 구성안)을 그대로 복사해서 다음과 같이 프롬프트 작성 권장:

> 다음 12장 슬라이드 구성으로 SKT 부장님 미팅용 PPT를 만들어줘. 톤은 §6 강조 톤 참고.
> 각 슬라이드는 한 페이지 한 메시지, 본문 3~5 bullet, 시각 자료 1개.
> 디자인은 미니멀 / 데이터 우선 / 파랑·초록·빨강 일관 색상.
> 발표 시간 15~20분 가정.
> [§3 본문 12 슬라이드 텍스트 붙여넣기]
