Create a complete, detailed sitemap diagram for a web dashboard product called "Readyz-T", which is a Zero Trust maturity level automated assessment system. The sitemap must be fully detailed, production-ready, and require no additional prompting.

---

## Design System

Typography: Use Pretendard or Inter font throughout
Corner radius: 8px on all boxes
Background: White (#FFFFFF)
Canvas size: As wide and tall as needed to fit all content without overlap

Color coding (strictly follow this):
- Blue filled box (#E6F1FB border #185FA5): Main page (top-level navigation)
- White box with gray border (#888780): Sub-page or feature section
- Light green box (#EAF3DE border #3B6D11): Data fields / displayed values / information shown on screen
- White box with dashed gray border: Shared / common UI elements
- Orange dashed arrow (#EF9F27): Shortcut navigation between pages

Legend: Place a clearly labeled legend box in the top-left corner explaining all colors and line types before the diagram begins.

---

## Layout Rules

- Root node at the top center: "Readyz-T 웹 대시보드"
- 6 main page columns horizontally below the root, evenly spaced
- Each column expands downward with sub-features, then data fields below those
- Columns from left to right: Dashboard / New Assessment / In-Progress / Reporting / History / Settings
- Add a full-width dashed box at the very top (below legend, above root) showing the common layout elements shared across all pages
- All connections are straight lines with right-angle bends where needed
- Minimum 40px spacing between sibling nodes, minimum 60px between levels
- No overlapping boxes or lines anywhere

---

## Full Content

### [공통 레이아웃] — Full-width dashed box
- 네브바: 로고 / 현재 세션명 / 오류 알림 아이콘 / 사용자 정보
- 사이드바: Dashboard / New Assessment / History / Settings

---

### Column 1: Dashboard (홈)

Main page box: "Dashboard"

Sub-features:
- 최근 진단 세션 카드
- 성숙도 레이더 차트 미리보기
- 성숙도 추이 그래프
- 빠른 실행 버튼

Data fields under 최근 진단 세션 카드:
- 기관명 / 담당자 / 진단 날짜 / 종합 성숙도 등급

Data fields under 성숙도 레이더 차트 미리보기:
- 6개 필러 현재 수준 표시

Data fields under 성숙도 추이 그래프:
- 시간순 성숙도 변화 / 이전 회차 비교

Data fields under 빠른 실행 버튼:
- 새 진단 시작 버튼 → (orange dashed arrow to New Assessment)
- 마지막 진단 이어보기 버튼

---

### Column 2: New Assessment (새 진단)

Main page box: "New Assessment"

Sub-feature: Step 1 — 기업 환경 입력
  Data fields:
  - 기관명 / 담당자명 / 연락처 / 진단 날짜
  - 기관 유형 선택 (기업 / 공공기관 / 금융기관 / 의료기관)
  - 진단 범위 선택 (6개 필러 체크박스)
  - 분모값 입력 (전체 임직원 수 / 전체 서버 수 / 전체 애플리케이션 수 / 주요 시스템 수)
  - 외부 노출 서비스 유형 (웹 / API / VPN / 없음)
  - 증적 자료 업로드
  - 임시저장

Sub-feature: Step 2 — 수동 항목 직접 입력
  Data fields:
  - 필러별 그룹핑된 수동 체크리스트
  - 항목별 True / False 선택
  - 항목별 근거 문서 첨부
  - 입력 진행률 표시 (N개 중 N개 완료)

Sub-feature: Step 3 — 최종 확인 및 진단 시작
  Data fields:
  - 입력된 기업 정보 요약
  - 진단 범위 요약
  - 예상 소요 시간
  - 진단 시작 버튼 → (orange dashed arrow to In-Progress)

---

### Column 3: In-Progress (진단 중)

Main page box: "In-Progress"

Sub-feature: 진행 현황
  Data fields:
  - 전체 진행률 %
  - 예상 완료 시간
  - 6개 필러 원형 링 (진행 중 필러 강조 / 필러별 진행률 % 표시)

Sub-feature: Playbook 도구별 상태
  Data fields:
  - Wazuh 상태 (대기 / 실행 중 / 완료 / 실패) / 수집 항목 수
  - Keycloak 상태 (대기 / 실행 중 / 완료 / 실패) / 수집 항목 수
  - Trivy 상태 (대기 / 실행 중 / 완료 / 실패) / 수집 항목 수
  - Nmap 상태 (대기 / 실행 중 / 완료 / 실패) / 수집 항목 수

Sub-feature: 실시간 로그 스트림
  Data fields:
  - API 호출 내역
  - 캐시 HIT / MISS 여부
  - 오류 경고 배너
  - N/A 처리 안내

---

### Column 4: Reporting (진단 결과)

Main page box: "Reporting"

Sub-feature: 탭 1 — 종합 결과
  Data fields:
  - 종합 성숙도 등급 (기존 / 초기 / 향상 / 최적화)
  - AS-IS / TO-BE 레이더 차트 (6개 필러)
  - 필러별 점수 요약 카드 (6개)
  - 이전 진단과 비교 차트 (재진단 시)

Sub-feature: 탭 2 — 세부 항목 결과
  Data fields:
  - 필러별 드릴다운 테이블
  - 체크리스트 항목명 / 성숙도 단계 / True·False·N/A / 판정 근거
  - N/A 항목 사유 표시
  - 오류 발생 항목 별도 표시

Sub-feature: 탭 3 — 개선 과제
  Data fields:
  - GAP 분석 결과 (목표 단계 vs 현재 단계)
  - 개선 과제 우선순위 로드맵
  - 단기 / 중기 / 장기 분류
  - 항목 중요도 (Critical / High / Medium)

Sub-feature: 탭 4 — 보고서 출력
  Data fields:
  - PDF 미리보기
  - PDF 다운로드 버튼
  - 재진단 바로가기 버튼 → (orange dashed arrow to New Assessment)

---

### Column 5: History (진단 이력)

Main page box: "History"

Sub-feature: 세션 목록 테이블
  Data fields:
  - 기관명 / 진단 날짜 / 담당자 / 종합 성숙도 등급 / 상태
  - 세션 클릭 → (orange dashed arrow to Reporting)

Sub-feature: 세션 비교
  Data fields:
  - 최대 2개 세션 선택
  - 성숙도 비교 차트
  - 개선된 항목 / 악화된 항목 표시

---

### Column 6: Settings (설정)

Main page box: "Settings"

Sub-feature: 판정 임계값 설정
  Data fields:
  - Wazuh SCA score 기준값
  - Trivy CVE severity 기준 (Critical / High / Medium)
  - 커버리지 비율 기준값 (기본 90%)

Sub-feature: 알림 설정
  Data fields:
  - 진단 완료 알림 ON/OFF
  - 오류 발생 시 알림 ON/OFF

Sub-feature: 사용자 계정 정보
  Data fields:
  - 이름 / 이메일 / 소속 / 비밀번호 변경

---

## Shortcut Arrows (orange dashed)

Draw the following shortcut connections as orange dashed arrows with labels:
1. Dashboard "새 진단 시작" → New Assessment (label: "바로가기")
2. New Assessment Step 3 "진단 시작" → In-Progress (label: "진단 시작")
3. In-Progress 완료 → Reporting (label: "자동 이동")
4. Reporting "재진단 바로가기" → New Assessment (label: "재진단")
5. History 세션 행 클릭 → Reporting (label: "결과 보기")

---

## Final Instructions

- Label every single box in Korean (한국어)
- Do not leave any box unlabeled
- Do not overlap any elements
- Use generous whitespace between all nodes
- The diagram must be fully self-contained — no follow-up prompts should be needed
- Export or present the final result as a complete Figma frame titled "Readyz-T 사이트맵 v1.0"