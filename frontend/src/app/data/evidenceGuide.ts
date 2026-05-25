// SKT 가이드 §5 — T-Markov 증적 준비표 (6 Pillar).
// 운영자가 양식 작성 시 어떤 증적을 준비해야 하는지 안내용으로 InProgress/Reporting
// 페이지에 토글로 노출.

export interface EvidenceGuideRow {
  pillar: string;
  pillarKey: string;
  prepare: string;     // 팀이 준비할 증적
  questions: string;   // 주요 질문
  cautions: string;    // 판정 시 주의점
}

export const EVIDENCE_GUIDE: EvidenceGuideRow[] = [
  {
    pillar: "식별자 및 신원",
    pillarKey: "identity",
    prepare:
      "로그인 방식, Google Workspace OAuth 설정, 관리자 계정 목록, MFA 정책, " +
      "세션 만료 정책, Supabase Auth/RLS 설정, 운영자 권한 부여·회수 절차.",
    questions:
      "사용자와 운영자 모두 강한 인증을 쓰는가? 데모 로그인과 운영 로그인은 분리되어 있는가? " +
      "서비스 계정과 OAuth token은 누가 관리하는가?",
    cautions:
      "공개 화면의 '아무 정보나 입력 후 진입'은 데모 범위라면 별도 라벨링, " +
      "운영 데이터 접근과 연결되어 있으면 신원 항목의 중대 리스크로 분류.",
  },
  {
    pillar: "기기 및 엔드포인트",
    pillarKey: "device",
    prepare:
      "개발자 PC 보안 정책, OneDrive 동기화 사용 정책, GitHub 접근 권한, " +
      "Railway/Vercel CLI 토큰 관리, 운영 단말 EDR/MDM 적용 여부.",
    questions:
      "배포 권한이 있는 단말은 식별·보호되는가? 로컬 OAuth token과 API key가 암호화·분리되는가?",
    cautions:
      "앱 자체보다 운영자 단말과 배포 도구가 핵심 자산입니다. Wazuh가 없으면 수동 증적으로 판단.",
  },
  {
    pillar: "네트워크",
    pillarKey: "network",
    prepare:
      "Vercel/Railway 도메인, DNS, HTTPS/HSTS 헤더, CORS 설정, API 공개 경로, " +
      "allowlist 정책, rate limit, backend CORS origin 설정.",
    questions:
      "공개되어야 할 endpoint만 열려 있는가? frontend, backend, DB 간 통신 경계가 명확한가? " +
      "CORS wildcard가 필요한가?",
    cautions:
      "공개 URL에서 Access-Control-Allow-Origin: *가 관찰되었습니다. " +
      "단순 취약점 단정은 금물이나, 인증 API와 결합될 경우 별도 검토 필요.",
  },
  {
    pillar: "시스템",
    pillarKey: "system",
    prepare:
      "Vercel/Railway/Supabase 보안 설정, 환경변수 목록의 redacted export, " +
      "secret rotation 기록, 백업·복구 절차, 장애 대응, audit log, 배포 권한.",
    questions:
      "secret은 코드와 분리되어 있는가? 장애·복구·권한 변경 이력이 남는가? " +
      "최소 권한으로 서비스 간 연결되는가?",
    cautions:
      "handoff 문서상 OAuth token, Google service account, Notion/Supabase key가 핵심입니다. " +
      "평문 파일, 장기 토큰, 과도한 scope를 별도 리스크로 봅니다.",
  },
  {
    pillar: "애플리케이션 및 워크로드",
    pillarKey: "application",
    prepare:
      "API 명세, 입력 검증, 인증/인가 흐름, dependency lockfile, Trivy/SCA 결과, " +
      "LLM prompt 처리 정책, SSRF/웹검색 도구 제한, CSP/보안 헤더, CI/CD 로그.",
    questions:
      "사용자의 영업 입력이 LLM/API로 전달될 때 보호되는가? build/download API는 권한 검사를 하는가? " +
      "의존성 취약점은 관리되는가?",
    cautions:
      "Anthropic, DART, KOTRA, Notion, Drive 연동은 supply chain과 데이터 유출 관점에서 함께 평가.",
  },
  {
    pillar: "데이터",
    pillarKey: "data",
    prepare:
      "Supabase 테이블/RLS, Notion DB 공유 권한, Drive 폴더 공유 범위, " +
      "usage log/feedback 보관 기간, 고객명·제안서·prompt 데이터 분류표, 삭제 요청 처리 절차.",
    questions:
      "고객 데이터와 데모 데이터가 분리되는가? LLM 입력과 산출물은 얼마나 보관되는가? " +
      "Drive/Notion 링크가 외부 공유되는가?",
    cautions:
      "제로트러스트 평가는 '앱이 돌아간다'보다 데이터 흐름과 최소 접근 제어가 더 중요합니다.",
  },
];
