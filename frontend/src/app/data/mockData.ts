import { CHECKLIST_ITEMS } from "./checklistItems";

export interface ChecklistDetail {
  id: string;
  pillar: string;
  category: string;
  item: string;
  maturity: string;
  maturityScore: number;
  question: string;
  diagnosisType: string;
  tool: string;
  result: "충족" | "미흡" | "해당 없음";
  score: number;
  evidence: string;
  criteria: string;
  fields: string;
  logic: string;
  exceptions: string;
  recommendation: string;
  evidenceSummary?: {
    source: string;
    observed: string;
    location: string;
    reason: string;
    impact: number;
  };
  relatedImprovementIds?: string[];
}

export interface Session {
  id: number;
  org: string;
  date: string;
  manager: string;
  userId: string;
  level: string;
  status: string;
  score: number | null;
  errors: { code: string; message: string; severity: string }[];
  checklistDetails: ChecklistDetail[];
}

export interface Improvement {
  id?: string;
  task: string;
  priority: string;
  term: string;
  pillar: string;
  duration?: string;
  difficulty?: string;
  owner?: string;
  expectedGain?: string;
  relatedItem?: string;
  steps?: string[];
  expectedEffect?: string;
}

const PILLAR_CATEGORY_TO_KEY: Record<string, string> = {
  "식별자 및 신원": "Identify",
  "식별 및 신원": "Identify",
  "기기 및 엔드포인트": "Device",
  "네트워크": "Network",
  "시스템": "System",
  "애플리케이션 및 워크로드": "Application",
  "애플리케이션": "Application",
  "데이터": "Data",
};

const MATURITY_TO_SCORE: Record<string, number> = {
  "기존": 1,
  "초기": 2,
  "향상": 3,
  "최적화": 4,
};

function buildChecklist(seedScore: number | null): ChecklistDetail[] {
  return CHECKLIST_ITEMS.map((item, index) => {
    const pillarKey = PILLAR_CATEGORY_TO_KEY[item.category] ?? PILLAR_CATEGORY_TO_KEY[item.pillar] ?? item.pillar;
    const maturityScore = MATURITY_TO_SCORE[item.maturity] ?? item.maturityScore;
    const variation = ((index % 7) - 3) * 0.08;
    const rawScore = seedScore === null ? 0 : Math.max(0.5, Math.min(4, seedScore + variation));
    const score = Number(rawScore.toFixed(1));
    const result = seedScore === null ? "해당 없음" : score + 0.35 >= maturityScore ? "충족" : "미흡";

    return {
      ...item,
      pillar: pillarKey,
      maturityScore,
      result,
      score,
      recommendation: result === "충족"
        ? "현재 기준을 유지하면서 정기 점검 주기와 증적 보관 체계를 유지하세요."
        : `${item.maturity} 단계 기준을 충족하도록 증적, 정책, 자동화 로직을 보완하세요.`,
    };
  });
}

export const sessions: Session[] = [
  {
    id: 1,
    org: "ABC 기업",
    date: "2026-04-20",
    manager: "김철수",
    userId: "user1",
    level: "향상",
    status: "완료",
    score: 2.5,
    errors: [
      { code: "E001", message: "MFA 미적용 사용자 발견", severity: "High" },
      { code: "E012", message: "데이터 암호화 정책 미수립", severity: "Critical" },
    ],
    checklistDetails: buildChecklist(2.5),
  },
  {
    id: 2,
    org: "ABC 기업",
    date: "2026-03-15",
    manager: "김철수",
    userId: "user1",
    level: "초기",
    status: "완료",
    score: 1.8,
    errors: [
      { code: "E003", message: "네트워크 세그먼테이션 부족", severity: "Medium" },
    ],
    checklistDetails: buildChecklist(1.8),
  },
  {
    id: 3,
    org: "XYZ 금융",
    date: "2026-04-15",
    manager: "이영희",
    userId: "user2",
    level: "초기",
    status: "완료",
    score: 2.1,
    errors: [
      { code: "E005", message: "취약점 스캔 미실행", severity: "High" },
    ],
    checklistDetails: buildChecklist(2.1),
  },
  {
    id: 4,
    org: "DEF 공공기관",
    date: "2026-04-10",
    manager: "박민준",
    userId: "user3",
    level: "최적화",
    status: "완료",
    score: 3.2,
    errors: [],
    checklistDetails: buildChecklist(3.2),
  },
  {
    id: 5,
    org: "GHI 의료기관",
    date: "2026-04-05",
    manager: "최수아",
    userId: "user4",
    level: "향상",
    status: "완료",
    score: 2.7,
    errors: [
      { code: "E008", message: "로그 모니터링 자동화 부족", severity: "Medium" },
    ],
    checklistDetails: buildChecklist(2.7),
  },
  {
    id: 6,
    org: "ABC 기업",
    date: "2026-02-10",
    manager: "김철수",
    userId: "user1",
    level: "기존",
    status: "완료",
    score: 1.2,
    errors: [
      { code: "E001", message: "MFA 미적용", severity: "Critical" },
      { code: "E002", message: "디바이스 보안 정책 미수립", severity: "High" },
    ],
    checklistDetails: buildChecklist(1.2),
  },
  {
    id: 7,
    org: "JKL 제조사",
    date: "2026-04-27",
    manager: "정우진",
    userId: "admin",
    level: "진행 중",
    status: "진행 중",
    score: null,
    errors: [],
    checklistDetails: buildChecklist(null),
  },
];

export const improvements: Improvement[] = [
  { task: "사용자 인벤토리 문서화 및 활성 사용자·역할 부여 현황 정리", priority: "High", term: "단기", pillar: "Identify" },
  { task: "MFA 필수 적용 범위 점검 및 미적용 계정 우선 조치", priority: "Critical", term: "단기", pillar: "Identify" },
  { task: "세션 기반 인증 정책과 세션 만료 기준 재점검", priority: "High", term: "단기", pillar: "Identify" },
  { task: "리소스 연결 기기 식별을 위한 Nmap 기반 기초 자산 스캔 수행", priority: "High", term: "단기", pillar: "Device" },
  { task: "자산 접근 기기 정보 수집 상태와 Wazuh 에이전트 연결 누락 확인", priority: "High", term: "단기", pillar: "Device" },
  { task: "기기 인벤토리 최신화 및 수동 업데이트 책임자 지정", priority: "Medium", term: "단기", pillar: "Device" },
  { task: "비즈니스 영역별 매크로 세그멘테이션 현황 점검", priority: "High", term: "단기", pillar: "Network" },
  { task: "내·외부 트래픽 암호화 적용 범위와 미암호화 구간 식별", priority: "Critical", term: "단기", pillar: "Network" },
  { task: "사용자·기기 접근 권한 수동 부여 현황 정리 및 과권한 제거", priority: "High", term: "단기", pillar: "System" },
  { task: "PAM 구축 여부와 특권 계정 사용 증적 점검", priority: "Critical", term: "단기", pillar: "System" },
  { task: "애플리케이션 접근 권한 수동 관리 목록 정비", priority: "High", term: "단기", pillar: "Application" },
  { task: "원격 접속 VPN 및 외부 노출 포트 현황 점검", priority: "Critical", term: "단기", pillar: "Application" },
  { task: "데이터 자산 초기 카탈로그 작성 및 중요 데이터 식별", priority: "High", term: "단기", pillar: "Data" },
  { task: "데이터 접근 정책과 수동 암호화 적용 현황 점검", priority: "Critical", term: "단기", pillar: "Data" },

  { task: "외부 IdP 활성화 및 사용자 자격 증명 연동 범위 확대", priority: "High", term: "중기", pillar: "Identify" },
  { task: "사용자 활동·조건 기반 접근 로그를 Wazuh로 수집하고 탐지 룰 활성화", priority: "High", term: "중기", pillar: "Identify" },
  { task: "최소 권한 원칙을 역할 기반 접근제어 정책으로 구체화", priority: "High", term: "중기", pillar: "Identify" },
  { task: "엔드포인트 및 모바일 기기 관리 체계 도입 범위 확대", priority: "High", term: "중기", pillar: "Device" },
  { task: "EDR 탐지 이벤트 수집과 고위험 알림 기준 수립", priority: "High", term: "중기", pillar: "Device" },
  { task: "자산·취약성·패치 관리 현황을 정량 지표로 관리", priority: "High", term: "중기", pillar: "Device" },
  { task: "마이크로 세그멘테이션 후보 구간 선정 및 접근 정책 설계", priority: "High", term: "중기", pillar: "Network" },
  { task: "IDS·IPS 또는 Wazuh 이벤트 기반 위협 대응 모니터링 체계화", priority: "High", term: "중기", pillar: "Network" },
  { task: "데이터 흐름 매핑을 통해 중요 업무 트래픽 경로 문서화", priority: "Medium", term: "중기", pillar: "Network" },
  { task: "자격 증명 관리 절차를 표준화하고 비밀정보 보관 위치 통제", priority: "High", term: "중기", pillar: "System" },
  { task: "네트워크 세분화 및 그룹 간 이동 통제 정책 적용", priority: "High", term: "중기", pillar: "System" },
  { task: "온프레미스·클라우드 환경별 보안 정책 기준 통합", priority: "Medium", term: "중기", pillar: "System" },
  { task: "애플리케이션 보안 상태 지속 모니터링 및 승인 절차 수립", priority: "High", term: "중기", pillar: "Application" },
  { task: "배포 전 코드 검토·취약점 검사 결과를 릴리즈 게이트에 반영", priority: "High", term: "중기", pillar: "Application" },
  { task: "애플리케이션 인벤토리와 소프트웨어 위험 목록 최신화", priority: "Medium", term: "중기", pillar: "Application" },
  { task: "데이터 거버넌스 정책과 접근제어 기준을 업무 데이터 등급에 매핑", priority: "High", term: "중기", pillar: "Data" },
  { task: "데이터 라벨링·태그 지정 지침을 수립하고 운영 데이터에 적용", priority: "Medium", term: "중기", pillar: "Data" },
  { task: "DLP 정책 수립 및 주요 데이터 유출 시나리오 점검", priority: "High", term: "중기", pillar: "Data" },

  { task: "통합 ICAM 플랫폼 기반으로 사용자·권한 관리 최적화", priority: "Medium", term: "장기", pillar: "Identify" },
  { task: "행동·컨텍스트 기반 ID 분석과 생체 인증 적용 검토", priority: "Medium", term: "장기", pillar: "Identify" },
  { task: "AI 기반 사용자 행동 분석(UEBA) 도입 로드맵 수립", priority: "Medium", term: "장기", pillar: "Identify" },
  { task: "UEM/MDM 기반 엔드포인트 통합 관리 체계 구축", priority: "Medium", term: "장기", pillar: "Device" },
  { task: "EDR·XDR 연계 탐지 대응 자동화 범위 확대", priority: "Medium", term: "장기", pillar: "Device" },
  { task: "취약성·패치 관리 자동화 파이프라인 구축", priority: "High", term: "장기", pillar: "Device" },
  { task: "소프트웨어 정의 네트워킹(SDN) 기반 정책 적용 검토", priority: "Medium", term: "장기", pillar: "Network" },
  { task: "마이크로 세그멘테이션 단계적 적용 및 정책 자동화", priority: "High", term: "장기", pillar: "Network" },
  { task: "네트워크 회복성 확보를 위한 복구 경로와 백업 경로 검증", priority: "Medium", term: "장기", pillar: "Network" },
  { task: "PAM·자격 증명 관리·접근통제 정책을 통합 운영 체계로 전환", priority: "High", term: "장기", pillar: "System" },
  { task: "시스템 환경 변화에 따른 정책 자동 적용 체계 마련", priority: "Medium", term: "장기", pillar: "System" },
  { task: "애플리케이션 리소스 권한 부여를 정책 기반 자동 승인으로 전환", priority: "Medium", term: "장기", pillar: "Application" },
  { task: "보안 코딩 표준과 소프트웨어 위험 관리를 SDLC에 통합", priority: "Medium", term: "장기", pillar: "Application" },
  { task: "데이터 활동 모니터링 및 이상 행위 감지 자동화", priority: "Medium", term: "장기", pillar: "Data" },
  { task: "데이터 암호화·권한 관리·DLP 증적을 자동 수집하는 체계 구축", priority: "High", term: "장기", pillar: "Data" },
];
