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

export const improvements = [
  { task: "MFA 적용 확대", priority: "Critical", term: "단기", pillar: "Identify" },
  { task: "디바이스 취약점 스캔 자동화", priority: "High", term: "중기", pillar: "Device" },
  { task: "네트워크 마이크로 세그먼테이션", priority: "High", term: "장기", pillar: "Network" },
  { task: "데이터 암호화 정책 수립", priority: "Critical", term: "단기", pillar: "Data" },
  { task: "Zero Trust 아키텍처 전환", priority: "Medium", term: "장기", pillar: "Network" },
  { task: "SIEM 통합 및 자동화", priority: "High", term: "중기", pillar: "System" },
];
