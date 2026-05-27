// 백엔드 enum 그대로 사용 (KISA 가이드라인 2.0 라벨과 일치).
export const MATURITY_STEPS = ["기존", "초기", "향상", "최적화"] as const;

// UI 표시용 라벨 매핑 — API raw 값 비교에는 사용하지 말 것.
// (UI 라벨이 백엔드 enum 과 동일해도 향후 i18n 등에서 매핑 지점 보존)
export const MATURITY_LABEL: Record<string, string> = {
  기존: "기존",
  초기: "초기",
  향상: "향상",
  최적화: "최적화",
};

export function maturityLabel(level: string | undefined | null): string {
  if (!level) return "-";
  return MATURITY_LABEL[level] ?? level;
}

export function getMaturityLevel(score: number) {
  if (score < 1.0) return "기존";
  if (score < 2.0) return "초기";
  if (score < 3.0) return "향상";
  return "최적화";
}

// 노션 2번 피드백 D-1: maturity 단계별 색상 통일 — 기존(빨강)/초기(노랑)/향상(파랑)/최적화(초록).
// getScoreColor 와 MATURITY_COLOR 가 같은 톤을 쓰도록 정렬해 Dashboard/Reporting/History
// 전 영역에서 일관성 유지. (이전엔 초기=주황, 향상=파랑이라 카드와 배지 색이 어긋났음)
export function getScoreColor(score: number) {
  // 점수 기반 색 — 차트/막대 등에서 사용 (maturity 라벨이 없는 컨텍스트).
  if (score < 1.0) return { bar: "bg-red-500",    text: "text-red-600",    badge: "bg-red-100 text-red-700" };       // 기존
  if (score < 2.0) return { bar: "bg-yellow-500", text: "text-yellow-600", badge: "bg-yellow-100 text-yellow-800" }; // 초기
  if (score < 3.0) return { bar: "bg-blue-500",   text: "text-blue-600",   badge: "bg-blue-100 text-blue-700" };     // 향상
  return                  { bar: "bg-green-500",  text: "text-green-600",  badge: "bg-green-100 text-green-700" };   // 최적화
}

// maturity 단계별 고정 색 — 기존(빨강) → 초기(노랑) → 향상(파랑) → 최적화(초록).
export const MATURITY_COLOR: Record<string, { bar: string; text: string; badge: string; ring: string }> = {
  기존:    { bar: "bg-red-500",    text: "text-red-600",    badge: "bg-red-100 text-red-700 border border-red-200",         ring: "ring-red-200" },
  초기:    { bar: "bg-yellow-500", text: "text-yellow-700", badge: "bg-yellow-100 text-yellow-800 border border-yellow-200", ring: "ring-yellow-200" },
  향상:    { bar: "bg-blue-500",   text: "text-blue-600",   badge: "bg-blue-100 text-blue-700 border border-blue-200",       ring: "ring-blue-200" },
  최적화:  { bar: "bg-green-500",  text: "text-green-600",  badge: "bg-green-100 text-green-700 border border-green-200",    ring: "ring-green-200" },
};

export function getMaturityColor(maturity: string | undefined | null) {
  if (!maturity) return { bar: "bg-gray-300", text: "text-gray-500", badge: "bg-gray-100 text-gray-500 border border-gray-200", ring: "ring-gray-200" };
  return MATURITY_COLOR[maturity] ?? { bar: "bg-gray-300", text: "text-gray-500", badge: "bg-gray-100 text-gray-500 border border-gray-200", ring: "ring-gray-200" };
}
