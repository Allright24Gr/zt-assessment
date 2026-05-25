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

export function getScoreColor(score: number) {
  // 점수 기반 색 — 차트/막대 등에서 사용 (maturity 라벨이 없는 컨텍스트).
  if (score < 1.5) return { bar: "bg-red-500", text: "text-red-600", badge: "bg-red-100 text-red-700" };
  if (score < 2.5) return { bar: "bg-orange-500", text: "text-orange-600", badge: "bg-orange-100 text-orange-700" };
  if (score < 3.5) return { bar: "bg-blue-500", text: "text-blue-600", badge: "bg-blue-100 text-blue-700" };
  return { bar: "bg-emerald-500", text: "text-emerald-600", badge: "bg-emerald-100 text-emerald-700" };
}

// maturity 단계별 고정 색 — 기존(약) → 초기 → 향상 → 최적화(강) 그라데이션.
export const MATURITY_COLOR: Record<string, { bar: string; text: string; badge: string; ring: string }> = {
  기존:    { bar: "bg-red-500",     text: "text-red-600",     badge: "bg-red-100 text-red-700 border border-red-200",       ring: "ring-red-200" },
  초기:    { bar: "bg-orange-500",  text: "text-orange-600",  badge: "bg-orange-100 text-orange-700 border border-orange-200", ring: "ring-orange-200" },
  향상:    { bar: "bg-blue-500",    text: "text-blue-600",    badge: "bg-blue-100 text-blue-700 border border-blue-200",      ring: "ring-blue-200" },
  최적화:  { bar: "bg-emerald-500", text: "text-emerald-600", badge: "bg-emerald-100 text-emerald-700 border border-emerald-200", ring: "ring-emerald-200" },
};

export function getMaturityColor(maturity: string | undefined | null) {
  if (!maturity) return { bar: "bg-gray-300", text: "text-gray-500", badge: "bg-gray-100 text-gray-500 border border-gray-200", ring: "ring-gray-200" };
  return MATURITY_COLOR[maturity] ?? { bar: "bg-gray-300", text: "text-gray-500", badge: "bg-gray-100 text-gray-500 border border-gray-200", ring: "ring-gray-200" };
}
