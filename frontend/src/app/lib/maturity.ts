// 백엔드 enum은 그대로 유지(점수/판정 비교 로직과 동일).
// UI 표기만 "근간"으로 매핑한다.
export const MATURITY_STEPS = ["기존", "초기", "향상", "최적화"] as const;

// UI 표시용 라벨 매핑 — API raw 값 비교에는 사용하지 말 것.
export const MATURITY_LABEL: Record<string, string> = {
  기존: "근간",
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
  if (score < 1.5) return { bar: "bg-red-500", text: "text-red-600", badge: "bg-red-100 text-red-700" };
  if (score < 2.5) return { bar: "bg-yellow-500", text: "text-yellow-600", badge: "bg-yellow-100 text-yellow-700" };
  return { bar: "bg-green-500", text: "text-green-600", badge: "bg-green-100 text-green-700" };
}
