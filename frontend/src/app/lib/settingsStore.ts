// Settings 페이지에서 저장한 사용자 설정을 다른 페이지에서 공유하기 위한 가벼운 헬퍼.
// 영속 매체: localStorage["zt_settings"]. 향후 백엔드 저장으로 교체 가능.
import { PILLARS } from "../data/constants";

const STORAGE_KEY = "zt_settings";

// 디폴트 목표 점수 — Settings 화면 기본값과 동일하게 유지.
export const DEFAULT_TARGET_SCORES = [3.5, 3.5, 3.0, 3.5, 3.5, 3.0];

export function getStoredTargetScores(): number[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_TARGET_SCORES;
    const parsed = JSON.parse(raw) as { targetScores?: unknown };
    if (
      Array.isArray(parsed.targetScores) &&
      parsed.targetScores.length === PILLARS.length &&
      parsed.targetScores.every((v) => typeof v === "number" && Number.isFinite(v))
    ) {
      return parsed.targetScores as number[];
    }
  } catch {
    /* ignore — corrupt settings fall through to default */
  }
  return DEFAULT_TARGET_SCORES;
}
