// 백엔드가 보내는 한글 필러 이름 ↔ 프론트 PILLARS.key (영문) 매핑
// "식별자 및 신원" → "Identify"  /  "기기 및 엔드포인트" → "Device" ...

export const PILLAR_NAME_TO_KEY: Record<string, string> = {
  "식별자 및 신원": "Identify",
  "식별 및 신원":   "Identify",
  "신원":           "Identify",
  "기기 및 엔드포인트": "Device",
  "기기":             "Device",
  "디바이스":         "Device",
  "네트워크":         "Network",
  "시스템":           "System",
  "애플리케이션 및 워크로드": "Application",
  "애플리케이션":             "Application",
  "데이터":           "Data",
};

const KEY_KEYWORDS: Record<string, string[]> = {
  Identify:    ["식별", "신원"],
  Device:      ["기기", "디바이스", "엔드포인트"],
  Network:     ["네트워크"],
  System:      ["시스템"],
  Application: ["애플리케이션", "워크로드"],
  Data:        ["데이터"],
};

export function pillarKeyOf(apiPillar: string): string {
  if (!apiPillar) return "";
  return PILLAR_NAME_TO_KEY[apiPillar] ?? apiPillar;
}

export function pillarMatchesKey(apiPillar: string, key: string): boolean {
  if (!apiPillar) return false;
  if ((PILLAR_NAME_TO_KEY[apiPillar] ?? "") === key) return true;
  return (KEY_KEYWORDS[key] ?? []).some((kw) => apiPillar.includes(kw));
}
