/**
 * 도구 식별자(소문자 영문 키) → 사용자 표시 라벨 매핑.
 *
 * 백엔드 collector 가 반환하는 `tool` 필드는 한 단어 소문자 (keycloak / wazuh /
 * nmap / trivy / web_probe / 수동 / tool_unavailable ...) 이지만, UI 에는
 * 사람이 읽을 수 있는 한국어 라벨을 함께 노출한다. 라벨이 흩어지지 않도록
 * 본 파일에서 한 곳에서 관리한다.
 *
 * - `toolLabel(t)`   — 짧은 라벨 (Badge 등에서 사용)
 * - `toolLongLabel(t)` — 진단 영역까지 포함한 라벨 (InProgress / Reporting 상단)
 */

export const TOOL_LABEL: Record<string, string> = {
  keycloak: "Keycloak",
  wazuh: "Wazuh",
  nmap: "Nmap",
  trivy: "Trivy",
  web_probe: "웹 Probe",
  supabase: "Supabase",
  vercel: "Vercel",
  railway: "Railway",
  수동: "수동",
  manual: "수동",
  tool_unavailable: "미연결",
  미설정: "미연결",
};

/** 도구별 한 줄 상세 라벨 — 진단 범위 포함. InProgress 카드/Reporting 헤더용. */
export const TOOL_LONG_LABEL: Record<string, string> = {
  keycloak: "Keycloak (IdP/SSO)",
  wazuh: "Wazuh (SIEM/HIDS)",
  nmap: "Nmap (네트워크/포트)",
  trivy: "Trivy (이미지/Repo/IaC/Secret)",
  web_probe: "웹 Probe (OIDC/DNS/TLS/HTTP/CT)",
  supabase: "Supabase (Auth/RLS/DB)",
  vercel: "Vercel (배포/환경변수/도메인)",
  railway: "Railway (서비스/헬스/restart)",
  수동: "수동 입력",
};

export function toolLabel(tool?: string | null): string {
  if (!tool) return "";
  const key = String(tool).trim().toLowerCase();
  if (!key) return "";
  // "수동" 한글 키는 lowercase 적용해도 그대로 — TOOL_LABEL 에 양쪽 등록.
  return TOOL_LABEL[key] ?? TOOL_LABEL[String(tool).trim()] ?? tool;
}

export function toolLongLabel(tool?: string | null): string {
  if (!tool) return "";
  const key = String(tool).trim().toLowerCase();
  if (!key) return "";
  return (
    TOOL_LONG_LABEL[key] ??
    TOOL_LONG_LABEL[String(tool).trim()] ??
    toolLabel(tool)
  );
}
