import type {
  AssessmentCompareResponse,
  AssessmentHistoryResponse,
  AssessmentResultResponse,
  AssessmentRunRequest,
  AssessmentRunResponse,
  AssessmentShareCreateResponse,
  AssessmentShareListItem,
  AuthEnvelope,
  ChecklistResponse,
  ImprovementResponse,
  ManualEvidenceUploadResponse,
  ManualItemsFullResponse,
  ManualSubmitRequest,
  ManualSubmitResponse,
  ReportGenerateResponse,
  ScoreSummaryResponse,
  ScoreTrendResponse,
  TokenPair,
} from "../types/api";

export const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

export const API_ENDPOINTS = {
  ASSESSMENT_RUN: "/api/assessment/run",
  ASSESSMENT_WEBHOOK: "/api/assessment/webhook",
  ASSESSMENT_RESULT: "/api/assessment/result",
  ASSESSMENT_HISTORY: "/api/assessment/history",
  ASSESSMENT_COMPARE: "/api/assessment/compare",
  SCORE_SUMMARY: "/api/score/summary",
  SCORE_TREND: "/api/score/trend",
  MANUAL_SUBMIT: "/api/manual/submit",
  MANUAL_UPLOAD: "/api/manual/upload",
  MANUAL_UPLOAD_EVIDENCE: "/api/manual/upload-evidence",
  CHECKLIST: "/api/checklist",
  IMPROVEMENT: "/api/improvement",
  REPORT_GENERATE: "/api/report/generate",
  AUTH_REGISTER: "/api/auth/register",
  AUTH_LOGIN: "/api/auth/login",
  AUTH_ME: "/api/auth/me",
  AUTH_PROFILE: "/api/auth/profile",
  AUTH_CHANGE_PASSWORD: "/api/auth/change-password",
  AUTH_REFRESH: "/api/auth/refresh",
  AUTH_REQUEST_PASSWORD_RESET: "/api/auth/request-password-reset",
  AUTH_RESET_PASSWORD: "/api/auth/reset-password",
  AUTH_DELETE_ME: "/api/auth/me",
} as const;

export class ApiError extends Error {
  status: number;
  payload: unknown;

  constructor(message: string, status: number, payload: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

type QueryParams = Record<string, string | number | boolean | null | undefined>;

function buildUrl(endpoint: string, params?: QueryParams) {
  const url = new URL(endpoint, API_BASE);

  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, String(value));
      }
    });
  }

  return url.toString();
}

async function parseResponse(response: Response) {
  const contentType = response.headers.get("content-type") ?? "";

  if (response.status === 204) {
    return null;
  }

  if (contentType.includes("application/json")) {
    return response.json();
  }

  return response.text();
}

// 인증 헤더 자동 첨부 — 보호 엔드포인트에 Authorization: Bearer + 호환용 X-Login-Id 첨부.
// 로그인 전(register/login/refresh/password-reset/공유 결과)에는 헤더 없이 호출.
const PUBLIC_ENDPOINTS = new Set<string>([
  API_ENDPOINTS.AUTH_REGISTER,
  API_ENDPOINTS.AUTH_LOGIN,
  API_ENDPOINTS.AUTH_REFRESH,
  API_ENDPOINTS.AUTH_REQUEST_PASSWORD_RESET,
  API_ENDPOINTS.AUTH_RESET_PASSWORD,
]);
// 시작 경로 매칭(공유 결과 조회 등)
const PUBLIC_ENDPOINT_PREFIXES = ["/api/assessment/shared/"];

function isPublicEndpoint(endpoint: string): boolean {
  if (PUBLIC_ENDPOINTS.has(endpoint)) return true;
  return PUBLIC_ENDPOINT_PREFIXES.some((p) => endpoint.startsWith(p));
}

const TOKENS_STORAGE_KEY = "zt_tokens";

function _getLoginIdFromStorage(): string | null {
  try {
    const raw = localStorage.getItem("zt_user");
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { login_id?: string; id?: string };
    return parsed?.login_id ?? parsed?.id ?? null;
  } catch {
    return null;
  }
}

function _getTokensFromStorage(): TokenPair | null {
  try {
    const raw = localStorage.getItem(TOKENS_STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as TokenPair;
  } catch {
    return null;
  }
}

function _setTokensInStorage(tokens: TokenPair | null) {
  try {
    if (tokens) localStorage.setItem(TOKENS_STORAGE_KEY, JSON.stringify(tokens));
    else localStorage.removeItem(TOKENS_STORAGE_KEY);
  } catch {
    /* ignore */
  }
}

export function getStoredAccessToken(): string | null {
  return _getTokensFromStorage()?.access_token ?? null;
}

export function getStoredRefreshToken(): string | null {
  return _getTokensFromStorage()?.refresh_token ?? null;
}

export function setStoredTokens(tokens: TokenPair | null) {
  _setTokensInStorage(tokens);
}

/**
 * 단일 refresh in-flight 가드: 동시 다발 401 시 단 한 번만 refresh 호출.
 */
let _refreshInFlight: Promise<TokenPair | null> | null = null;

async function _tryRefreshAccessToken(): Promise<TokenPair | null> {
  if (_refreshInFlight) return _refreshInFlight;
  const refreshToken = getStoredRefreshToken();
  if (!refreshToken) return null;
  _refreshInFlight = (async () => {
    try {
      const url = buildUrl(API_ENDPOINTS.AUTH_REFRESH);
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
      if (!res.ok) return null;
      const payload = (await res.json()) as TokenPair;
      _setTokensInStorage(payload);
      return payload;
    } catch {
      return null;
    } finally {
      _refreshInFlight = null;
    }
  })();
  return _refreshInFlight;
}

interface InternalFetchOptions extends RequestInit {
  params?: QueryParams;
  _retry?: boolean;
}

export async function apiFetch<T>(
  endpoint: string,
  options: InternalFetchOptions = {},
): Promise<T> {
  const { params, headers, body, _retry, ...requestOptions } = options;

  const mergedHeaders: Record<string, string> = {
    ...(body instanceof FormData ? {} : { "Content-Type": "application/json" }),
  };

  if (!isPublicEndpoint(endpoint)) {
    // 호환성: X-Login-Id 와 Authorization 둘 다 첨부 (백엔드가 둘 다 지원)
    const loginId = _getLoginIdFromStorage();
    if (loginId) mergedHeaders["X-Login-Id"] = loginId;
    const accessToken = getStoredAccessToken();
    if (accessToken) mergedHeaders["Authorization"] = `Bearer ${accessToken}`;
  }
  Object.assign(mergedHeaders, headers as Record<string, string> | undefined);

  const response = await fetch(buildUrl(endpoint, params), {
    ...requestOptions,
    headers: mergedHeaders,
    body,
  });

  // 401 → refresh 한 번 시도 후 재시도
  if (response.status === 401 && !_retry && !isPublicEndpoint(endpoint)) {
    const newTokens = await _tryRefreshAccessToken();
    if (newTokens) {
      return apiFetch<T>(endpoint, { ...options, _retry: true });
    }
  }

  const payload = await parseResponse(response);

  if (!response.ok) {
    const message = typeof payload === "object" && payload && "detail" in payload
      ? String((payload as { detail: unknown }).detail)
      : `API request failed with status ${response.status}`;
    throw new ApiError(message, response.status, payload);
  }

  return payload as T;
}

export function runAssessment(payload?: AssessmentRunRequest) {
  return apiFetch<AssessmentRunResponse>(API_ENDPOINTS.ASSESSMENT_RUN, {
    method: "POST",
    body: JSON.stringify(payload ?? {}),
  });
}

export function getAssessmentResult(sessionId?: number | string) {
  return apiFetch<AssessmentResultResponse>(API_ENDPOINTS.ASSESSMENT_RESULT, {
    params: { session_id: sessionId },
  });
}

export function getAssessmentHistory(orgName?: string) {
  return apiFetch<AssessmentHistoryResponse>(API_ENDPOINTS.ASSESSMENT_HISTORY, {
    params: orgName ? { org_name: orgName } : undefined,
  });
}

export function getAssessmentCompare(fromId: number | string, toId: number | string) {
  return apiFetch<AssessmentCompareResponse>(API_ENDPOINTS.ASSESSMENT_COMPARE, {
    params: { from_id: fromId, to_id: toId },
  });
}

export function getScoreSummary(sessionId?: number | string) {
  return apiFetch<ScoreSummaryResponse>(API_ENDPOINTS.SCORE_SUMMARY, {
    params: { session_id: sessionId },
  });
}

export function getScoreTrend(orgId: number | string, limit = 12) {
  return apiFetch<ScoreTrendResponse>(API_ENDPOINTS.SCORE_TREND, {
    params: { org_id: orgId, limit },
  });
}

export function getChecklist() {
  return apiFetch<ChecklistResponse>(API_ENDPOINTS.CHECKLIST);
}

export function getImprovement(sessionId?: number | string) {
  return apiFetch<ImprovementResponse>(API_ENDPOINTS.IMPROVEMENT, {
    params: { session_id: sessionId },
  });
}

export function submitManual(payload: ManualSubmitRequest) {
  return apiFetch<ManualSubmitResponse>(API_ENDPOINTS.MANUAL_SUBMIT, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function generateReport(sessionId?: number | string) {
  return apiFetch<ReportGenerateResponse>(API_ENDPOINTS.REPORT_GENERATE, {
    params: { session_id: sessionId },
  });
}

export function getManualItems(sessionId: number | string, excludedTools?: string) {
  return apiFetch<ManualItemsFullResponse>(`/api/manual/items/${sessionId}`, {
    params: excludedTools ? { excluded_tools: excludedTools } : undefined,
  });
}

export function finalizeAssessment(sessionId: number | string) {
  return apiFetch<{ status: string; session_id: number }>(
    `/api/assessment/finalize/${sessionId}`,
    { method: "POST" },
  );
}

export interface AssessmentStatusResponse {
  session_id: number;
  status: string;
  selected_tools: string[];
  collected_count: number;
  auto_total: number;
  collection_done: boolean;
  tool_progress: Array<{ tool: string; collected: number; expected: number }>;
  pillar_progress: Array<{ pillar: string; collected: number; expected: number }>;
}

export function getAssessmentStatus(sessionId: number | string) {
  return apiFetch<AssessmentStatusResponse>(`/api/assessment/status/${sessionId}`);
}

export function uploadManualExcel(sessionId: number | string, file: File) {
  const form = new FormData();
  form.append("session_id", String(sessionId));
  form.append("file", file);
  return apiFetch<{ status: string; session_id: number; parsed_count: number }>(
    API_ENDPOINTS.MANUAL_UPLOAD,
    { method: "POST", body: form },
  );
}

// ─── Evidence 업로드 (P1-7) ───────────────────────────────────────────────────
export function uploadEvidence(
  sessionId: number | string,
  checkId: number | string,
  file: File,
  note?: string,
) {
  const form = new FormData();
  form.append("session_id", String(sessionId));
  form.append("check_id", String(checkId));
  form.append("file", file);
  if (note) form.append("note", note);
  return apiFetch<ManualEvidenceUploadResponse>(
    API_ENDPOINTS.MANUAL_UPLOAD_EVIDENCE,
    { method: "POST", body: form },
  );
}

export function evidenceDownloadUrl(evidenceId: number | string) {
  return `${API_BASE}/api/manual/evidence/${evidenceId}`;
}

// ─── 공유 링크 (P1-11) ─────────────────────────────────────────────────────────
export function createAssessmentShare(sessionId: number | string, expiresDays: number) {
  return apiFetch<AssessmentShareCreateResponse>(
    `/api/assessment/share/${sessionId}`,
    {
      method: "POST",
      body: JSON.stringify({ expires_days: expiresDays }),
    },
  );
}

export function listAssessmentShares(sessionId: number | string) {
  return apiFetch<AssessmentShareListItem[]>(
    `/api/assessment/share/${sessionId}`,
  );
}

export function revokeAssessmentShare(shareId: number | string) {
  return apiFetch<{ status: string }>(
    `/api/assessment/share/${shareId}`,
    { method: "DELETE" },
  );
}

export function getSharedAssessment(token: string) {
  return apiFetch<AssessmentResultResponse & { shared?: { expires_at?: string; org?: string } }>(
    `/api/assessment/shared/${token}`,
  );
}

// ─── Auth ──────────────────────────────────────────────────────────────

export interface ProfileFields {
  org_name?: string;
  department?: string;
  contact?: string;
  org_type?: string;
  infra_type?: string;
  employees?: number;
  servers?: number;
  applications?: number;
  note?: string;
}

export interface AuthUser {
  user_id: number;
  login_id: string;
  name: string;
  email?: string | null;
  role: string;
  org_id: number;
  org_name: string;
  profile?: ProfileFields | null;
}

export interface RegisterPayload {
  login_id: string;
  password: string;
  name: string;
  email?: string;
  profile?: ProfileFields;
  // P0-5: 약관 동의 필수
  tos_agreed: boolean;
  privacy_agreed: boolean;
  marketing_agreed?: boolean;
}

// 새 응답 envelope: { user, tokens }
export function registerUser(payload: RegisterPayload) {
  return apiFetch<AuthEnvelope>(API_ENDPOINTS.AUTH_REGISTER, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function loginUser(login_id: string, password: string) {
  return apiFetch<AuthEnvelope>(API_ENDPOINTS.AUTH_LOGIN, {
    method: "POST",
    body: JSON.stringify({ login_id, password }),
  });
}

export function fetchAuthMe(login_id: string) {
  return apiFetch<AuthUser>(API_ENDPOINTS.AUTH_ME, {
    headers: { "X-Login-Id": login_id },
  });
}

export function updateAuthProfile(
  login_id: string,
  profile: ProfileFields,
  currentPassword: string,
) {
  return apiFetch<AuthUser>(API_ENDPOINTS.AUTH_PROFILE, {
    method: "PUT",
    headers: { "X-Login-Id": login_id },
    body: JSON.stringify({ profile, current_password: currentPassword }),
  });
}

export function changePassword(
  login_id: string,
  current_password: string,
  new_password: string,
) {
  return apiFetch<{ status: string; message?: string }>(
    API_ENDPOINTS.AUTH_CHANGE_PASSWORD,
    {
      method: "POST",
      headers: { "X-Login-Id": login_id },
      body: JSON.stringify({ current_password, new_password }),
    },
  );
}

// ─── 비밀번호 재설정 / 회원 탈퇴 (P0-2, P0-6) ───────────────────────────────────

export function refreshAccessToken(refresh_token: string) {
  return apiFetch<TokenPair>(API_ENDPOINTS.AUTH_REFRESH, {
    method: "POST",
    body: JSON.stringify({ refresh_token }),
  });
}

export function requestPasswordReset(login_id: string) {
  return apiFetch<{ status: string }>(
    API_ENDPOINTS.AUTH_REQUEST_PASSWORD_RESET,
    {
      method: "POST",
      body: JSON.stringify({ login_id }),
    },
  );
}

export function resetPassword(token: string, new_password: string) {
  return apiFetch<{ status: string }>(
    API_ENDPOINTS.AUTH_RESET_PASSWORD,
    {
      method: "POST",
      body: JSON.stringify({ token, new_password }),
    },
  );
}

export function deleteAccount(current_password: string) {
  return apiFetch<{ status: string }>(
    API_ENDPOINTS.AUTH_DELETE_ME,
    {
      method: "DELETE",
      body: JSON.stringify({ current_password }),
    },
  );
}
