import type {
  AssessmentHistoryResponse,
  AssessmentResultResponse,
  AssessmentRunRequest,
  AssessmentRunResponse,
  ChecklistResponse,
  ImprovementResponse,
  ManualItemsFullResponse,
  ManualSubmitRequest,
  ManualSubmitResponse,
  ReportGenerateResponse,
  ScoreSummaryResponse,
  ScoreTrendResponse,
} from "../types/api";

export const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

export const API_ENDPOINTS = {
  ASSESSMENT_RUN: "/api/assessment/run",
  ASSESSMENT_WEBHOOK: "/api/assessment/webhook",
  ASSESSMENT_RESULT: "/api/assessment/result",
  ASSESSMENT_HISTORY: "/api/assessment/history",
  SCORE_SUMMARY: "/api/score/summary",
  SCORE_TREND: "/api/score/trend",
  MANUAL_SUBMIT: "/api/manual/submit",
  MANUAL_UPLOAD: "/api/manual/upload",
  CHECKLIST: "/api/checklist",
  IMPROVEMENT: "/api/improvement",
  REPORT_GENERATE: "/api/report/generate",
  AUTH_REGISTER: "/api/auth/register",
  AUTH_LOGIN: "/api/auth/login",
  AUTH_ME: "/api/auth/me",
  AUTH_PROFILE: "/api/auth/profile",
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

export async function apiFetch<T>(
  endpoint: string,
  options: RequestInit & { params?: QueryParams } = {},
): Promise<T> {
  const { params, headers, body, ...requestOptions } = options;
  const response = await fetch(buildUrl(endpoint, params), {
    ...requestOptions,
    headers: {
      ...(body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...headers,
    },
    body,
  });
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

// ─── Auth ──────────────────────────────────────────────────────────────────

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
}

export function registerUser(payload: RegisterPayload) {
  return apiFetch<AuthUser>(API_ENDPOINTS.AUTH_REGISTER, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function loginUser(login_id: string, password: string) {
  return apiFetch<AuthUser>(API_ENDPOINTS.AUTH_LOGIN, {
    method: "POST",
    body: JSON.stringify({ login_id, password }),
  });
}

export function fetchAuthMe(login_id: string) {
  return apiFetch<AuthUser>(API_ENDPOINTS.AUTH_ME, { params: { login_id } });
}

export function updateAuthProfile(login_id: string, profile: ProfileFields) {
  return apiFetch<AuthUser>(API_ENDPOINTS.AUTH_PROFILE, {
    method: "PUT",
    params: { login_id },
    body: JSON.stringify({ profile }),
  });
}
