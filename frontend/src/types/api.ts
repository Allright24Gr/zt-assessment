export type MaturityLevel = "기존" | "초기" | "향상" | "최적화";
export type AssessmentStatus = "완료" | "진행 중" | "실패" | string;
export type AssessmentResult = "충족" | "부분충족" | "미충족" | "평가불가";
export type Priority = "Critical" | "High" | "Medium" | "Low" | string;
export type ImprovementTerm = "단기" | "중기" | "장기" | string;

export interface PillarScore {
  pillar: string;
  score: number;
  level: MaturityLevel | string;
  pass_cnt: number;
  fail_cnt: number;
  na_cnt: number;
}

export interface AssessmentError {
  code: string;
  message: string;
  severity: Priority;
  area?: string;
  pillar?: string;
  fail_count?: number;
  miss_count?: number;
}

export interface EvidenceSummary {
  source: string;
  observed: string;
  location: string;
  reason: string;
  impact: number;
}

export interface ChecklistItemResult {
  id: string;
  pillar: string;
  category: string;
  item: string;
  maturity: MaturityLevel | string;
  maturity_score?: number;
  diagnosis_type?: string;
  tool: string;
  result: AssessmentResult;
  score: number;
  evidence: string;
  criteria: string;
  fields: string;
  logic: string;
  exceptions: string;
  recommendation: string;
  evidence_summary?: EvidenceSummary;
  related_improvement_ids?: string[];
}

export interface AssessmentSession {
  id: number | string;
  org: string;
  org_id?: number;
  date: string;
  manager: string;
  user_id?: number | string;
  level: MaturityLevel | string;
  status: AssessmentStatus;
  score: number | null;
  errors: AssessmentError[];
  extra?: Record<string, unknown>;
  checklist_details?: ChecklistItemResult[];
  is_demo?: boolean;
}

export interface ScanTargets {
  nmap?: string;
  trivy?: string;
}

export interface KeycloakCreds {
  url?: string;
  admin_user?: string;
  admin_pass?: string;
}

export interface WazuhCreds {
  url?: string;
  api_user?: string;
  api_pass?: string;
}

export interface EntraCreds {
  tenant_id?: string;
  client_id?: string;
  client_secret?: string;
}

export interface OktaCreds {
  domain?: string;
  api_token?: string;
}

export interface SplunkCreds {
  url?: string;
  user?: string;
  password?: string;
}

// 인증 토큰 (P0-1) — 백엔드 login/register 응답의 tokens 필드 형식
export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: "Bearer";
  expires_in: number;
}

// /api/auth/login, /api/auth/register 의 새 응답 envelope
export interface AuthEnvelope {
  // user.* 필드는 config/api.ts의 AuthUser와 1:1
  user: {
    user_id: number;
    login_id: string;
    name: string;
    email?: string | null;
    role: string;
    org_id: number;
    org_name: string;
    profile?: Record<string, unknown> | null;
  };
  tokens: TokenPair;
}

// 비교 API (P1-8)
export interface AssessmentCompareSessionMeta {
  id: number;
  org: string;
  date: string;
  manager: string;
  level: MaturityLevel | string;
  score: number | null;
  status: AssessmentStatus;
}

export interface AssessmentComparePillarDelta {
  pillar: string;
  from_score: number;
  to_score: number;
  delta: number;
}

export interface AssessmentCompareItemDiff {
  id: string;
  pillar: string;
  item: string;
  from_result?: AssessmentResult | string | null;
  to_result?: AssessmentResult | string | null;
  from_score?: number | null;
  to_score?: number | null;
}

export interface AssessmentCompareResponse {
  from: AssessmentCompareSessionMeta;
  to: AssessmentCompareSessionMeta;
  overall_delta: number;
  pillar_deltas: AssessmentComparePillarDelta[];
  improved: AssessmentCompareItemDiff[];   // 미충족→충족 (또는 점수 상승)
  regressed: AssessmentCompareItemDiff[];  // 충족→미충족 (또는 점수 하락)
  new_in_to: AssessmentCompareItemDiff[];  // to에만 존재
  unchanged_count: number;
}

// 공유 링크 (P1-11)
export interface AssessmentShareCreateRequest {
  expires_days: number;
}

export interface AssessmentShareCreateResponse {
  share_id: number;
  token: string;
  expires_at: string;
  share_url?: string;
}

export interface AssessmentShareListItem {
  share_id: number;
  token: string;
  expires_at: string;
  created_at: string;
  revoked?: boolean;
}

// Evidence 업로드 (P1-7)
export interface ManualEvidenceUploadResponse {
  evidence_id: number;
  check_id: number;
  filename: string;
  size: number;
  uploaded_at: string;
}

export type IdpType = "keycloak" | "entra" | "okta" | "ldap" | "none";
export type SiemType = "wazuh" | "splunk" | "elastic" | "none";

export interface ProfileSelect {
  idp_type: IdpType;
  siem_type: SiemType;
}

export interface AssessmentRunRequest {
  org_name?: string;
  manager?: string;
  department?: string;
  email?: string;
  contact?: string;
  org_type?: string;
  infra_type?: string;
  employees?: number;
  servers?: number;
  applications?: number;
  note?: string;
  pillar_scope?: Record<string, boolean>;
  tool_scope?: Record<string, boolean>;
  scan_targets?: ScanTargets;
  keycloak_creds?: KeycloakCreds;
  wazuh_creds?: WazuhCreds;
  entra_creds?: EntraCreds;
  okta_creds?: OktaCreds;
  splunk_creds?: SplunkCreds;
  profile_select?: ProfileSelect;
}

export interface AssessmentRunResponse {
  session_id: number | string;
  status: AssessmentStatus;
  message?: string;
  started_at?: string;
}

export interface AssessmentResultResponse {
  session: AssessmentSession;
  pillar_scores: PillarScore[];
  overall_score: number;
  overall_level: MaturityLevel | string;
  checklist_results: ChecklistItemResult[];
  errors?: AssessmentError[];
}

export interface AssessmentHistoryResponse {
  sessions: AssessmentSession[];
  total: number;
  completed_count?: number;
}

export interface ScoreSummaryResponse {
  overall_score: number;
  overall_level: MaturityLevel | string;
  previous_score?: number;
  trend?: number;
  weakest_pillar?: PillarScore;
  pillar_scores: PillarScore[];
}

export interface ScoreTrendPoint {
  history_id?: number;
  session_id?: number | string;
  total_score: number;
  maturity_level?: MaturityLevel | string;
  pillar_scores?: Record<string, number> | null;
  assessed_at?: string | null;
}

export type ScoreTrendResponse = ScoreTrendPoint[];

export interface ChecklistItem {
  id: string;
  item_num?: string;
  pillar: string;
  category: string;
  item: string;
  maturity: MaturityLevel | string;
  maturity_score: number;
  diagnosis_type: string;
  tool: string;
  evidence: string;
  criteria: string;
  fields: string;
  logic: string;
  exceptions: string;
}

export interface ChecklistResponse {
  items: ChecklistItem[];
  total: number;
}

export interface ImprovementItem {
  id?: string;
  task: string;
  priority: Priority;
  term: ImprovementTerm;
  pillar: string;
  duration?: string;
  difficulty?: string;
  owner?: string;
  expected_gain?: string;
  related_item?: string;
  steps?: string[];
  expected_effect?: string;
}

export interface ImprovementResponse {
  items: ImprovementItem[];
  total: number;
}

export interface ManualItemDetail {
  check_id: number;
  item_id: string;
  pillar: string;
  category: string;
  item_name: string;
  maturity: string;
  criteria: string;
  tool: string;
  diagnosis_type: string;
  submitted: boolean;
}

export interface ManualItemsFullResponse {
  items: ManualItemDetail[];
  total: number;
  submitted_count: number;
}

export interface ManualSubmitRequest {
  session_id: number | string;
  answers: Array<{
    check_id: string;
    value: AssessmentResult | string;
    evidence?: string;
    note?: string;
  }>;
}

export interface ManualSubmitResponse {
  status: AssessmentStatus;
  message?: string;
  submitted_count?: number;
}

export interface ReportGenerateResponse {
  report_id?: number | string;
  session_id?: number | string;
  status: AssessmentStatus;
  download_url?: string;
  message?: string;
}
