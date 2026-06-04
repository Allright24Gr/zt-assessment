export type MaturityLevel = "기존" | "초기" | "향상" | "최적화";
export type AssessmentStatus = "완료" | "진행 중" | "실패" | string;
export type AssessmentResult = "충족" | "부분충족" | "미충족" | "평가불가";
export type Priority = "Critical" | "High" | "Medium" | "Low" | string;
export type ImprovementTerm = "단기" | "중기" | "장기" | string;

export interface PillarScore {
  pillar: string;
  score: number;
  level: MaturityLevel | string;
  unmeasurable?: boolean;
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
  /** 세부 질문 (xlsx '세부 질문' 컬럼) — UI 카드 메인 텍스트 */
  question?: string;
  evidence: string;
  criteria: string;
  fields: string;
  logic: string;
  exceptions: string;
  recommendation: string;
  evidence_summary?: EvidenceSummary;
  related_improvement_ids?: string[];
  /** 평가불가 사유 코드 (tool_not_connected / tool_unreachable / collector_error
   *  / audit_policy_disabled / sysmon_not_deployed / ot_segment_excluded 등) */
  unevaluable_reason_code?: string;
  /** 사람이 읽을 사유 라벨 — Reporting 툴팁/리포트에 노출 */
  unevaluable_reason_label?: string;
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
  scan_mode?: "demo" | "live" | string;
}

export interface ScanTargets {
  nmap?: string;
  trivy?: string;
  // 도구 무관 외부 probe (OIDC/DNS/HTTP/TLS/CT log). 도메인 또는 https URL.
  // 미입력 시 백엔드는 nmap target 으로 폴백한다.
  web_probe?: string;
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

// Supabase 자격 — Management PAT 권장. service_role/anon 은 보조.
export interface SupabaseCreds {
  project_ref?: string;  // 대시보드 ref (20자 lowercase 영숫자)
  pat?: string;          // sbp_ 로 시작하는 Management PAT
  service_role?: string; // service_role JWT (RLS bypass, 강력)
  anon_key?: string;     // anon JWT (제한적, 공개 auth settings 만)
}

// Vercel 자격 — Personal/Team API Token + project/team id.
export interface VercelCreds {
  token?: string;       // vcp_/vcl_/vca_ 접두
  team_id?: string;     // team_xxx (개인 계정은 빈 값)
  project_id?: string;  // prj_xxx
}

// Railway 자격 — API token + project/service/environment UUID.
export interface RailwayCreds {
  token?: string;
  project_id?: string;
  service_id?: string;
  environment_id?: string;
}

// 인증 토큰 (P0-1) — 백엔드 login/register 응답의 tokens 필드 형식
export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: "Bearer";
  expires_in: number;
}

// 진단 프로필 필드 — Settings/Signup/NewAssessment에서 공유
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

// /api/auth/me, /api/auth/profile, /api/auth/login.user 응답 형식
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

// /api/auth/login, /api/auth/register 의 응답 envelope
export interface AuthEnvelope {
  user: AuthUser;
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

// 자동 진단은 4 오픈소스 도구만 — 그 외 값은 backend가 수동 폴백으로 처리.
// (SKT T-Markov 등 SaaS형 평가 대비: Google/Entra/Okta/Splunk/Elastic 등도 선택만 가능)
export type IdpType =
  | "keycloak"
  | "supabase"
  | "google_workspace"
  | "entra"
  | "okta"
  | "ldap_ad"
  | "none";
export type SiemType =
  | "wazuh"
  | "splunk"
  | "elastic"
  | "none";
// SKT XDR 명세 §6 흡수 — emit 자체가 안 되면 수집 불가이므로 사전 입력.
export type YesNoUnknown = "yes" | "no" | "unknown";

export interface ProfileSelect {
  idp_type: IdpType;
  siem_type: SiemType;
  /** Windows Audit Policy / GPO 활성 여부 — Security 채널 4688/4697/4720 emit 조건 */
  windows_audit_policy_enabled?: YesNoUnknown;
  /** Sysmon 설치 여부 — EID 1·3·10·22·25 등 정밀 행위 탐지 룰 측정 가능 여부 */
  sysmon_deployed?: YesNoUnknown;
  /** 기 운영 EDR 제품명 (없으면 빈문자열) — 신원·기기 Pillar 가산 지표 */
  edr_product?: string;
  /** OT 세그먼트 존재 여부 — 'yes' 면 OT 트랙 분리 */
  ot_segment_present?: YesNoUnknown;
}

/** 외부 스캔 승인 메타데이터 (SKT 가이드 §3·§4 요구).
 *  Reporting/PDF 머리에 "어떤 권한으로, 언제, 어디까지 스캔했는가" 를 표기하기 위함. */
export interface ScanConsent {
  approver?: string;            // 승인자(이름/직위)
  scheduled_window?: string;    // 시간대 (예: "2026-05-25 22:00~24:00 KST")
  intensity?: "light" | "standard"; // 스캔 강도
  exclude_paths?: string;       // 제외 경로/자산
  emergency_contact?: string;   // 비상 연락처
}

/** SKT 가이드 §3 평가 착수 전 확정사항 4종. */
export interface EvaluationVersion {
  frontend_deployment?: string; // 예: "Vercel dpl_abc123"
  backend_deployment?: string;  // 예: "Railway xyz"
  git_commit?: string;          // 예: "a156b40"
  version_label?: string;       // 예: "2026-05-22 배포본"
}

export interface ScopeAsset {
  name: string;       // 예: "Frontend URL", "Supabase project"
  value: string;      // 자유 입력 (URL/ID/경로)
  included: boolean;  // 포함/제외
}

export interface DataClassification {
  name: string;                       // 예: "영업 고객명"
  sensitivity: "낮음" | "중간" | "높음";
  storage_location?: string;          // 예: "Supabase / Notion"
}

export interface Reviewers {
  app_owner?: string;
  backend_owner?: string;
  cloud_owner?: string;
  security_reviewer?: string;
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
  supabase_creds?: SupabaseCreds;
  vercel_creds?: VercelCreds;
  railway_creds?: RailwayCreds;
  profile_select?: ProfileSelect;
  /** "demo" | "live" — NewAssessment 토글. demo면 backend가 collector 실호출 없이 fake 결과 생성 */
  scan_mode?: "demo" | "live";
  /** live 모드에서 Nmap/Trivy 같은 외부 스캔 시 승인 메타. 보고서 머리에 표기. */
  scan_consent?: ScanConsent;
  /** SKT 가이드 §3 평가 착수 전 확정사항 — 보고서 첫 장 고정값. */
  evaluation_version?: EvaluationVersion;
  evaluation_scope_assets?: ScopeAsset[];
  data_classifications?: DataClassification[];
  reviewers?: Reviewers;
  /** true 면 세션만 만들고 collector 호출 안 함. 양식 미리 받기 흐름용. */
  skip_collector?: boolean;
}

export interface AssessmentRunResponse {
  session_id: number | string;
  status: AssessmentStatus;
  message?: string;
  started_at?: string;
}

/** SKT 가이드 §3 §4 §7 §9 — Reporting/PDF 머리에 표기할 평가 메타.
 *  backend build_evaluation_meta() 결과를 그대로 전달. */
export interface EvaluationMeta {
  scan_mode: "demo" | "live" | string;
  started_at?: string | null;
  completed_at?: string | null;
  selected_tools: string[];
  excluded_tools: string[];
  profile_select: {
    idp_type: string;
    siem_type: string;
  };
  scan_targets?: {
    nmap?: string;
    trivy?: string;
    web_probe?: string;
  };
  scan_consent?: ScanConsent;
  // SKT 가이드 §3 평가 착수 전 확정사항
  evaluation_version?: EvaluationVersion;
  evaluation_scope_assets?: ScopeAsset[];
  data_classifications?: DataClassification[];
  reviewers?: Reviewers;
}

export interface AssessmentResultResponse {
  session: AssessmentSession;
  pillar_scores: PillarScore[];
  overall_score: number;
  overall_level: MaturityLevel | string;
  checklist_results: ChecklistItemResult[];
  errors?: AssessmentError[];
  // B-3: pillar별 평가불가 카운트 / 진단 신뢰도
  pillar_unevaluable?: Record<string, number>;
  total_score?: number;
  maturity_level?: MaturityLevel | string;
  evaluable_items?: number;
  unevaluable_items?: number;
  confidence?: number;
  // SKT 가이드 §3 §4 §7 §9 — Reporting 상단·PDF 표지 표기용
  evaluation_meta?: EvaluationMeta;
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
  limit?: number;
  offset?: number;
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
