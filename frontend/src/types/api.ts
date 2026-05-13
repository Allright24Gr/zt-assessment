export type MaturityLevel = "기존" | "초기" | "향상" | "최적화";
export type AssessmentStatus = "완료" | "진행 중" | "실패" | string;
export type AssessmentResult = "충족" | "부분충족" | "미충족" | "평가불가" | "미흡" | "해당 없음";
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
  date: string;
  manager: string;
  user_id?: string;
  level: MaturityLevel | string;
  status: AssessmentStatus;
  score: number | null;
  errors: AssessmentError[];
  checklist_details?: ChecklistItemResult[];
}

export interface AssessmentRunRequest {
  org_name?: string;
  manager?: string;
  department?: string;
  email?: string;
  contact?: string;
  org_type?: string;
  infra_type?: string;
  employees?: number | string;
  servers?: number | string;
  applications?: number | string;
  note?: string;
  pillar_scope?: Record<string, boolean>;
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
  date: string;
  score: number;
  level?: MaturityLevel | string;
  session_id?: number | string;
}

export interface ScoreTrendResponse {
  trend: ScoreTrendPoint[];
}

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

export interface ManualSubmitRequest {
  session_id: number | string;
  answers: Array<{
    check_id: string;
    value: boolean | string | number;
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
