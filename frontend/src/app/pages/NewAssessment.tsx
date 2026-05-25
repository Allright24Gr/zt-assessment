import { useRef, useState, useEffect } from "react";
import { useNavigate } from "react-router";
import { Building2, Upload, CheckCircle2, FileText, X, Info, Target, AlertTriangle, Shield, KeyRound, Activity, FlaskConical, Fingerprint, BookOpenCheck, Tag, Database as DatabaseIcon, Users as UsersIcon, GitCommit } from "lucide-react";
import { toast } from "sonner";
import { PILLARS } from "../data/constants";
import {
  runAssessment, prepareAssessment, startPreparedAssessment,
  downloadSessionManualTemplate, uploadManualExcel,
} from "../../config/api";
import { useAuth } from "../context/AuthContext";
import type {
  ScanTargets, KeycloakCreds, WazuhCreds,
  IdpType, SiemType, YesNoUnknown, ProfileSelect, ScanConsent,
  EvaluationVersion, ScopeAsset, DataClassification, Reviewers,
  AssessmentRunRequest,
} from "../../types/api";

// SKT 가이드 §3 — 평가 범위 자산 8개 기본 항목.
const DEFAULT_SCOPE_ASSETS: ScopeAsset[] = [
  { name: "Frontend URL",     value: "", included: true },
  { name: "Backend API",      value: "", included: true },
  { name: "Supabase project", value: "", included: true },
  { name: "Notion DB",        value: "", included: true },
  { name: "Drive folder",     value: "", included: true },
  { name: "GitHub repo",      value: "", included: true },
  { name: "CI/CD",            value: "", included: true },
  { name: "운영자 계정",       value: "", included: true },
];

// SKT 가이드 §3 — 데이터 등급 7개 기본 항목.
const DEFAULT_DATA_CLASSIFICATIONS: DataClassification[] = [
  { name: "영업 고객명",        sensitivity: "높음", storage_location: "" },
  { name: "산업군",             sensitivity: "낮음", storage_location: "" },
  { name: "제안서",             sensitivity: "중간", storage_location: "" },
  { name: "사용 로그",          sensitivity: "중간", storage_location: "" },
  { name: "LLM prompt/response", sensitivity: "높음", storage_location: "" },
  { name: "OAuth token",        sensitivity: "높음", storage_location: "" },
  { name: "API key",            sensitivity: "높음", storage_location: "" },
];

const ORG_TYPES = ["기업", "공공기관", "금융기관", "의료기관"];
const INFRA_TYPES = [
  "온프레미스",
  "클라우드 (AWS)",
  "클라우드 (Azure)",
  "클라우드 (GCP)",
  "SaaS형 (Vercel·Railway·Supabase 등)",
  "하이브리드",
];

// 사전 프로파일링.
// supported=true 한 도구만 자동 진단 — 그 외(상용 SaaS 등)는 선택 가능하지만
// backend가 자동 항목을 수동 폴백으로 돌린다(manual.py /items 가 노출).
const IDP_OPTIONS: Array<{ key: IdpType; label: string; desc: string; supported: boolean }> = [
  { key: "keycloak",         label: "Keycloak",          desc: "오픈소스 IAM/SSO",        supported: true  },
  { key: "google_workspace", label: "Google Workspace",  desc: "Google OAuth 기반",       supported: false },
  { key: "entra",            label: "MS Entra ID",       desc: "Microsoft 365 / Azure AD", supported: false },
  { key: "okta",             label: "Okta",              desc: "Okta Workforce Identity",  supported: false },
  { key: "ldap_ad",          label: "자체 LDAP / AD",    desc: "온프레미스 디렉터리",       supported: false },
  { key: "none",             label: "사용 안 함 / 기타", desc: "수동 진단으로 폴백",        supported: false },
];

const SIEM_OPTIONS: Array<{ key: SiemType; label: string; desc: string; supported: boolean }> = [
  { key: "wazuh",   label: "Wazuh",             desc: "오픈소스 SIEM/HIDS",      supported: true  },
  { key: "splunk",  label: "Splunk",            desc: "Splunk Enterprise/Cloud", supported: false },
  { key: "elastic", label: "Elastic SIEM",      desc: "Elastic Security",         supported: false },
  { key: "none",    label: "사용 안 함 / 기타", desc: "수동 진단으로 폴백",        supported: false },
];

export function NewAssessment() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [step, setStep] = useState(1);
  const [prefillNotice, setPrefillNotice] = useState(false);
  const [formData, setFormData] = useState({
    orgName: "",
    manager: "",
    department: "",
    email: "",
    contact: "",
    orgType: "기업",
    infraType: "온프레미스",
    employees: "",
    servers: "",
    applications: "",
    note: "",
  });

  // 로그인 사용자 프로필이 있으면 폼을 자동 채움. 사용자가 임시저장한 draft가
  // 있으면 draft가 우선이며, draft가 없을 때만 프로필을 끌어옴.
  useEffect(() => {
    if (!user) return;
    let drafted = false;
    try {
      drafted = !!localStorage.getItem("zt_new_assessment_draft");
    } catch { /* ignore */ }
    if (drafted) return;

    const p = user.profile || {};
    // backend 가 email 비워두면 `{login_id}@local` placeholder 를 만드는데,
    // 우리 이메일 정규식 fail 이라 빈 칸으로 두어 사용자가 직접 입력하게.
    const userEmail = user.email ?? "";
    const isLocalPlaceholder = userEmail.endsWith("@local") || /@local$/.test(userEmail);
    const next = {
      orgName:      p.org_name      ?? user.orgName ?? "",
      manager:      user.username   ?? "",
      department:   p.department    ?? "",
      email:        isLocalPlaceholder ? "" : userEmail,
      contact:      p.contact       ?? "",
      orgType:      p.org_type      ?? "기업",
      infraType:    p.infra_type    ?? "온프레미스",
      employees:    p.employees     != null ? String(p.employees)    : "",
      servers:      p.servers       != null ? String(p.servers)      : "",
      applications: p.applications  != null ? String(p.applications) : "",
      note:         p.note          ?? "",
    };
    setFormData(next);
    if (p.org_name || p.department || p.contact || p.org_type ||
        p.infra_type || p.employees || p.servers || p.applications || p.note) {
      setPrefillNotice(true);
    }
  }, [user]);
  const [pillarScope, setPillarScope] = useState<Record<string, boolean>>(
    Object.fromEntries(PILLARS.map((p) => [p.key, true]))
  );
  // 사전 프로파일링 선택 — 4 오픈소스 도구 + SKT XDR 명세 §6 흡수 4종
  const [profileSelect, setProfileSelect] = useState<ProfileSelect>({
    idp_type: "keycloak",
    siem_type: "wazuh",
    windows_audit_policy_enabled: "unknown",
    sysmon_deployed: "unknown",
    edr_product: "",
    ot_segment_present: "unknown",
  });
  // 외부 자동 스캔(도구 무관) 토글 — Nmap / Trivy
  const [externalScanTools, setExternalScanTools] = useState<{ nmap: boolean; trivy: boolean }>({
    nmap: true, trivy: true,
  });
  // 내부적으로 백엔드에 보내는 tool_scope는 profileSelect + externalScanTools에서 파생
  const toolScope: Record<string, boolean> = {
    keycloak: profileSelect.idp_type === "keycloak",
    wazuh:    profileSelect.siem_type === "wazuh",
    nmap:     externalScanTools.nmap,
    trivy:    externalScanTools.trivy,
  };
  const [scanTargets, setScanTargets] = useState<{ nmap: string; trivy: string }>({
    nmap: "", trivy: "",
  });
  const [files, setFiles] = useState<File[]>([]);

  // 데모/실 스캔 모드: 기본은 데모(외부 시스템 미접근).
  const [scanMode, setScanMode] = useState<"demo" | "live">("demo");
  // 외부 스캔 동의 체크박스 (작업 C)
  const [consentExternalScan, setConsentExternalScan] = useState(false);
  // 외부 스캔 승인 메타 (SKT 가이드 §3·§4 — 승인자/시간/강도/제외/비상연락처)
  const [scanConsent, setScanConsent] = useState<ScanConsent>({
    approver: "",
    scheduled_window: "",
    intensity: "standard",
    exclude_paths: "",
    emergency_contact: "",
  });
  // SKT 가이드 §3 평가 착수 전 확정사항 4종
  const [evaluationVersion, setEvaluationVersion] = useState<EvaluationVersion>({
    frontend_deployment: "",
    backend_deployment: "",
    git_commit: "",
    version_label: "",
  });
  const [scopeAssets, setScopeAssets] = useState<ScopeAsset[]>(DEFAULT_SCOPE_ASSETS);
  const [dataClassifications, setDataClassifications] = useState<DataClassification[]>(
    DEFAULT_DATA_CLASSIFICATIONS,
  );
  const [reviewers, setReviewers] = useState<Reviewers>({
    app_owner: "",
    backend_owner: "",
    cloud_owner: "",
    security_reviewer: "",
  });
  // Step 2 — 수동 양식 미리 작성 (선택). prepareAssessment 로 미리 세션 생성.
  const [preparedSessionId, setPreparedSessionId] = useState<number | string | null>(null);
  const [preparing, setPreparing] = useState(false);
  const [manualUploading, setManualUploading] = useState(false);
  const [manualUploadResult, setManualUploadResult] = useState<
    { parsed: number; skipped: number; unmatched: number } | null
  >(null);
  const manualFileInputRef = useRef<HTMLInputElement>(null);
  // Keycloak 연결 카드 입력값 (작업 E-fe)
  const [keycloakCreds, setKeycloakCreds] = useState<{ url: string; admin_user: string; admin_pass: string }>({
    url: "", admin_user: "", admin_pass: "",
  });
  // Wazuh 연결 카드 입력값
  const [wazuhCreds, setWazuhCreds] = useState<{ url: string; api_user: string; api_pass: string }>({
    url: "", api_user: "", api_pass: "",
  });

  const togglePillar = (key: string) => {
    setPillarScope((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const selectedPillarCount = Object.values(pillarScope).filter(Boolean).length;

  const handleFiles = (list: FileList | null) => {
    if (!list) return;
    setFiles((prev) => [...prev, ...Array.from(list)]);
  };

  const removeFile = (idx: number) => {
    setFiles((prev) => prev.filter((_, i) => i !== idx));
  };

  const goToStep2 = () => {
    if (!formData.orgName.trim() || !formData.manager.trim()) {
      toast.error("기관명과 담당자명은 필수 입력 항목입니다.");
      return;
    }
    if (!formData.email.trim()) {
      toast.error("담당자 이메일은 필수 입력 항목입니다.");
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email.trim())) {
      toast.error("올바른 이메일 형식이 아닙니다.");
      return;
    }
    if (selectedPillarCount === 0) {
      toast.error("진단 범위는 최소 1개 이상 선택해야 합니다.");
      return;
    }
    setStep(2);
  };

  // 실 스캔 모드에서 외부 스캔 입력이 있는지(=동의 체크박스가 필요한지)
  const isLive = scanMode === "live";
  const liveScanIntent = isLive && (
    (toolScope.nmap && scanTargets.nmap.trim()) ||
    (toolScope.trivy && scanTargets.trivy.trim())
  );
  // 승인 메타 필수값(승인자 + 비상연락처) — 외부 스캔 시 책임 추적을 위해 보고서에 기록.
  const consentMetaMissing = !!liveScanIntent && (
    !scanConsent.approver?.trim() ||
    !scanConsent.emergency_contact?.trim()
  );
  const submitDisabled =
    !!liveScanIntent && (!consentExternalScan || consentMetaMissing);

  // payload 빌더 — runAssessment / prepareAssessment 둘 다 사용.
  const buildRunPayload = (): AssessmentRunRequest => {
    const nmapTarget = scanTargets.nmap.trim();
    const trivyTarget = scanTargets.trivy.trim();
    const scanTargetsPayload: ScanTargets = {};
    if (isLive && toolScope.nmap && nmapTarget) scanTargetsPayload.nmap = nmapTarget;
    if (isLive && toolScope.trivy && trivyTarget) scanTargetsPayload.trivy = trivyTarget;
    const hasScanTargets = Object.keys(scanTargetsPayload).length > 0;

    const kcPayload: KeycloakCreds = {};
    if (isLive && toolScope.keycloak) {
      if (keycloakCreds.url.trim())        kcPayload.url        = keycloakCreds.url.trim();
      if (keycloakCreds.admin_user.trim()) kcPayload.admin_user = keycloakCreds.admin_user.trim();
      if (keycloakCreds.admin_pass)        kcPayload.admin_pass = keycloakCreds.admin_pass;
    }
    const hasKc = Object.keys(kcPayload).length > 0;

    const wzPayload: WazuhCreds = {};
    if (isLive && toolScope.wazuh) {
      if (wazuhCreds.url.trim())      wzPayload.url      = wazuhCreds.url.trim();
      if (wazuhCreds.api_user.trim()) wzPayload.api_user = wazuhCreds.api_user.trim();
      if (wazuhCreds.api_pass)        wzPayload.api_pass = wazuhCreds.api_pass;
    }
    const hasWz = Object.keys(wzPayload).length > 0;

    const consentPayload: ScanConsent = {};
    if (liveScanIntent) {
      const approver = (scanConsent.approver || "").trim();
      const window_  = (scanConsent.scheduled_window || "").trim();
      const exclude  = (scanConsent.exclude_paths || "").trim();
      const contact  = (scanConsent.emergency_contact || "").trim();
      if (approver) consentPayload.approver = approver;
      if (window_)  consentPayload.scheduled_window = window_;
      if (scanConsent.intensity) consentPayload.intensity = scanConsent.intensity;
      if (exclude)  consentPayload.exclude_paths = exclude;
      if (contact)  consentPayload.emergency_contact = contact;
    }
    const hasConsent = Object.keys(consentPayload).length > 0;

    const evalVersionPayload: EvaluationVersion = {};
    (["frontend_deployment", "backend_deployment", "git_commit", "version_label"] as const).forEach((k) => {
      const v = (evaluationVersion[k] || "").trim();
      if (v) evalVersionPayload[k] = v;
    });
    const hasEvalVersion = Object.keys(evalVersionPayload).length > 0;

    const scopeAssetsPayload = scopeAssets
      .filter((a) => a.name.trim() && a.value.trim())
      .map((a) => ({ name: a.name.trim(), value: a.value.trim(), included: a.included }));

    const dcPayload = dataClassifications
      .filter((d) => d.name.trim())
      .map((d) => ({
        name: d.name.trim(),
        sensitivity: d.sensitivity,
        storage_location: (d.storage_location || "").trim(),
      }));

    const reviewersPayload: Reviewers = {};
    (["app_owner", "backend_owner", "cloud_owner", "security_reviewer"] as const).forEach((k) => {
      const v = (reviewers[k] || "").trim();
      if (v) reviewersPayload[k] = v;
    });
    const hasReviewers = Object.keys(reviewersPayload).length > 0;

    return {
      org_name: formData.orgName,
      manager: formData.manager,
      department: formData.department,
      email: formData.email,
      contact: formData.contact,
      org_type: formData.orgType,
      infra_type: formData.infraType,
      employees: Number(formData.employees) || undefined,
      servers: Number(formData.servers) || undefined,
      applications: Number(formData.applications) || undefined,
      note: formData.note,
      pillar_scope: pillarScope,
      tool_scope: toolScope,
      profile_select: profileSelect,
      scan_mode: scanMode,
      ...(hasScanTargets ? { scan_targets: scanTargetsPayload } : {}),
      ...(hasKc ? { keycloak_creds: kcPayload } : {}),
      ...(hasWz ? { wazuh_creds: wzPayload } : {}),
      ...(hasConsent ? { scan_consent: consentPayload } : {}),
      ...(hasEvalVersion ? { evaluation_version: evalVersionPayload } : {}),
      ...(scopeAssetsPayload.length > 0 ? { evaluation_scope_assets: scopeAssetsPayload } : {}),
      ...(dcPayload.length > 0 ? { data_classifications: dcPayload } : {}),
      ...(hasReviewers ? { reviewers: reviewersPayload } : {}),
    };
  };

  const excludedToolsStr = Object.entries(toolScope)
    .filter(([, enabled]) => !enabled)
    .map(([tool]) => tool)
    .join(",");

  // 미리 세션 만들기 (skip_collector=true) — Step 2 양식 카드에서 호출.
  const handlePrepareSession = async () => {
    if (preparedSessionId || preparing) return;
    setPreparing(true);
    try {
      const res = await prepareAssessment(buildRunPayload());
      setPreparedSessionId(res.session_id);
      toast.success("세션 준비 완료 — 양식을 다운로드받아 작성하세요.");
    } catch (err) {
      console.warn("[new-assessment] prepare failed:", err);
      toast.error("세션 준비 실패: 입력값을 확인해주세요.");
    } finally {
      setPreparing(false);
    }
  };

  // 양식 다운로드 (prepared session 기반).
  const handleDownloadManualTemplate = async () => {
    if (!preparedSessionId) {
      toast.error("먼저 세션을 준비해주세요.");
      return;
    }
    try {
      await downloadSessionManualTemplate(preparedSessionId);
    } catch (err) {
      console.warn("[new-assessment] template download failed:", err);
      toast.error("양식 다운로드에 실패했습니다.");
    }
  };

  // 양식 업로드 (자동 채점).
  const handleManualExcelUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !preparedSessionId) return;
    setManualUploading(true);
    try {
      const res = await uploadManualExcel(preparedSessionId, file);
      setManualUploadResult({
        parsed: res.parsed_count ?? 0,
        skipped: res.skipped_count ?? 0,
        unmatched: res.unmatched_count ?? 0,
      });
      toast.success(`양식 업로드 완료 — ${res.parsed_count ?? 0}건 채점됨`);
    } catch (err) {
      console.warn("[new-assessment] manual upload failed:", err);
      toast.error("양식 업로드에 실패했습니다.");
    } finally {
      setManualUploading(false);
      if (manualFileInputRef.current) manualFileInputRef.current.value = "";
    }
  };

  const handleSubmit = () => {
    // 이미 prepared session 있으면 startPreparedAssessment, 아니면 기존 runAssessment.
    const navTo = (sid: number | string) =>
      navigate(`/in-progress/${sid}`, {
        state: {
          excludedTools: excludedToolsStr,
          orgName: formData.orgName,
          manager: formData.manager,
        },
      });

    if (preparedSessionId) {
      startPreparedAssessment(preparedSessionId)
        .then(() => navTo(preparedSessionId))
        .catch((err) => {
          console.warn("[new-assessment] startPrepared failed:", err);
          toast.error("진단 시작 실패: 백엔드 연결 상태를 확인해주세요.");
        });
      return;
    }

    runAssessment(buildRunPayload())
      .then((res) => navTo(res.session_id))
      .catch((err) => {
        console.warn("[new-assessment] runAssessment failed:", err);
        toast.error("진단 시작 실패: 백엔드 연결 상태를 확인해주세요.");
      });
  };

  const handleSaveDraft = () => {
    try {
      localStorage.setItem(
        "zt_new_assessment_draft",
        // 보안: keycloak/wazuh/entra 비밀번호·시크릿은 임시저장에 포함하지 않는다.
        JSON.stringify({
          formData,
          pillarScope,
          profileSelect,
          externalScanTools,
          scanTargets,
          scanMode,
          scanConsent,
          keycloakCreds: { url: keycloakCreds.url, admin_user: keycloakCreds.admin_user },
          wazuhCreds:    { url: wazuhCreds.url,    api_user:   wazuhCreds.api_user   },
        }),
      );
      toast.success("입력한 내용이 임시저장되었습니다. (비밀번호는 저장되지 않습니다)");
    } catch (err) {
      console.warn("[new-assessment] save draft failed:", err);
      toast.error("임시저장에 실패했습니다.");
    }
  };

  return (
    <div className="max-w-screen-2xl mx-auto">
      {/* Step Indicator */}
      <div className="flex items-center justify-center gap-4 mb-8">
        {[1, 2, 3].map((s) => (
          <div key={s} className="flex items-center">
            <div
              className={`w-10 h-10 rounded-full flex items-center justify-center ${
                step >= s ? "bg-blue-600 text-white" : "bg-gray-200 text-gray-500"
              }`}
            >
              {step > s ? <CheckCircle2 size={20} /> : s}
            </div>
            {s < 3 && <div className={`w-24 h-1 ${step > s ? "bg-blue-600" : "bg-gray-200"}`}></div>}
          </div>
        ))}
      </div>

      <div className="bg-white rounded-lg border border-gray-200 p-8">
        {step === 1 && (
          <div className="space-y-6">
            <div className="flex items-center gap-2 mb-6">
              <Building2 className="text-blue-600" size={24} />
              <h2>Step 1: 사전 프로파일링 + 기관 정보 입력</h2>
            </div>

            {/* SKT 가이드 §9 — 평가 목적 안내 */}
            <div className="rounded-xl border border-emerald-300 bg-emerald-50/60 p-5">
              <div className="flex items-start gap-3">
                <BookOpenCheck size={20} className="text-emerald-700 mt-0.5 shrink-0" />
                <div>
                  <p className="text-sm font-semibold text-emerald-900 mb-1">평가 목적 안내</p>
                  <p className="text-sm text-emerald-900 leading-relaxed">
                    이번 평가는 제로트러스트 제품처럼 홍보하기 위한 점수 산출이 아니라,
                    <strong> 실제 운영 구조에서 신원·네트워크·시스템·앱·데이터 통제가 어디까지 증명되는지 확인</strong>하는 작업입니다.
                    자동수집이 되는 항목과 안 되는 항목을 명확히 나누어 쓰고,
                    자동수집이 안 되는 항목은 평가불가로 방치하지 말고 <strong>수동 증적을 붙여 판정</strong>하세요.
                    live scan은 승인된 범위에서만 진행합니다.
                  </p>
                </div>
              </div>
            </div>

            {prefillNotice && (
              <div className="flex items-start gap-2 p-3 bg-blue-50 border border-blue-200 rounded-lg text-sm text-blue-900">
                <Info size={16} className="mt-0.5 shrink-0" />
                <span>가입 시 등록한 진단 프로필이 자동으로 입력되었습니다. 필요 시 수정해주세요.</span>
              </div>
            )}

            {/* 데모 / 실 스캔 모드 토글 (작업 D) */}
            <div className={`rounded-xl border p-5 transition-colors ${
              isLive ? "border-red-300 bg-red-50/40" : "border-blue-200 bg-blue-50/40"
            }`}>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Shield size={18} className={isLive ? "text-red-600" : "text-blue-600"} />
                  <h3 className="text-sm font-semibold text-gray-800">진단 실행 모드</h3>
                </div>
                {isLive && (
                  <span className="inline-flex items-center gap-1 px-2.5 py-0.5 text-[11px] font-semibold rounded-full bg-red-600 text-white">
                    <AlertTriangle size={12} />
                    외부 시스템 스캔
                  </span>
                )}
              </div>
              <p className="text-xs text-gray-600 mb-4">
                데모 모드는 외부 시스템에 접근하지 않고 안전한 예시 데이터로 진단 흐름을 시연합니다.
                실 스캔 모드는 입력한 외부 시스템(Keycloak/Wazuh/Nmap/Trivy)을 실제로 스캔합니다.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3" role="radiogroup" aria-label="진단 실행 모드">
                <label
                  className={`flex items-start gap-3 p-3 border rounded-lg cursor-pointer transition-colors ${
                    !isLive ? "border-blue-500 bg-white shadow-sm" : "border-gray-200 bg-white hover:bg-gray-50"
                  }`}
                >
                  <input
                    type="radio"
                    name="scanMode"
                    value="demo"
                    checked={!isLive}
                    onChange={() => setScanMode("demo")}
                    className="mt-1 w-4 h-4"
                  />
                  <div>
                    <div className="flex items-center gap-1.5">
                      <FlaskConical size={14} className="text-blue-600" />
                      <p className="text-sm font-semibold text-gray-800">데모 모드</p>
                    </div>
                    <p className="text-xs text-gray-600 mt-0.5">
                      안전한 예시 데이터로 진행. 외부 시스템에 접근하지 않습니다.
                    </p>
                  </div>
                </label>
                <label
                  className={`flex items-start gap-3 p-3 border rounded-lg cursor-pointer transition-colors ${
                    isLive ? "border-red-500 bg-white shadow-sm" : "border-gray-200 bg-white hover:bg-gray-50"
                  }`}
                >
                  <input
                    type="radio"
                    name="scanMode"
                    value="live"
                    checked={isLive}
                    onChange={() => setScanMode("live")}
                    className="mt-1 w-4 h-4"
                  />
                  <div>
                    <div className="flex items-center gap-1.5">
                      <Activity size={14} className="text-red-600" />
                      <p className="text-sm font-semibold text-gray-800">실 스캔 모드</p>
                    </div>
                    <p className="text-xs text-gray-600 mt-0.5">
                      입력한 외부 시스템을 실제로 스캔합니다. 권한 보유 자산만 대상으로 사용하세요.
                    </p>
                  </div>
                </label>
              </div>
            </div>

            {/* Step 0 — 사전 프로파일링 (사용 중인 보안 도구) */}
            <div className="rounded-xl border border-blue-200 bg-blue-50/30 p-5">
              <div className="flex items-center gap-2 mb-1">
                <Fingerprint size={18} className="text-blue-600" />
                <h3 className="text-sm font-semibold text-gray-800">사용 중인 보안 도구 (사전 프로파일링)</h3>
              </div>
              <p className="text-xs text-gray-600 mb-4">
                기관에서 운영 중인 도구를 먼저 선택하면 해당 자동 진단 항목이 활성화됩니다.
                <strong className="text-gray-800"> "사용 안 함 / 기타"</strong>를 고르면 해당 분야의 자동 항목은 수동 진단으로 폴백됩니다.
              </p>

              {/* 신원 관리(IdP) */}
              <div className="mb-4">
                <p className="mb-2 text-xs font-semibold text-gray-700">신원 관리 (IdP)</p>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2" role="radiogroup" aria-label="신원 관리 도구">
                  {IDP_OPTIONS.map((opt) => {
                    const checked = profileSelect.idp_type === opt.key;
                    return (
                      <label
                        key={opt.key}
                        className={`flex items-center gap-2 p-3 border rounded-lg cursor-pointer transition-colors min-h-[68px] ${
                          checked ? "border-blue-500 bg-white shadow-sm" : "border-gray-200 bg-white hover:bg-gray-50"
                        }`}
                      >
                        <input
                          type="radio"
                          name="idpType"
                          className="mt-0.5 w-4 h-4"
                          checked={checked}
                          onChange={() => setProfileSelect((prev) => ({ ...prev, idp_type: opt.key }))}
                        />
                        <div className="min-w-0 flex flex-col justify-center min-h-[44px]">
                          <p className="text-sm font-medium text-gray-800 flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
                            {opt.label}
                            {!opt.supported && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-500 border border-gray-200">
                                자동 미지원
                              </span>
                            )}
                          </p>
                          <p className="text-xs text-gray-500">{opt.desc}</p>
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>

              {/* 보안 정보 관리(SIEM) */}
              <div className="mb-4">
                <p className="mb-2 text-xs font-semibold text-gray-700">보안 정보 관리 (SIEM)</p>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2" role="radiogroup" aria-label="보안 정보 관리 도구">
                  {SIEM_OPTIONS.map((opt) => {
                    const checked = profileSelect.siem_type === opt.key;
                    return (
                      <label
                        key={opt.key}
                        className={`flex items-center gap-2 p-3 border rounded-lg cursor-pointer transition-colors min-h-[68px] ${
                          checked ? "border-blue-500 bg-white shadow-sm" : "border-gray-200 bg-white hover:bg-gray-50"
                        }`}
                      >
                        <input
                          type="radio"
                          name="siemType"
                          className="mt-0.5 w-4 h-4"
                          checked={checked}
                          onChange={() => setProfileSelect((prev) => ({ ...prev, siem_type: opt.key }))}
                        />
                        <div className="min-w-0 flex flex-col justify-center min-h-[44px]">
                          <p className="text-sm font-medium text-gray-800 flex flex-wrap items-center gap-x-1.5 gap-y-0.5">
                            {opt.label}
                            {!opt.supported && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 text-gray-500 border border-gray-200">
                                자동 미지원
                              </span>
                            )}
                          </p>
                          <p className="text-xs text-gray-500">{opt.desc}</p>
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>

              {/* 외부 자동 스캔 (도구 무관) */}
              <div>
                <p className="mb-2 text-xs font-semibold text-gray-700">외부 자동 스캔 (도구 무관)</p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <label className={`flex items-center gap-2 p-3 border rounded-lg cursor-pointer transition-colors min-h-[68px] ${
                    externalScanTools.nmap ? "border-blue-500 bg-white shadow-sm" : "border-gray-200 bg-white hover:bg-gray-50"
                  }`}>
                    <input
                      type="checkbox"
                      className="mt-0.5 w-4 h-4"
                      checked={externalScanTools.nmap}
                      onChange={() => setExternalScanTools((p) => ({ ...p, nmap: !p.nmap }))}
                    />
                    <div className="min-w-0 flex flex-col justify-center min-h-[44px]">
                      <p className="text-sm font-medium text-gray-800">Nmap</p>
                      <p className="text-xs text-gray-500">네트워크/포트 외부 스캔</p>
                    </div>
                  </label>
                  <label className={`flex items-center gap-2 p-3 border rounded-lg cursor-pointer transition-colors min-h-[68px] ${
                    externalScanTools.trivy ? "border-blue-500 bg-white shadow-sm" : "border-gray-200 bg-white hover:bg-gray-50"
                  }`}>
                    <input
                      type="checkbox"
                      className="mt-0.5 w-4 h-4"
                      checked={externalScanTools.trivy}
                      onChange={() => setExternalScanTools((p) => ({ ...p, trivy: !p.trivy }))}
                    />
                    <div className="min-w-0 flex flex-col justify-center min-h-[44px]">
                      <p className="text-sm font-medium text-gray-800">Trivy</p>
                      <p className="text-xs text-gray-500">컨테이너 이미지 스캔</p>
                    </div>
                  </label>
                </div>
              </div>

              {/* 폴백 안내 */}
              {(profileSelect.idp_type === "none" || profileSelect.siem_type === "none") && (
                <div className="mt-4 flex items-start gap-2 p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-800">
                  <Info size={14} className="mt-0.5 shrink-0" />
                  <span>
                    선택하지 않은 영역의 자동 항목은 다음 단계에서 <strong>수동 진단</strong>으로 표시됩니다.
                  </span>
                </div>
              )}

              {/* 엔드포인트 측정 가능성 — SKT XDR 명세 §6 흡수 4종 */}
              <div className="mt-5 pt-4 border-t border-blue-100">
                <p className="mb-1 text-xs font-semibold text-gray-700">엔드포인트 측정 가능성</p>
                <p className="mb-3 text-[11px] text-gray-500">
                  Windows Security 채널 / Sysmon 이벤트는 OS 측에서 emit 되지 않으면 수집할 수 없습니다.
                  사전 입력이 없으면 일부 자동 항목은 "측정 전제 미충족"으로 평가불가 처리됩니다.
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] font-medium text-gray-600 mb-1">
                      Windows Audit Policy / GPO 활성
                    </label>
                    <select
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm bg-white"
                      value={profileSelect.windows_audit_policy_enabled || "unknown"}
                      onChange={(e) => setProfileSelect((p) => ({
                        ...p, windows_audit_policy_enabled: e.target.value as YesNoUnknown,
                      }))}
                    >
                      <option value="yes">활성 (Security 4688/4697/4720 emit)</option>
                      <option value="no">비활성</option>
                      <option value="unknown">모름</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[11px] font-medium text-gray-600 mb-1">
                      Sysmon 설치 여부
                    </label>
                    <select
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm bg-white"
                      value={profileSelect.sysmon_deployed || "unknown"}
                      onChange={(e) => setProfileSelect((p) => ({
                        ...p, sysmon_deployed: e.target.value as YesNoUnknown,
                      }))}
                    >
                      <option value="yes">설치됨 (EID 1·3·10·22·25 수집 가능)</option>
                      <option value="no">미설치</option>
                      <option value="unknown">모름</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[11px] font-medium text-gray-600 mb-1">
                      기 운영 EDR 제품 (선택)
                    </label>
                    <input
                      type="text"
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm"
                      value={profileSelect.edr_product || ""}
                      onChange={(e) => setProfileSelect((p) => ({
                        ...p, edr_product: e.target.value,
                      }))}
                      placeholder="예: CrowdStrike Falcon / 없음"
                      maxLength={120}
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-medium text-gray-600 mb-1">
                      OT 세그먼트 존재
                    </label>
                    <select
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm bg-white"
                      value={profileSelect.ot_segment_present || "unknown"}
                      onChange={(e) => setProfileSelect((p) => ({
                        ...p, ot_segment_present: e.target.value as YesNoUnknown,
                      }))}
                    >
                      <option value="yes">있음 (별도 트랙 분리)</option>
                      <option value="no">없음</option>
                      <option value="unknown">모름</option>
                    </select>
                  </div>
                </div>
                {(profileSelect.windows_audit_policy_enabled === "no"
                  || profileSelect.sysmon_deployed === "no") && (
                  <div className="mt-3 flex items-start gap-2 p-2.5 bg-amber-50 border border-amber-200 rounded text-[11px] text-amber-800">
                    <AlertTriangle size={12} className="mt-0.5 shrink-0" />
                    <span>
                      Audit Policy 비활성 또는 Sysmon 미설치 환경은 Windows 정밀 행위 탐지 항목이
                      <strong> "측정 전제 미충족"</strong> 사유로 평가불가 처리됩니다.
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* 기관 정보 + 담당자 정보 — lg에선 좌우 배치 */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <h3 className="text-sm font-semibold text-gray-700 mb-3">기관 정보</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block mb-2">기관명 <span className="text-red-500">*</span></label>
                    <input
                      type="text"
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                      value={formData.orgName}
                      onChange={(e) => setFormData({ ...formData, orgName: e.target.value })}
                      placeholder="기관명을 입력하세요"
                    />
                  </div>
                  <div>
                    <label className="block mb-2">기관 유형</label>
                    <select
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                      value={formData.orgType}
                      onChange={(e) => setFormData({ ...formData, orgType: e.target.value })}
                    >
                      {ORG_TYPES.map((t) => <option key={t}>{t}</option>)}
                    </select>
                  </div>
                </div>
              </div>

              {/* 담당자 정보 */}
              <div>
                <h3 className="text-sm font-semibold text-gray-700 mb-3">담당자 정보</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block mb-2">담당자명 <span className="text-red-500">*</span></label>
                  <input
                    type="text"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                    value={formData.manager}
                    onChange={(e) => setFormData({ ...formData, manager: e.target.value })}
                    placeholder="홍길동"
                  />
                </div>
                <div>
                  <label className="block mb-2">부서 / 직책</label>
                  <input
                    type="text"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                    value={formData.department}
                    onChange={(e) => setFormData({ ...formData, department: e.target.value })}
                    placeholder="예: 정보보안팀 / 팀장"
                  />
                </div>
                <div>
                  <label className="block mb-2">이메일 <span className="text-red-500">*</span></label>
                  <input
                    type="email"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    placeholder="manager@example.com"
                  />
                </div>
                <div>
                  <label className="block mb-2">연락처</label>
                  <input
                    type="tel"
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                    value={formData.contact}
                    onChange={(e) => setFormData({ ...formData, contact: e.target.value })}
                    placeholder="010-0000-0000"
                  />
                </div>
              </div>
            </div>
            </div>

            <div>
              <label className="block mb-2">
                진단 범위 선택 <span className="text-sm text-gray-500">({selectedPillarCount}/{PILLARS.length})</span>
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                {PILLARS.map((pillar) => (
                  <label key={pillar.key} className="flex items-center gap-2 p-3 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
                    <input
                      type="checkbox"
                      className="w-4 h-4 shrink-0"
                      checked={!!pillarScope[pillar.key]}
                      onChange={() => togglePillar(pillar.key)}
                    />
                    <span className="text-sm truncate">{pillar.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* 인프라 환경 */}
            <div>
              <h3 className="text-sm font-semibold text-gray-700 mb-3">인프라 환경</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="md:col-span-2">
                  <label className="block mb-2">인프라 유형</label>
                  <select
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                    value={formData.infraType}
                    onChange={(e) => setFormData({ ...formData, infraType: e.target.value })}
                  >
                    {INFRA_TYPES.map((t) => <option key={t}>{t}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block mb-2">전체 임직원 수</label>
                  <input
                    type="number"
                    min={0}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                    value={formData.employees}
                    onChange={(e) => setFormData({ ...formData, employees: e.target.value })}
                    placeholder="예: 500"
                  />
                </div>
                <div>
                  <label className="block mb-2">전체 서버 수</label>
                  <input
                    type="number"
                    min={0}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                    value={formData.servers}
                    onChange={(e) => setFormData({ ...formData, servers: e.target.value })}
                    placeholder="예: 50"
                  />
                </div>
                <div className="md:col-span-2">
                  <label className="block mb-2">운영 중 애플리케이션 수</label>
                  <input
                    type="number"
                    min={0}
                    className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                    value={formData.applications}
                    onChange={(e) => setFormData({ ...formData, applications: e.target.value })}
                    placeholder="예: 30"
                  />
                </div>
              </div>
            </div>

            {/* 진단 대상 (외부 스캔) */}
            {(toolScope.nmap || toolScope.trivy) && (
              <div className={!isLive ? "opacity-60" : ""}>
                <div className="flex items-center gap-2 mb-3">
                  <Target size={16} className="text-blue-600" />
                  <h3 className="text-sm font-semibold text-gray-700">진단 대상 (외부 스캔)</h3>
                  {!isLive && (
                    <span className="text-[11px] px-2 py-0.5 rounded bg-gray-100 text-gray-500 border border-gray-200">
                      데모 모드 비활성
                    </span>
                  )}
                </div>
                <p className="text-xs text-gray-500 mb-3">
                  {isLive
                    ? "선택한 도구가 외부에서 스캔할 대상을 입력합니다. 권한 보유 자산만 대상으로 사용하세요."
                    : "데모 모드에서는 외부 스캔 대상을 입력할 수 없습니다. 실 스캔 모드로 전환 후 입력해주세요."}
                </p>
                <div className="grid grid-cols-1 gap-4">
                  {toolScope.nmap && (
                    <div>
                      <label className="block mb-2 text-sm">
                        네트워크/호스트 (Nmap) <span className="text-gray-400 text-xs">(선택)</span>
                      </label>
                      <input
                        type="text"
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                        value={scanTargets.nmap}
                        onChange={(e) => setScanTargets({ ...scanTargets, nmap: e.target.value })}
                        placeholder="예: scanme.nmap.org 또는 192.168.1.1"
                        disabled={!isLive}
                      />
                    </div>
                  )}
                  {toolScope.trivy && (
                    <div>
                      <label className="block mb-2 text-sm">
                        컨테이너 이미지 (Trivy) <span className="text-gray-400 text-xs">(선택)</span>
                      </label>
                      <input
                        type="text"
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                        value={scanTargets.trivy}
                        onChange={(e) => setScanTargets({ ...scanTargets, trivy: e.target.value })}
                        placeholder="예: nginx:1.25, alpine:latest"
                        disabled={!isLive}
                      />
                    </div>
                  )}
                </div>
                {isLive && (scanTargets.nmap.trim() || scanTargets.trivy.trim()) && (
                  <>
                    <div className="mt-3 flex items-start gap-2 p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">
                      <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                      <span>외부 시스템 스캔 동의(권한 보유) 후 진행하세요. 권한이 없는 자산을 스캔하면 법적 책임이 발생할 수 있습니다.</span>
                    </div>
                    {/* 외부 스캔 동의 체크박스 (작업 C) */}
                    <label className="mt-3 flex items-start gap-2 p-3 bg-white border border-red-300 rounded-lg cursor-pointer">
                      <input
                        type="checkbox"
                        className="mt-0.5 w-4 h-4 accent-red-600"
                        checked={consentExternalScan}
                        onChange={(e) => setConsentExternalScan(e.target.checked)}
                      />
                      <span className="text-xs text-gray-800 leading-relaxed">
                        제가 해당 시스템에 대한 진단 권한을 보유하고 있으며,<br />
                        외부 스캔 수행으로 인한 모든 책임을 인지하고 진행합니다.
                      </span>
                    </label>

                    {/* 외부 스캔 승인 메타 (SKT 가이드 §3·§4) — 보고서 머리에 표기 */}
                    <div className="mt-3 p-3 bg-white border border-red-200 rounded-lg">
                      <p className="text-xs font-semibold text-gray-800 mb-2">
                        스캔 승인 기록
                        <span className="ml-1 text-[11px] font-normal text-gray-500">
                          (보고서 첫 장에 자동 기록됩니다)
                        </span>
                      </p>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div>
                          <label className="block mb-1 text-xs text-gray-700">
                            승인자 <span className="text-red-600">*</span>
                          </label>
                          <input
                            type="text"
                            className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-lg"
                            value={scanConsent.approver || ""}
                            onChange={(e) =>
                              setScanConsent({ ...scanConsent, approver: e.target.value })
                            }
                            placeholder="예: 최주용 팀장(SKT)"
                          />
                        </div>
                        <div>
                          <label className="block mb-1 text-xs text-gray-700">
                            비상 연락처 <span className="text-red-600">*</span>
                          </label>
                          <input
                            type="text"
                            className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-lg"
                            value={scanConsent.emergency_contact || ""}
                            onChange={(e) =>
                              setScanConsent({ ...scanConsent, emergency_contact: e.target.value })
                            }
                            placeholder="예: 010-0000-0000 / oncall@example.com"
                          />
                        </div>
                        <div>
                          <label className="block mb-1 text-xs text-gray-700">스캔 시간대</label>
                          <input
                            type="text"
                            className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-lg"
                            value={scanConsent.scheduled_window || ""}
                            onChange={(e) =>
                              setScanConsent({ ...scanConsent, scheduled_window: e.target.value })
                            }
                            placeholder="예: 2026-05-25 22:00~24:00 KST"
                          />
                        </div>
                        <div>
                          <label className="block mb-1 text-xs text-gray-700">스캔 강도</label>
                          <select
                            className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-lg bg-white"
                            value={scanConsent.intensity || "standard"}
                            onChange={(e) =>
                              setScanConsent({
                                ...scanConsent,
                                intensity: e.target.value as "light" | "standard",
                              })
                            }
                          >
                            <option value="light">light (최소 — top-100 포트 등)</option>
                            <option value="standard">standard (기본 옵션)</option>
                          </select>
                        </div>
                        <div className="sm:col-span-2">
                          <label className="block mb-1 text-xs text-gray-700">
                            제외 경로 / 자산
                            <span className="ml-1 text-[11px] text-gray-500">(쉼표로 구분)</span>
                          </label>
                          <input
                            type="text"
                            className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-lg"
                            value={scanConsent.exclude_paths || ""}
                            onChange={(e) =>
                              setScanConsent({ ...scanConsent, exclude_paths: e.target.value })
                            }
                            placeholder="예: /admin/*, api.internal.example.com"
                          />
                        </div>
                      </div>
                      {consentMetaMissing && (
                        <p className="mt-2 text-[11px] text-red-600">
                          승인자와 비상 연락처는 필수입니다. (감사 추적 목적)
                        </p>
                      )}
                    </div>
                  </>
                )}
              </div>
            )}

            {/* IdP / SIEM / EDR 연결 카드 */}
            {(toolScope.keycloak || toolScope.wazuh) && (
              <div className={!isLive ? "opacity-60" : ""}>
                <div className="flex items-center gap-2 mb-3">
                  <KeyRound size={16} className="text-blue-600" />
                  <h3 className="text-sm font-semibold text-gray-700">보안 도구 연결 정보</h3>
                  {!isLive && (
                    <span className="text-[11px] px-2 py-0.5 rounded bg-gray-100 text-gray-500 border border-gray-200">
                      데모 모드 비활성
                    </span>
                  )}
                </div>
                <p className="text-xs text-gray-500 mb-3">
                  {isLive
                    ? "사전 프로파일링에서 선택한 도구의 연결 정보를 입력합니다. 비워두면 도구 기본 설정값이 사용됩니다."
                    : "데모 모드에서는 연결 정보를 입력할 수 없습니다. 실 스캔 모드로 전환 후 입력해주세요."}
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Keycloak 카드 */}
                  {toolScope.keycloak && (
                    <div className="border border-gray-200 rounded-lg p-4 bg-gray-50/40">
                      <div className="flex items-center gap-2 mb-3">
                        <span className="text-xs font-semibold text-gray-700">Keycloak</span>
                        <span className="text-[10px] text-gray-400">IAM/SSO</span>
                      </div>
                      <div className="space-y-2.5">
                        <input
                          type="text"
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                          value={keycloakCreds.url}
                          onChange={(e) => setKeycloakCreds({ ...keycloakCreds, url: e.target.value })}
                          placeholder="https://keycloak.example.com:8443"
                          disabled={!isLive}
                          aria-label="Keycloak URL"
                        />
                        <input
                          type="text"
                          autoComplete="off"
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                          value={keycloakCreds.admin_user}
                          onChange={(e) => setKeycloakCreds({ ...keycloakCreds, admin_user: e.target.value })}
                          placeholder="admin"
                          disabled={!isLive}
                          aria-label="Keycloak Admin 사용자"
                        />
                        <input
                          type="password"
                          autoComplete="new-password"
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                          value={keycloakCreds.admin_pass}
                          onChange={(e) => setKeycloakCreds({ ...keycloakCreds, admin_pass: e.target.value })}
                          placeholder="Admin 비밀번호"
                          disabled={!isLive}
                          aria-label="Keycloak Admin 비밀번호"
                        />
                      </div>
                    </div>
                  )}
                  {/* Wazuh 카드 */}
                  {toolScope.wazuh && (
                    <div className="border border-gray-200 rounded-lg p-4 bg-gray-50/40">
                      <div className="flex items-center gap-2 mb-3">
                        <span className="text-xs font-semibold text-gray-700">Wazuh</span>
                        <span className="text-[10px] text-gray-400">SIEM/EDR</span>
                      </div>
                      <div className="space-y-2.5">
                        <input
                          type="text"
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                          value={wazuhCreds.url}
                          onChange={(e) => setWazuhCreds({ ...wazuhCreds, url: e.target.value })}
                          placeholder="https://wazuh.example.com:55000"
                          disabled={!isLive}
                          aria-label="Wazuh URL"
                        />
                        <input
                          type="text"
                          autoComplete="off"
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                          value={wazuhCreds.api_user}
                          onChange={(e) => setWazuhCreds({ ...wazuhCreds, api_user: e.target.value })}
                          placeholder="wazuh-api"
                          disabled={!isLive}
                          aria-label="Wazuh API 사용자"
                        />
                        <input
                          type="password"
                          autoComplete="new-password"
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                          value={wazuhCreds.api_pass}
                          onChange={(e) => setWazuhCreds({ ...wazuhCreds, api_pass: e.target.value })}
                          placeholder="API 비밀번호"
                          disabled={!isLive}
                          aria-label="Wazuh API 비밀번호"
                        />
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* 비고 */}
            <div>
              <label className="block mb-2">비고 / 진단 목적 <span className="text-sm text-gray-400">(선택)</span></label>
              <textarea
                rows={3}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg resize-none"
                value={formData.note}
                onChange={(e) => setFormData({ ...formData, note: e.target.value })}
                placeholder="진단 배경, 중점 검토 영역, 기타 참고 사항을 입력하세요"
              />
            </div>

            <div>
              <label className="block mb-2">
                증적 자료 업로드 <span className="text-gray-400 text-sm font-normal">(선택)</span>
              </label>
              <input
                ref={fileInputRef}
                type="file"
                multiple
                className="hidden"
                onChange={(e) => handleFiles(e.target.files)}
              />
              <div
                onClick={() => fileInputRef.current?.click()}
                onDragOver={(e) => e.preventDefault()}
                onDrop={(e) => { e.preventDefault(); handleFiles(e.dataTransfer.files); }}
                className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-blue-400 cursor-pointer"
              >
                <Upload className="mx-auto text-gray-400 mb-2" size={32} />
                <p className="text-sm text-gray-600">파일을 드래그하거나 클릭하여 업로드</p>
              </div>
              {files.length > 0 && (
                <ul className="mt-3 space-y-1.5">
                  {files.map((f, i) => (
                    <li key={`${f.name}-${i}`} className="flex items-center justify-between gap-2 px-3 py-2 bg-gray-50 rounded-lg text-sm">
                      <div className="flex items-center gap-2 min-w-0">
                        <FileText size={14} className="text-blue-500 shrink-0" />
                        <span className="truncate">{f.name}</span>
                        <span className="text-xs text-gray-400 shrink-0">{(f.size / 1024).toFixed(1)} KB</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => removeFile(i)}
                        className="text-gray-400 hover:text-red-500"
                        title="삭제"
                      >
                        <X size={14} />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* SKT 가이드 §3 평가 착수 전 확정사항 — 4 카드 */}
            <div className="rounded-xl border border-gray-200 bg-gray-50/50 p-5">
              <div className="mb-4 flex items-center gap-2">
                <FileText size={18} className="text-gray-700" />
                <h3 className="text-sm font-semibold text-gray-800">
                  평가 착수 전 확정사항
                </h3>
              </div>
              <p className="text-xs text-gray-600 mb-4">
                보고서 첫 장 · 판정 로그 · 증적 목록에 자동 표기됩니다. 비워두면 해당 항목은 표시되지 않습니다.
              </p>

              {/* Card A — 평가 대상 버전 */}
              <div className="mb-4 rounded-lg border border-gray-200 bg-white p-4">
                <div className="mb-3 flex items-center gap-2">
                  <GitCommit size={14} className="text-blue-600" />
                  <p className="text-xs font-semibold text-gray-800">평가 대상 버전 (Deployment / Commit)</p>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block mb-1 text-xs text-gray-600">Frontend deployment ID</label>
                    <input
                      type="text"
                      className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-lg"
                      value={evaluationVersion.frontend_deployment || ""}
                      onChange={(e) => setEvaluationVersion({ ...evaluationVersion, frontend_deployment: e.target.value })}
                      placeholder="예: Vercel dpl_abc123"
                    />
                  </div>
                  <div>
                    <label className="block mb-1 text-xs text-gray-600">Backend deployment ID</label>
                    <input
                      type="text"
                      className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-lg"
                      value={evaluationVersion.backend_deployment || ""}
                      onChange={(e) => setEvaluationVersion({ ...evaluationVersion, backend_deployment: e.target.value })}
                      placeholder="예: Railway xyz789"
                    />
                  </div>
                  <div>
                    <label className="block mb-1 text-xs text-gray-600">Git commit hash</label>
                    <input
                      type="text"
                      className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-lg font-mono"
                      value={evaluationVersion.git_commit || ""}
                      onChange={(e) => setEvaluationVersion({ ...evaluationVersion, git_commit: e.target.value })}
                      placeholder="예: a156b40"
                    />
                  </div>
                  <div>
                    <label className="block mb-1 text-xs text-gray-600">버전 라벨 (자유 표기)</label>
                    <input
                      type="text"
                      className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-lg"
                      value={evaluationVersion.version_label || ""}
                      onChange={(e) => setEvaluationVersion({ ...evaluationVersion, version_label: e.target.value })}
                      placeholder="예: 2026-05-22 배포본"
                    />
                  </div>
                </div>
              </div>

              {/* Card B — 평가 범위 자산 목록 */}
              <div className="mb-4 rounded-lg border border-gray-200 bg-white p-4">
                <div className="mb-3 flex items-center gap-2">
                  <Tag size={14} className="text-blue-600" />
                  <p className="text-xs font-semibold text-gray-800">평가 범위 자산 목록</p>
                  <span className="ml-auto text-[11px] text-gray-500">포함/제외 표시</span>
                </div>
                <div className="space-y-2">
                  {scopeAssets.map((asset, idx) => (
                    <div key={asset.name} className="grid grid-cols-12 gap-2 items-center">
                      <div className="col-span-3 text-xs text-gray-700">{asset.name}</div>
                      <div className="col-span-7">
                        <input
                          type="text"
                          className="w-full px-2.5 py-1 text-sm border border-gray-300 rounded"
                          value={asset.value}
                          onChange={(e) => {
                            const next = [...scopeAssets];
                            next[idx] = { ...next[idx], value: e.target.value };
                            setScopeAssets(next);
                          }}
                          placeholder={
                            asset.name === "Frontend URL" ? "https://tmarkovframework.vercel.app" :
                            asset.name === "Backend API" ? "https://api.tmarkov.example.com" :
                            asset.name === "Supabase project" ? "프로젝트 ID 또는 URL" :
                            asset.name === "GitHub repo" ? "owner/name" :
                            "값 또는 URL"
                          }
                        />
                      </div>
                      <div className="col-span-2">
                        <label className="flex items-center gap-1 text-xs text-gray-600 cursor-pointer">
                          <input
                            type="checkbox"
                            className="w-3.5 h-3.5"
                            checked={asset.included}
                            onChange={(e) => {
                              const next = [...scopeAssets];
                              next[idx] = { ...next[idx], included: e.target.checked };
                              setScopeAssets(next);
                            }}
                          />
                          포함
                        </label>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Card C — 데이터 등급 분류 */}
              <div className="mb-4 rounded-lg border border-gray-200 bg-white p-4">
                <div className="mb-3 flex items-center gap-2">
                  <DatabaseIcon size={14} className="text-blue-600" />
                  <p className="text-xs font-semibold text-gray-800">데이터 등급 분류 (민감도 · 보관 위치)</p>
                </div>
                <div className="space-y-2">
                  {dataClassifications.map((dc, idx) => (
                    <div key={dc.name} className="grid grid-cols-12 gap-2 items-center">
                      <div className="col-span-4 text-xs text-gray-700">{dc.name}</div>
                      <div className="col-span-3">
                        <select
                          className="w-full px-2 py-1 text-xs border border-gray-300 rounded bg-white"
                          value={dc.sensitivity}
                          onChange={(e) => {
                            const next = [...dataClassifications];
                            next[idx] = { ...next[idx], sensitivity: e.target.value as DataClassification["sensitivity"] };
                            setDataClassifications(next);
                          }}
                        >
                          <option value="낮음">낮음</option>
                          <option value="중간">중간</option>
                          <option value="높음">높음</option>
                        </select>
                      </div>
                      <div className="col-span-5">
                        <input
                          type="text"
                          className="w-full px-2.5 py-1 text-sm border border-gray-300 rounded"
                          value={dc.storage_location || ""}
                          onChange={(e) => {
                            const next = [...dataClassifications];
                            next[idx] = { ...next[idx], storage_location: e.target.value };
                            setDataClassifications(next);
                          }}
                          placeholder="예: Supabase / Notion / Drive"
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Card D — 판정자 4역할 */}
              <div className="rounded-lg border border-gray-200 bg-white p-4">
                <div className="mb-3 flex items-center gap-2">
                  <UsersIcon size={14} className="text-blue-600" />
                  <p className="text-xs font-semibold text-gray-800">판정자 4역할 (수동 항목은 최소 2인 리뷰)</p>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block mb-1 text-xs text-gray-600">App owner</label>
                    <input
                      type="text"
                      className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-lg"
                      value={reviewers.app_owner || ""}
                      onChange={(e) => setReviewers({ ...reviewers, app_owner: e.target.value })}
                      placeholder="이름"
                    />
                  </div>
                  <div>
                    <label className="block mb-1 text-xs text-gray-600">Backend owner</label>
                    <input
                      type="text"
                      className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-lg"
                      value={reviewers.backend_owner || ""}
                      onChange={(e) => setReviewers({ ...reviewers, backend_owner: e.target.value })}
                      placeholder="이름"
                    />
                  </div>
                  <div>
                    <label className="block mb-1 text-xs text-gray-600">Cloud owner</label>
                    <input
                      type="text"
                      className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-lg"
                      value={reviewers.cloud_owner || ""}
                      onChange={(e) => setReviewers({ ...reviewers, cloud_owner: e.target.value })}
                      placeholder="이름"
                    />
                  </div>
                  <div>
                    <label className="block mb-1 text-xs text-gray-600">Security reviewer</label>
                    <input
                      type="text"
                      className="w-full px-3 py-1.5 text-sm border border-gray-300 rounded-lg"
                      value={reviewers.security_reviewer || ""}
                      onChange={(e) => setReviewers({ ...reviewers, security_reviewer: e.target.value })}
                      placeholder="이름"
                    />
                  </div>
                </div>
              </div>
            </div>

            <div className="flex justify-between pt-4">
              <button
                type="button"
                onClick={handleSaveDraft}
                className="px-6 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
              >
                임시저장
              </button>
              <button
                onClick={goToStep2}
                className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                다음 단계
              </button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-6">
            <div className="flex items-center gap-2 mb-2">
              <Info className="text-blue-600" size={22} />
              <h2>Step 2: 진단 방식 안내</h2>
            </div>
            <p className="text-sm text-gray-500">
              선택하신 필러와 도구 기반으로 진단이 진행됩니다. 다음 단계에서 최종 확인 후 진단을 시작하세요.
            </p>
            <div className="space-y-3">
              {PILLARS.filter((p) => pillarScope[p.key]).map((pillar) => {
                const autoTools = Object.entries(toolScope).filter(([, on]) => on).map(([k]) => k);
                return (
                  <div key={pillar.key} className="border border-gray-200 rounded-lg p-4">
                    <div className="flex items-center justify-between">
                      <h3 className="font-semibold text-gray-800">{pillar.label}</h3>
                      <span className="text-xs text-gray-400">진단 대상 필러</span>
                    </div>
                    <p className="mt-2 text-xs text-gray-500">
                      자동 수집 도구: {autoTools.length > 0 ? autoTools.join(", ") : "없음 (전체 수동 진단)"}
                    </p>
                    <p className="mt-1 text-xs text-gray-400">
                      세부 체크리스트 답변은 진단 시작 후 자동 수집과 병행하여 진행됩니다.
                    </p>
                  </div>
                );
              })}
              {Object.values(pillarScope).every((v) => !v) && (
                <p className="text-sm text-amber-600 bg-amber-50 border border-amber-200 rounded px-3 py-2">
                  선택된 필러가 없습니다. 이전 단계에서 진단 범위를 선택해주세요.
                </p>
              )}
            </div>

            {/* 수동 양식 미리 작성 (선택) — 진단 시작 전 자동 채점 */}
            <div className="rounded-xl border border-blue-200 bg-blue-50/40 p-5">
              <div className="flex items-center gap-2 mb-2">
                <Upload size={18} className="text-blue-700" />
                <h3 className="text-sm font-semibold text-gray-800">
                  수동 진단 양식 미리 작성 (선택)
                </h3>
              </div>
              <p className="text-xs text-gray-600 mb-3">
                Step 1에서 선택한 IdP/SIEM 환경에 맞춰 자동 진단이 불가능한 항목만 모은 Excel 양식을
                미리 받아 채울 수 있습니다. 업로드 시 자동 채점됩니다.
                다음 단계 마지막에 [진단 시작]을 누르면 자동 수집과 합쳐져 최종 PDF가 만들어집니다.
              </p>

              {!preparedSessionId ? (
                <button
                  type="button"
                  onClick={handlePrepareSession}
                  disabled={preparing || selectedPillarCount === 0}
                  className={`inline-flex items-center gap-2 px-4 py-2 text-sm rounded-lg ${
                    preparing || selectedPillarCount === 0
                      ? "bg-gray-300 text-gray-500 cursor-not-allowed"
                      : "bg-blue-600 text-white hover:bg-blue-700"
                  }`}
                >
                  {preparing ? "준비 중..." : "환경 기반 양식 준비"}
                </button>
              ) : (
                <div className="space-y-3">
                  <p className="text-xs text-emerald-700">
                    ✅ 세션 준비 완료 (session #{preparedSessionId}). 양식 다운로드 → 작성 → 업로드.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={handleDownloadManualTemplate}
                      className="inline-flex items-center gap-2 px-4 py-2 text-sm border border-gray-300 bg-white rounded-lg hover:bg-gray-50 text-gray-700"
                    >
                      <FileText size={15} />
                      양식 다운로드 (.xlsx)
                    </button>
                    <label
                      className={`inline-flex items-center gap-2 px-4 py-2 text-sm rounded-lg cursor-pointer ${
                        manualUploading
                          ? "bg-gray-100 text-gray-400 cursor-not-allowed"
                          : "bg-blue-600 text-white hover:bg-blue-700"
                      }`}
                    >
                      <Upload size={15} />
                      {manualUploading ? "업로드 중..." : "작성한 양식 업로드"}
                      <input
                        ref={manualFileInputRef}
                        type="file"
                        accept=".xlsx"
                        className="hidden"
                        disabled={manualUploading}
                        onChange={handleManualExcelUpload}
                      />
                    </label>
                  </div>
                  {manualUploadResult && (
                    <div className="text-xs text-gray-700 bg-white rounded border border-gray-200 px-3 py-2">
                      <span className="font-semibold text-emerald-700">자동 채점 완료:</span>{" "}
                      <strong>{manualUploadResult.parsed}건</strong> 채점,
                      건너뜀 {manualUploadResult.skipped}건, 매칭 실패 {manualUploadResult.unmatched}건.
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex justify-between pt-4">
              <button onClick={() => setStep(1)} className="px-6 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">
                이전
              </button>
              <button onClick={() => setStep(3)} className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                다음 단계
              </button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-6">
            <h2>Step 3: 최종 확인 및 진단 시작</h2>
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-6 space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-gray-600">기관명</p>
                  <p>{formData.orgName || "미입력"}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">기관 유형</p>
                  <p>{formData.orgType}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">담당자</p>
                  <p>
                    {formData.manager || "미입력"}
                    {formData.department && <span className="text-gray-500"> · {formData.department}</span>}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">이메일</p>
                  <p>{formData.email || "미입력"}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">인프라 유형</p>
                  <p>{formData.infraType}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">진단 범위</p>
                  <p>{selectedPillarCount}개 필러</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600">규모</p>
                  <p className="text-sm">
                    임직원 {formData.employees || "-"}명 · 서버 {formData.servers || "-"}대 · 앱 {formData.applications || "-"}개
                  </p>
                </div>
                {files.length > 0 && (
                  <div>
                    <p className="text-sm text-gray-600">업로드된 파일</p>
                    <p>{files.length}개</p>
                  </div>
                )}
                {formData.note.trim() && (
                  <div className="md:col-span-2">
                    <p className="text-sm text-gray-600">비고</p>
                    <p className="text-sm whitespace-pre-wrap">{formData.note}</p>
                  </div>
                )}
              </div>
            </div>
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
              <p className="text-sm">예상 소요 시간: 약 5-10분</p>
            </div>
            {/* 실행 모드 안내 */}
            <div className={`border rounded-lg p-4 text-sm ${
              isLive ? "bg-red-50 border-red-200 text-red-800" : "bg-blue-50 border-blue-200 text-blue-800"
            }`}>
              {isLive ? (
                <div className="flex items-start gap-2">
                  <AlertTriangle size={16} className="mt-0.5 shrink-0" />
                  <div>
                    <p className="font-semibold">실 스캔 모드로 진단을 시작합니다.</p>
                    <p className="text-xs mt-1">
                      입력한 외부 시스템(Keycloak/Wazuh/Nmap/Trivy)을 실제로 스캔합니다.
                      {liveScanIntent && !consentExternalScan && " 외부 스캔 동의 체크가 필요합니다."}
                      {liveScanIntent && consentExternalScan && consentMetaMissing &&
                        " 승인자/비상연락처 입력이 필요합니다."}
                    </p>
                  </div>
                </div>
              ) : (
                <div className="flex items-start gap-2">
                  <FlaskConical size={16} className="mt-0.5 shrink-0" />
                  <p>데모 모드로 진단을 시작합니다. 외부 시스템에 접근하지 않고 예시 데이터로 진행됩니다.</p>
                </div>
              )}
            </div>
            <div className="flex justify-between pt-4">
              <button onClick={() => setStep(2)} className="px-6 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">
                이전
              </button>
              <button
                onClick={handleSubmit}
                disabled={submitDisabled}
                title={
                  submitDisabled
                    ? consentMetaMissing
                      ? "승인자/비상연락처를 입력해야 외부 스캔을 시작할 수 있습니다."
                      : "외부 스캔 동의 체크 후 진행 가능합니다."
                    : undefined
                }
                className={`px-8 py-3 text-white rounded-lg ${
                  submitDisabled
                    ? "bg-gray-300 cursor-not-allowed"
                    : "bg-green-600 hover:bg-green-700"
                }`}
              >
                진단 시작
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
