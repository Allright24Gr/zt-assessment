import { useRef, useState, useEffect } from "react";
import { useNavigate } from "react-router";
import { Building2, Upload, CheckCircle2, FileText, X, Info, Target, AlertTriangle, Shield, KeyRound, Activity, FlaskConical, Fingerprint } from "lucide-react";
import { toast } from "sonner";
import { PILLARS } from "../data/constants";
import { runAssessment } from "../../config/api";
import { useAuth } from "../context/AuthContext";
import type { ScanTargets, KeycloakCreds, WazuhCreds, EntraCreds, OktaCreds, SplunkCreds, IdpType, SiemType } from "../../types/api";

const ORG_TYPES = ["기업", "공공기관", "금융기관", "의료기관"];
const INFRA_TYPES = ["온프레미스", "클라우드 (AWS)", "클라우드 (Azure)", "클라우드 (GCP)", "하이브리드"];

// 사전 프로파일링 — 신원 관리(IdP) 선택지
const IDP_OPTIONS: Array<{ key: IdpType; label: string; desc: string; supported: boolean }> = [
  { key: "keycloak", label: "Keycloak",                desc: "오픈소스 IAM/SSO",        supported: true  },
  { key: "entra",    label: "MS Entra ID (Azure AD)",  desc: "Microsoft 클라우드 IdP",   supported: true  },
  { key: "okta",     label: "Okta",                    desc: "SaaS IdP",                supported: true  },
  { key: "ldap",     label: "자체 LDAP / AD",          desc: "온프레미스 디렉터리",      supported: false },
  { key: "none",     label: "사용 안 함 / 기타",       desc: "수동 진단으로 폴백",       supported: false },
];

// 사전 프로파일링 — 보안 정보 관리(SIEM) 선택지
const SIEM_OPTIONS: Array<{ key: SiemType; label: string; desc: string; supported: boolean }> = [
  { key: "wazuh",   label: "Wazuh",        desc: "오픈소스 SIEM/XDR",  supported: true  },
  { key: "splunk",  label: "Splunk",       desc: "상용 SIEM",          supported: true  },
  { key: "elastic", label: "Elastic SIEM", desc: "Elastic Stack",      supported: false },
  { key: "none",    label: "사용 안 함 / 기타", desc: "수동 진단으로 폴백", supported: false },
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
    const next = {
      orgName:      p.org_name      ?? user.orgName ?? "",
      manager:      user.username   ?? "",
      department:   p.department    ?? "",
      email:        user.email      ?? "",
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
  // 사전 프로파일링 선택 — 기본은 현재 동작과 동일(Keycloak + Wazuh)
  const [profileSelect, setProfileSelect] = useState<{ idp_type: IdpType; siem_type: SiemType }>({
    idp_type: "keycloak",
    siem_type: "wazuh",
  });
  // 외부 자동 스캔(도구 무관) 토글 — Nmap / Trivy
  const [externalScanTools, setExternalScanTools] = useState<{ nmap: boolean; trivy: boolean }>({
    nmap: true, trivy: true,
  });
  // 내부적으로 백엔드에 보내는 tool_scope는 profileSelect + externalScanTools에서 파생
  const toolScope: Record<string, boolean> = {
    keycloak: profileSelect.idp_type === "keycloak",
    entra:    profileSelect.idp_type === "entra",
    okta:     profileSelect.idp_type === "okta",
    wazuh:    profileSelect.siem_type === "wazuh",
    splunk:   profileSelect.siem_type === "splunk",
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
  // Keycloak 연결 카드 입력값 (작업 E-fe)
  const [keycloakCreds, setKeycloakCreds] = useState<{ url: string; admin_user: string; admin_pass: string }>({
    url: "", admin_user: "", admin_pass: "",
  });
  // Wazuh 연결 카드 입력값 (작업 E-fe)
  const [wazuhCreds, setWazuhCreds] = useState<{ url: string; api_user: string; api_pass: string }>({
    url: "", api_user: "", api_pass: "",
  });
  // Entra ID 자격 카드 입력값 (신규)
  const [entraCreds, setEntraCreds] = useState<{ tenant_id: string; client_id: string; client_secret: string }>({
    tenant_id: "", client_id: "", client_secret: "",
  });
  // Okta 자격 카드 입력값 (P0/P1 기타)
  const [oktaCreds, setOktaCreds] = useState<{ domain: string; api_token: string }>({
    domain: "", api_token: "",
  });
  // Splunk 자격 카드 입력값 (P0/P1 기타)
  const [splunkCreds, setSplunkCreds] = useState<{ url: string; user: string; password: string }>({
    url: "", user: "", password: "",
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
  const submitDisabled = !!liveScanIntent && !consentExternalScan;

  const handleSubmit = () => {
    const excludedTools = Object.entries(toolScope)
      .filter(([, enabled]) => !enabled)
      .map(([tool]) => tool)
      .join(",");

    // 데모 모드: 외부 시스템 정보를 일절 전송하지 않는다.
    // 실 스캔 모드: 입력된 외부 시스템 정보만 선택적으로 전송한다.
    const nmapTarget = scanTargets.nmap.trim();
    const trivyTarget = scanTargets.trivy.trim();
    const scanTargetsPayload: ScanTargets = {};
    if (isLive && toolScope.nmap && nmapTarget) scanTargetsPayload.nmap = nmapTarget;
    if (isLive && toolScope.trivy && trivyTarget) scanTargetsPayload.trivy = trivyTarget;
    const hasScanTargets = Object.keys(scanTargetsPayload).length > 0;

    // Keycloak/Wazuh 연결 정보 — 실 스캔 모드 + 도구 선택 시에만, 그리고 입력값이 있을 때만 전송
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

    // Entra ID 자격: 실 스캔 모드 + IdP=entra + 입력값이 있을 때만 전송
    const entraPayload: EntraCreds = {};
    if (isLive && toolScope.entra) {
      if (entraCreds.tenant_id.trim())     entraPayload.tenant_id     = entraCreds.tenant_id.trim();
      if (entraCreds.client_id.trim())     entraPayload.client_id     = entraCreds.client_id.trim();
      if (entraCreds.client_secret)        entraPayload.client_secret = entraCreds.client_secret;
    }
    const hasEntra = Object.keys(entraPayload).length > 0;

    // Okta 자격: 실 스캔 모드 + IdP=okta + 입력값이 있을 때만 전송
    const oktaPayload: OktaCreds = {};
    if (isLive && toolScope.okta) {
      if (oktaCreds.domain.trim())    oktaPayload.domain    = oktaCreds.domain.trim();
      if (oktaCreds.api_token)         oktaPayload.api_token = oktaCreds.api_token;
    }
    const hasOkta = Object.keys(oktaPayload).length > 0;

    // Splunk 자격: 실 스캔 모드 + SIEM=splunk + 입력값이 있을 때만 전송
    const splunkPayload: SplunkCreds = {};
    if (isLive && toolScope.splunk) {
      if (splunkCreds.url.trim())  splunkPayload.url      = splunkCreds.url.trim();
      if (splunkCreds.user.trim()) splunkPayload.user     = splunkCreds.user.trim();
      if (splunkCreds.password)    splunkPayload.password = splunkCreds.password;
    }
    const hasSplunk = Object.keys(splunkPayload).length > 0;

    runAssessment({
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
      ...(hasScanTargets ? { scan_targets: scanTargetsPayload } : {}),
      ...(hasKc ? { keycloak_creds: kcPayload } : {}),
      ...(hasWz ? { wazuh_creds: wzPayload } : {}),
      ...(hasEntra ? { entra_creds: entraPayload } : {}),
      ...(hasOkta ? { okta_creds: oktaPayload } : {}),
      ...(hasSplunk ? { splunk_creds: splunkPayload } : {}),
    })
      .then((res) =>
        navigate(`/in-progress/${res.session_id}`, {
          state: {
            excludedTools,
            orgName: formData.orgName,
            manager: formData.manager,
          },
        })
      )
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
          keycloakCreds: { url: keycloakCreds.url, admin_user: keycloakCreds.admin_user },
          wazuhCreds:    { url: wazuhCreds.url,    api_user:   wazuhCreds.api_user   },
          entraCreds:    { tenant_id: entraCreds.tenant_id, client_id: entraCreds.client_id },
          oktaCreds:     { domain: oktaCreds.domain },
          splunkCreds:   { url: splunkCreds.url, user: splunkCreds.user },
        }),
      );
      toast.success("입력한 내용이 임시저장되었습니다. (비밀번호는 저장되지 않습니다)");
    } catch (err) {
      console.warn("[new-assessment] save draft failed:", err);
      toast.error("임시저장에 실패했습니다.");
    }
  };

  return (
    <div className="max-w-4xl mx-auto">
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
                    <p className="text-xs text-gray-500 mt-0.5">
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
                    <p className="text-xs text-gray-500 mt-0.5">
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
                        className={`flex items-start gap-2 p-2.5 border rounded-lg cursor-pointer transition-colors ${
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
                        <div className="min-w-0">
                          <p className="text-sm font-medium text-gray-800 flex items-center gap-1.5">
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
                        className={`flex items-start gap-2 p-2.5 border rounded-lg cursor-pointer transition-colors ${
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
                        <div className="min-w-0">
                          <p className="text-sm font-medium text-gray-800 flex items-center gap-1.5">
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
                  <label className={`flex items-start gap-2 p-2.5 border rounded-lg cursor-pointer transition-colors ${
                    externalScanTools.nmap ? "border-blue-500 bg-white shadow-sm" : "border-gray-200 bg-white hover:bg-gray-50"
                  }`}>
                    <input
                      type="checkbox"
                      className="mt-0.5 w-4 h-4"
                      checked={externalScanTools.nmap}
                      onChange={() => setExternalScanTools((p) => ({ ...p, nmap: !p.nmap }))}
                    />
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-gray-800">Nmap</p>
                      <p className="text-xs text-gray-500">네트워크/포트 외부 스캔</p>
                    </div>
                  </label>
                  <label className={`flex items-start gap-2 p-2.5 border rounded-lg cursor-pointer transition-colors ${
                    externalScanTools.trivy ? "border-blue-500 bg-white shadow-sm" : "border-gray-200 bg-white hover:bg-gray-50"
                  }`}>
                    <input
                      type="checkbox"
                      className="mt-0.5 w-4 h-4"
                      checked={externalScanTools.trivy}
                      onChange={() => setExternalScanTools((p) => ({ ...p, trivy: !p.trivy }))}
                    />
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-gray-800">Trivy</p>
                      <p className="text-xs text-gray-500">컨테이너 이미지 스캔</p>
                    </div>
                  </label>
                </div>
              </div>

              {/* 폴백 안내 */}
              {(profileSelect.idp_type === "ldap" || profileSelect.idp_type === "none" ||
                profileSelect.siem_type === "elastic" || profileSelect.siem_type === "none") && (
                <div className="mt-4 flex items-start gap-2 p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-800">
                  <Info size={14} className="mt-0.5 shrink-0" />
                  <span>
                    선택한 도구 중 일부는 현재 cycle에서 자동 진단을 지원하지 않습니다. 해당 분야의 자동 항목은 다음 단계에서 <strong>수동 진단</strong>으로 표시됩니다.
                  </span>
                </div>
              )}
            </div>

            {/* 기관 정보 */}
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

            <div>
              <label className="block mb-2">
                진단 범위 선택 <span className="text-sm text-gray-400">({selectedPillarCount}/{PILLARS.length})</span>
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {PILLARS.map((pillar) => (
                  <label key={pillar.key} className="flex items-center gap-2 p-3 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
                    <input
                      type="checkbox"
                      className="w-4 h-4"
                      checked={!!pillarScope[pillar.key]}
                      onChange={() => togglePillar(pillar.key)}
                    />
                    <span className="text-sm">{pillar.label}</span>
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
                  </>
                )}
              </div>
            )}

            {/* IdP / SIEM 연결 카드 (작업 E-fe + Entra/Okta/Splunk) */}
            {(toolScope.keycloak || toolScope.entra || toolScope.okta || toolScope.wazuh || toolScope.splunk) && (
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
                  {/* Entra ID 카드 (신규) */}
                  {toolScope.entra && (
                    <div className="border border-gray-200 rounded-lg p-4 bg-gray-50/40">
                      <div className="flex items-center gap-2 mb-3">
                        <span className="text-xs font-semibold text-gray-700">MS Entra ID</span>
                        <span className="text-[10px] text-gray-400">Azure AD</span>
                      </div>
                      <div className="space-y-2.5">
                        <input
                          type="text"
                          autoComplete="off"
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                          value={entraCreds.tenant_id}
                          onChange={(e) => setEntraCreds({ ...entraCreds, tenant_id: e.target.value })}
                          placeholder="00000000-0000-0000-0000-000000000000"
                          disabled={!isLive}
                          aria-label="Entra Tenant ID"
                        />
                        <input
                          type="text"
                          autoComplete="off"
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                          value={entraCreds.client_id}
                          onChange={(e) => setEntraCreds({ ...entraCreds, client_id: e.target.value })}
                          placeholder="app registration의 Application(client) ID"
                          disabled={!isLive}
                          aria-label="Entra Client ID"
                        />
                        <input
                          type="password"
                          autoComplete="new-password"
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                          value={entraCreds.client_secret}
                          onChange={(e) => setEntraCreds({ ...entraCreds, client_secret: e.target.value })}
                          placeholder="Client Secret"
                          disabled={!isLive}
                          aria-label="Entra Client Secret"
                        />
                        <p className="text-[11px] text-gray-500 leading-relaxed">
                          Microsoft Entra admin center → App registrations → API permissions에
                          <strong className="text-gray-700"> Directory.Read.All, Policy.Read.All, AuditLog.Read.All</strong> 권한 부여 필요
                        </p>
                      </div>
                    </div>
                  )}
                  {/* Okta 카드 */}
                  {toolScope.okta && (
                    <div className="border border-gray-200 rounded-lg p-4 bg-gray-50/40">
                      <div className="flex items-center gap-2 mb-3">
                        <span className="text-xs font-semibold text-gray-700">Okta</span>
                        <span className="text-[10px] text-gray-400">SaaS IdP</span>
                      </div>
                      <div className="space-y-2.5">
                        <input
                          type="text"
                          autoComplete="off"
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                          value={oktaCreds.domain}
                          onChange={(e) => setOktaCreds({ ...oktaCreds, domain: e.target.value })}
                          placeholder="dev-12345.okta.com"
                          disabled={!isLive}
                          aria-label="Okta 도메인"
                        />
                        <input
                          type="password"
                          autoComplete="new-password"
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                          value={oktaCreds.api_token}
                          onChange={(e) => setOktaCreds({ ...oktaCreds, api_token: e.target.value })}
                          placeholder="API Token"
                          disabled={!isLive}
                          aria-label="Okta API Token"
                        />
                        <p className="text-[11px] text-gray-500 leading-relaxed">
                          Okta Admin Console → Security → API → Tokens 에서 발급한
                          <strong className="text-gray-700"> Read-only API Token</strong> 필요
                        </p>
                      </div>
                    </div>
                  )}
                  {/* Splunk 카드 */}
                  {toolScope.splunk && (
                    <div className="border border-gray-200 rounded-lg p-4 bg-gray-50/40">
                      <div className="flex items-center gap-2 mb-3">
                        <span className="text-xs font-semibold text-gray-700">Splunk</span>
                        <span className="text-[10px] text-gray-400">상용 SIEM</span>
                      </div>
                      <div className="space-y-2.5">
                        <input
                          type="text"
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                          value={splunkCreds.url}
                          onChange={(e) => setSplunkCreds({ ...splunkCreds, url: e.target.value })}
                          placeholder="https://splunk.example.com:8089"
                          disabled={!isLive}
                          aria-label="Splunk URL"
                        />
                        <input
                          type="text"
                          autoComplete="off"
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                          value={splunkCreds.user}
                          onChange={(e) => setSplunkCreds({ ...splunkCreds, user: e.target.value })}
                          placeholder="admin"
                          disabled={!isLive}
                          aria-label="Splunk 사용자"
                        />
                        <input
                          type="password"
                          autoComplete="new-password"
                          className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm disabled:bg-gray-100 disabled:text-gray-400 disabled:cursor-not-allowed"
                          value={splunkCreds.password}
                          onChange={(e) => setSplunkCreds({ ...splunkCreds, password: e.target.value })}
                          placeholder="비밀번호"
                          disabled={!isLive}
                          aria-label="Splunk 비밀번호"
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
                title={submitDisabled ? "외부 스캔 동의 체크 후 진행 가능합니다." : undefined}
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
