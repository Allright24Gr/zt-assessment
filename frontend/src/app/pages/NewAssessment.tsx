import { useRef, useState } from "react";
import { useNavigate } from "react-router";
import { Building2, Upload, CheckCircle2, FileText, X, Wrench, Info } from "lucide-react";
import { toast } from "sonner";
import { PILLARS } from "../data/constants";
import { runAssessment } from "../../config/api";

const TOOLS = [
  {
    key: "keycloak",
    label: "Keycloak",
    desc: "ID/접근 관리 (IAM/SSO/MFA)",
    detail: "신원 확인, 인증 정책, 접근 권한 항목 자동 수집",
  },
  {
    key: "wazuh",
    label: "Wazuh",
    desc: "SIEM / EDR / 로그 수집",
    detail: "보안 이벤트, 취약점, 정책 위반 항목 자동 수집",
  },
  {
    key: "nmap",
    label: "Nmap",
    desc: "네트워크 스캔",
    detail: "네트워크 세그먼테이션, 포트·서비스 현황 자동 수집",
  },
  {
    key: "trivy",
    label: "Trivy",
    desc: "컨테이너·소프트웨어 취약점",
    detail: "이미지 스캔, SBOM, 공급망 보안 항목 자동 수집",
  },
] as const;

const ORG_TYPES = ["기업", "공공기관", "금융기관", "의료기관"];
const INFRA_TYPES = ["온프레미스", "클라우드 (AWS)", "클라우드 (Azure)", "클라우드 (GCP)", "하이브리드"];

export function NewAssessment() {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [step, setStep] = useState(1);
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
  const [pillarScope, setPillarScope] = useState<Record<string, boolean>>(
    Object.fromEntries(PILLARS.map((p) => [p.key, true]))
  );
  const [toolScope, setToolScope] = useState<Record<string, boolean>>({
    keycloak: false, wazuh: false, nmap: false, trivy: false,
  });
  const [files, setFiles] = useState<File[]>([]);

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

  const handleSubmit = () => {
    const excludedTools = Object.entries(toolScope)
      .filter(([, enabled]) => !enabled)
      .map(([tool]) => tool)
      .join(",");

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
        JSON.stringify({ formData, pillarScope, toolScope }),
      );
      toast.success("입력한 내용이 임시저장되었습니다.");
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
              <h2>Step 1: 기업 환경 입력</h2>
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

            {/* 보안 도구 선택 */}
            <div>
              <div className="flex items-center gap-2 mb-3">
                <Wrench size={16} className="text-blue-600" />
                <h3 className="text-sm font-semibold text-gray-700">귀사에서 사용 중인 보안 도구 선택</h3>
              </div>
              <p className="text-xs text-gray-500 mb-3">
                선택한 도구의 항목은 자동으로 수집됩니다. 선택하지 않은 도구의 항목은 다음 단계에서 직접 답변합니다.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {TOOLS.map((tool) => (
                  <label
                    key={tool.key}
                    className={`flex items-start gap-3 p-3 border rounded-lg cursor-pointer transition-colors ${
                      toolScope[tool.key]
                        ? "border-blue-400 bg-blue-50"
                        : "border-gray-200 hover:bg-gray-50"
                    }`}
                  >
                    <input
                      type="checkbox"
                      className="mt-0.5 w-4 h-4"
                      checked={!!toolScope[tool.key]}
                      onChange={() =>
                        setToolScope((prev) => ({ ...prev, [tool.key]: !prev[tool.key] }))
                      }
                    />
                    <div>
                      <p className="text-sm font-semibold text-gray-800">{tool.label}
                        <span className="ml-2 text-xs font-normal text-gray-500">{tool.desc}</span>
                      </p>
                      <p className="text-xs text-gray-400 mt-0.5">{tool.detail}</p>
                    </div>
                  </label>
                ))}
              </div>
              {Object.values(toolScope).every((v) => !v) && (
                <p className="mt-2 text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded px-3 py-2">
                  도구를 선택하지 않으면 모든 항목을 직접 답변해야 합니다.
                </p>
              )}
            </div>

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
              <label className="block mb-2">증적 자료 업로드</label>
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
            <div className="flex justify-between pt-4">
              <button onClick={() => setStep(2)} className="px-6 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">
                이전
              </button>
              <button onClick={handleSubmit} className="px-8 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700">
                진단 시작
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
