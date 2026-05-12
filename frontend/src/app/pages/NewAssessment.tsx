import { useRef, useState } from "react";
import { useNavigate } from "react-router";
import { Building2, Upload, CheckCircle2, FileText, X } from "lucide-react";
import { toast } from "sonner";
import { PILLARS } from "../data/constants";
import { runAssessment } from "../../config/api";

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
    runAssessment({
      org_name: formData.orgName,
      manager: formData.manager,
      department: formData.department,
      email: formData.email,
      contact: formData.contact,
      org_type: formData.orgType,
      infra_type: formData.infraType,
      employees: Number(formData.employees) || 0,
      servers: Number(formData.servers) || 0,
      applications: Number(formData.applications) || 0,
      note: formData.note,
      pillar_scope: pillarScope,
    })
      .then((res) => navigate(`/in-progress/${res.session_id}`))
      .catch(() => navigate("/in-progress/new-session"));
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
              <button className="px-6 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">
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
            <h2>Step 2: 수동 항목 직접 입력</h2>
            <div className="space-y-4">
              {PILLARS.filter((p) => pillarScope[p.key]).map((pillar) => (
                <div key={pillar.key} className="border border-gray-200 rounded-lg p-4">
                  <h3 className="mb-3">{pillar.label}</h3>
                  <div className="space-y-2">
                    {[1, 2, 3].map((item) => (
                      <label key={item} className="flex items-center justify-between p-3 bg-gray-50 rounded">
                        <span className="text-sm">체크리스트 항목 {item}</span>
                        <div className="flex gap-4">
                          <label className="flex items-center gap-2">
                            <input type="radio" name={`${pillar.key}-${item}`} defaultChecked />
                            <span className="text-sm">True</span>
                          </label>
                          <label className="flex items-center gap-2">
                            <input type="radio" name={`${pillar.key}-${item}`} />
                            <span className="text-sm">False</span>
                          </label>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>
              ))}
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
