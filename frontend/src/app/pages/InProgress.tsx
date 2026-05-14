import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams, useLocation } from "react-router";
import { CheckCircle, ChevronDown, ChevronRight, Download, Loader2, Shield, Upload } from "lucide-react";
import { toast } from "sonner";
import {
  getManualItems, submitManual, finalizeAssessment,
  getAssessmentStatus, uploadManualExcel,
} from "../../config/api";
import type { ManualItemDetail } from "../../types/api";

const MANUAL_TEMPLATE_URL = "http://localhost:8000/api/manual/template";

const RESULT_OPTIONS = [
  { value: "충족", label: "충족", color: "text-green-700 border-green-400 bg-green-50" },
  { value: "부분충족", label: "부분 충족", color: "text-yellow-700 border-yellow-400 bg-yellow-50" },
  { value: "미충족", label: "미충족", color: "text-red-700 border-red-400 bg-red-50" },
  { value: "평가불가", label: "해당 없음", color: "text-gray-500 border-gray-300 bg-gray-50" },
] as const;

type ResultValue = (typeof RESULT_OPTIONS)[number]["value"];

export function InProgress() {
  const navigate = useNavigate();
  const { sessionId } = useParams();
  const location = useLocation();
  const { excludedTools = "", orgName = "", manager = "" } = (location.state ?? {}) as {
    excludedTools?: string;
    orgName?: string;
    manager?: string;
  };

  const [items, setItems] = useState<ManualItemDetail[]>([]);
  const [answers, setAnswers] = useState<Record<string, ResultValue>>({});
  const [evidences, setEvidences] = useState<Record<string, string>>({});
  const [expandedPillars, setExpandedPillars] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [autoRunning, setAutoRunning] = useState(false);
  const [collectionDone, setCollectionDone] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadMode, setUploadMode] = useState<"form" | "excel">("form");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const sid = sessionId && sessionId !== "demo" ? sessionId : null;

  useEffect(() => {
    if (!sid) {
      setLoading(false);
      return;
    }

    const hasAutoTools = excludedTools !== "keycloak,wazuh,nmap,trivy" && excludedTools.split(",").filter(Boolean).length < 4;
    setAutoRunning(hasAutoTools);

    getManualItems(sid, excludedTools)
      .then((res) => {
        setItems(res.items);
        const pre: Record<string, ResultValue> = {};
        res.items.forEach((item) => {
          if (item.submitted) pre[item.item_id] = "충족";
        });
        setAnswers(pre);
        const firstPillar = res.items[0]?.pillar;
        if (firstPillar) setExpandedPillars({ [firstPillar]: true });
      })
      .catch(() => toast.error("항목 로드 실패. 새로고침 해주세요."))
      .finally(() => setLoading(false));
  }, [sid, excludedTools]);

  // 자동수집 폴링
  useEffect(() => {
    if (!sid || !autoRunning || collectionDone) return;

    pollRef.current = setInterval(() => {
      getAssessmentStatus(sid)
        .then((s) => {
          if (s.collection_done) {
            setCollectionDone(true);
            setAutoRunning(false);
            if (pollRef.current) clearInterval(pollRef.current);
            toast.success("자동 수집이 완료되었습니다.");
          }
        })
        .catch(() => {/* 폴링 오류는 무시 */});
    }, 5000);

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [sid, autoRunning, collectionDone]);

  const byPillar = items.reduce<Record<string, ManualItemDetail[]>>((acc, item) => {
    (acc[item.pillar] ??= []).push(item);
    return acc;
  }, {});

  const totalCount = items.length;
  const answeredCount = Object.keys(answers).length;
  const allAnswered = totalCount > 0 && answeredCount >= totalCount;
  const progress = totalCount > 0 ? Math.round((answeredCount / totalCount) * 100) : 0;

  const handleExcelUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !sid) return;
    if (!file.name.endsWith(".xlsx")) {
      toast.error(".xlsx 파일만 업로드 가능합니다.");
      return;
    }
    setUploading(true);
    try {
      const res = await uploadManualExcel(sid, file);
      toast.success(`${res.parsed_count}개 항목이 업로드되었습니다.`);
      await finalizeAssessment(sid);
      toast.success("진단이 완료되었습니다.");
      navigate(`/reporting/${sid}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "업로드 중 오류가 발생했습니다.";
      toast.error(msg);
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const handleSubmit = async () => {
    if (!sid) {
      navigate("/reporting/demo");
      return;
    }
    if (!allAnswered) {
      toast.error("모든 항목에 답변해주세요.");
      return;
    }
    setSubmitting(true);
    try {
      await submitManual({
        session_id: Number(sid),
        answers: items.map((item) => ({
          check_id: item.item_id,
          value: answers[item.item_id] ?? "평가불가",
          evidence: evidences[item.item_id] ?? "",
        })),
      });
      await finalizeAssessment(sid);
      toast.success("진단이 완료되었습니다.");
      navigate(`/reporting/${sid}`);
    } catch {
      toast.error("제출 중 오류가 발생했습니다. 다시 시도해주세요.");
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3">
        <Loader2 size={32} className="animate-spin text-blue-600" />
        <p className="text-gray-500">진단 항목을 불러오는 중...</p>
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* 헤더 */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Shield size={20} className="text-blue-600" />
            <h1>제로트러스트 보안 자가진단</h1>
          </div>
          <p className="text-sm text-gray-500">
            {orgName || "진단 대상"}{manager ? ` · ${manager} 담당자` : ""}
          </p>
        </div>
        {autoRunning && (
          <div className="flex items-center gap-2 px-3 py-1.5 bg-blue-50 border border-blue-200 rounded-full text-sm text-blue-700">
            <Loader2 size={14} className="animate-spin" />
            자동 수집 진행 중
          </div>
        )}
      </div>

      {/* 진행률 */}
      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-gray-700">답변 진행률</span>
          <span className="text-sm font-semibold text-blue-600">{answeredCount} / {totalCount}개</span>
        </div>
        <div className="w-full bg-gray-100 rounded-full h-2.5">
          <div
            className="bg-blue-600 h-2.5 rounded-full transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>
        {autoRunning && (
          <p className="text-xs text-gray-400 mt-2">
            선택하신 도구의 자동 수집이 백그라운드에서 진행되고 있습니다. 아래 항목을 먼저 답변하실 수 있습니다.
          </p>
        )}
      </div>

      {/* 입력 방식 선택 탭 */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="flex border-b border-gray-100">
          <button
            onClick={() => setUploadMode("form")}
            className={`flex-1 py-3 text-sm font-medium transition-colors ${uploadMode === "form" ? "bg-blue-50 text-blue-700 border-b-2 border-blue-600" : "text-gray-500 hover:text-gray-700"}`}
          >
            웹 설문 작성
          </button>
          <button
            onClick={() => setUploadMode("excel")}
            className={`flex-1 py-3 text-sm font-medium transition-colors ${uploadMode === "excel" ? "bg-blue-50 text-blue-700 border-b-2 border-blue-600" : "text-gray-500 hover:text-gray-700"}`}
          >
            Excel 파일 업로드
          </button>
        </div>

        {uploadMode === "excel" && (
          <div className="px-5 py-5 space-y-4">
            <p className="text-sm text-gray-600">
              수동 진단 체크리스트 Excel을 다운로드하여 작성한 후 업로드하세요.
              업로드 즉시 점수 계산이 시작됩니다.
            </p>
            <div className="flex gap-3">
              <a
                href={`${import.meta.env.VITE_API_BASE ?? "http://localhost:8000"}/api/manual/template`}
                download="manual-checklist-template.xlsx"
                className="flex items-center gap-2 px-4 py-2 text-sm border border-gray-300 rounded-lg hover:bg-gray-50 text-gray-700"
              >
                <Download size={15} />
                템플릿 다운로드
              </a>
              <label className={`flex items-center gap-2 px-4 py-2 text-sm rounded-lg cursor-pointer transition-colors ${uploading ? "bg-gray-100 text-gray-400 cursor-not-allowed" : "bg-blue-600 text-white hover:bg-blue-700"}`}>
                {uploading ? (
                  <><Loader2 size={15} className="animate-spin" /> 업로드 중...</>
                ) : (
                  <><Upload size={15} /> Excel 파일 선택</>
                )}
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".xlsx"
                  className="hidden"
                  disabled={uploading}
                  onChange={handleExcelUpload}
                />
              </label>
            </div>
            <p className="text-xs text-gray-400">
              지원 형식: .xlsx — 파일 내 <strong>★ 담당자 선택 (필수)</strong> 열을 모두 작성 후 업로드하세요.
            </p>
          </div>
        )}
      </div>

      {/* 설명 (웹 설문 모드에서만) */}
      {uploadMode === "form" && (
      <div className="bg-amber-50 border border-amber-200 rounded-lg px-4 py-3 text-sm text-amber-800">
        <strong>답변 기준</strong>: 귀사의 현재 보안 환경 기준으로 답변해 주세요. 확인이 어려운 항목은 <strong>해당 없음</strong>을 선택하세요.
      </div>
      )}

      {/* 항목 목록 (웹 설문 모드에서만) */}
      {uploadMode === "form" && (totalCount === 0 ? (
        <div className="bg-white rounded-xl border border-gray-200 p-10 text-center">
          <CheckCircle size={40} className="mx-auto text-green-500 mb-3" />
          <p className="font-semibold text-gray-700">수동 진단 항목이 없습니다</p>
          <p className="text-sm text-gray-400 mt-1 mb-6">선택하신 도구로 모든 항목이 자동 수집됩니다.</p>
          <button
            onClick={handleSubmit}
            disabled={submitting}
            className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            {submitting ? <Loader2 size={16} className="animate-spin inline mr-2" /> : null}
            결과 확인하기
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {Object.entries(byPillar).map(([pillar, pillarItems]) => {
            const isOpen = !!expandedPillars[pillar];
            const pillarAnswered = pillarItems.filter((i) => answers[i.item_id]).length;
            const pillarDone = pillarAnswered === pillarItems.length;

            return (
              <div key={pillar} className="bg-white rounded-xl border border-gray-200 overflow-hidden">
                <button
                  className="w-full flex items-center justify-between px-5 py-4 hover:bg-gray-50 transition-colors"
                  onClick={() =>
                    setExpandedPillars((prev) => ({ ...prev, [pillar]: !prev[pillar] }))
                  }
                >
                  <div className="flex items-center gap-3">
                    {pillarDone ? (
                      <CheckCircle size={18} className="text-green-500 shrink-0" />
                    ) : (
                      <div className="w-4.5 h-4.5 rounded-full border-2 border-gray-300 shrink-0" />
                    )}
                    <span className="font-semibold text-gray-800 text-sm">{pillar}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className={`text-xs font-medium ${pillarDone ? "text-green-600" : "text-gray-400"}`}>
                      {pillarAnswered}/{pillarItems.length}
                    </span>
                    {isOpen ? <ChevronDown size={16} className="text-gray-400" /> : <ChevronRight size={16} className="text-gray-400" />}
                  </div>
                </button>

                {isOpen && (
                  <div className="border-t border-gray-100 divide-y divide-gray-50">
                    {pillarItems.map((item) => (
                      <div key={item.item_id} className="px-5 py-4">
                        <div className="flex items-start justify-between gap-2 mb-2">
                          <div className="flex-1">
                            <p className="text-sm font-medium text-gray-800">{item.item_name}</p>
                            <p className="text-xs text-gray-400 mt-0.5">{item.item_id} · 성숙도 {item.maturity}</p>
                          </div>
                          {answers[item.item_id] && (
                            <CheckCircle size={14} className="text-green-500 shrink-0 mt-1" />
                          )}
                        </div>

                        {item.criteria && (
                          <p className="text-xs text-gray-500 bg-gray-50 rounded px-3 py-2 mb-3">
                            {item.criteria}
                          </p>
                        )}

                        {/* 답변 선택 */}
                        <div className="flex flex-wrap gap-2 mb-2">
                          {RESULT_OPTIONS.map((opt) => (
                            <button
                              key={opt.value}
                              onClick={() =>
                                setAnswers((prev) => ({ ...prev, [item.item_id]: opt.value }))
                              }
                              className={`px-3 py-1.5 text-xs font-medium rounded-full border transition-all ${
                                answers[item.item_id] === opt.value
                                  ? opt.color + " ring-2 ring-offset-1 ring-current"
                                  : "border-gray-200 text-gray-500 hover:border-gray-300"
                              }`}
                            >
                              {opt.label}
                            </button>
                          ))}
                        </div>

                        {/* 증적 입력 */}
                        {answers[item.item_id] && answers[item.item_id] !== "평가불가" && (
                          <input
                            type="text"
                            placeholder="증적 자료 또는 근거 (선택)"
                            className="w-full text-xs px-3 py-2 border border-gray-200 rounded-lg text-gray-600 placeholder-gray-300 focus:outline-none focus:border-blue-300"
                            value={evidences[item.item_id] ?? ""}
                            onChange={(e) =>
                              setEvidences((prev) => ({ ...prev, [item.item_id]: e.target.value }))
                            }
                          />
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ))}

      {/* 제출 버튼 (웹 설문 모드에서만) */}
      {uploadMode === "form" && totalCount > 0 && (
        <div className="sticky bottom-6">
          <button
            onClick={handleSubmit}
            disabled={!allAnswered || submitting}
            className={`w-full py-4 rounded-xl font-semibold text-white text-sm transition-all shadow-lg ${
              allAnswered && !submitting
                ? "bg-blue-600 hover:bg-blue-700"
                : "bg-gray-300 cursor-not-allowed"
            }`}
          >
            {submitting ? (
              <span className="flex items-center justify-center gap-2">
                <Loader2 size={18} className="animate-spin" />
                분석 중...
              </span>
            ) : allAnswered ? (
              "진단 결과 확인하기"
            ) : (
              `${totalCount - answeredCount}개 항목 답변 필요`
            )}
          </button>
        </div>
      )}
    </div>
  );
}
