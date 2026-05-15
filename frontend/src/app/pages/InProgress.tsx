import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams, useLocation } from "react-router";
import { CheckCircle, Download, Loader2, Shield, Upload } from "lucide-react";
import { toast } from "sonner";
import {
  getManualItems, finalizeAssessment,
  getAssessmentStatus, uploadManualExcel,
} from "../../config/api";

export function InProgress() {
  const navigate = useNavigate();
  const { sessionId } = useParams();
  const location = useLocation();
  const { excludedTools = "", orgName = "", manager = "" } = (location.state ?? {}) as {
    excludedTools?: string;
    orgName?: string;
    manager?: string;
  };

  const [manualCount, setManualCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [finalizing, setFinalizing] = useState(false);
  const [autoRunning, setAutoRunning] = useState(false);
  const [collectionDone, setCollectionDone] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [collectedCount, setCollectedCount] = useState(0);
  const [autoTotal, setAutoTotal] = useState(0);
  const [selectedTools, setSelectedTools] = useState<string[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const sid = sessionId && sessionId !== "demo" ? sessionId : null;

  useEffect(() => {
    if (!sid) {
      setLoading(false);
      return;
    }

    const excludedCount = excludedTools.split(",").map((t) => t.trim()).filter(Boolean).length;
    const hasAutoTools = excludedCount < 4;
    setAutoRunning(hasAutoTools);

    getManualItems(sid, excludedTools)
      .then((res) => setManualCount(res.items.length))
      .catch(() => toast.error("항목 로드 실패. 새로고침 해주세요."))
      .finally(() => setLoading(false));
  }, [sid, excludedTools]);

  // 자동수집 폴링 (즉시 1회 + 5초 간격)
  useEffect(() => {
    if (!sid || !autoRunning || collectionDone) return;

    const check = () => {
      getAssessmentStatus(sid)
        .then((s) => {
          setCollectedCount(s.collected_count);
          setAutoTotal(s.auto_total);
          setSelectedTools(s.selected_tools ?? []);
          if (s.collection_done) {
            setCollectionDone(true);
            setAutoRunning(false);
            if (pollRef.current) clearInterval(pollRef.current);
            toast.success("자동 수집이 완료되었습니다.");
          }
        })
        .catch((err) => console.warn("[poll] status check failed:", err));
    };

    check();
    pollRef.current = setInterval(check, 5000);

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [sid, autoRunning, collectionDone]);

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

  const handleSkip = async () => {
    if (!sid) {
      navigate("/reporting/demo");
      return;
    }
    setFinalizing(true);
    try {
      await finalizeAssessment(sid);
      toast.success("진단이 완료되었습니다.");
      navigate(`/reporting/${sid}`);
    } catch {
      toast.error("결과 확정 중 오류가 발생했습니다.");
    } finally {
      setFinalizing(false);
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

      {/* 병행 진행 안내 */}
      {manualCount > 0 && (autoRunning || collectionDone) && (
        <div className="bg-indigo-50 border border-indigo-200 rounded-xl px-4 py-3 text-sm text-indigo-900">
          <strong>두 작업이 동시에 진행됩니다.</strong>
          <span className="ml-1 text-indigo-700">
            아래 <strong>① 자동 수집</strong>이 백그라운드에서 도는 동안
            <strong> ② Excel 수동 항목</strong>을 작성·업로드해주세요.
          </span>
        </div>
      )}

      {/* ① 자동수집 상태 */}
      <div className={`rounded-xl border p-5 transition-colors ${
        collectionDone   ? "bg-green-50 border-green-200" :
        autoRunning      ? "bg-blue-50 border-blue-200" :
                           "bg-white border-gray-200"
      }`}>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <span className="flex items-center justify-center w-6 h-6 rounded-full bg-white border-2 border-blue-500 text-blue-600 text-xs font-bold">①</span>
            <span className="text-sm font-semibold text-gray-800">자동 수집</span>
          </div>
          {collectionDone ? (
            <span className="flex items-center gap-1 text-sm font-semibold text-green-600">
              <CheckCircle size={14} /> 완료
            </span>
          ) : autoRunning ? (
            <span className="flex items-center gap-1 text-sm font-semibold text-blue-600">
              <Loader2 size={14} className="animate-spin" /> 진행 중
            </span>
          ) : (
            <span className="text-sm text-gray-400">사용 안 함</span>
          )}
        </div>

        {(autoRunning || collectionDone) && autoTotal > 0 && (
          <>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs text-gray-500">
                {selectedTools.length > 0 && (
                  <>도구: {selectedTools.map((t) => t.toUpperCase()).join(" · ")}</>
                )}
              </span>
              <span className="text-xs font-semibold text-gray-700">
                {collectedCount} / {autoTotal} 항목
              </span>
            </div>
            <div className="w-full bg-white/70 rounded-full h-2 overflow-hidden">
              <div
                className={`h-2 rounded-full transition-all duration-500 ${collectionDone ? "bg-green-500" : "bg-blue-500"}`}
                style={{ width: `${Math.min(100, Math.round((collectedCount / Math.max(autoTotal, 1)) * 100))}%` }}
              />
            </div>
          </>
        )}

        <p className="text-xs text-gray-500 mt-3">
          {autoRunning
            ? "선택하신 보안 도구가 백그라운드에서 진단 항목을 수집하고 있습니다. 이 작업은 Excel 업로드와 무관하게 동시에 진행됩니다."
            : collectionDone
            ? "선택한 도구의 모든 항목이 수집되었습니다. Excel 업로드 후 결과를 확인할 수 있습니다."
            : "자동 수집할 도구를 선택하지 않으셨습니다. Excel 업로드만으로 진단이 완료됩니다."}
        </p>
      </div>

      {/* 수동 진단 — Excel 업로드 전용 */}
      {manualCount === 0 ? (
        <div className="bg-white rounded-xl border border-gray-200 p-10 text-center">
          <CheckCircle size={40} className="mx-auto text-green-500 mb-3" />
          <p className="font-semibold text-gray-700">수동 진단 항목이 없습니다</p>
          <p className="text-sm text-gray-400 mt-1 mb-6">
            선택하신 도구로 모든 항목이 자동 수집됩니다.
          </p>
          <button
            onClick={handleSkip}
            disabled={finalizing}
            className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            {finalizing ? <Loader2 size={16} className="animate-spin inline mr-2" /> : null}
            결과 확인하기
          </button>
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <div className="px-5 py-3 border-b border-gray-100 bg-blue-50">
            <h2 className="text-sm font-semibold text-blue-800 flex items-center gap-2">
              <span className="flex items-center justify-center w-6 h-6 rounded-full bg-white border-2 border-blue-500 text-blue-600 text-xs font-bold">②</span>
              <Upload size={16} />
              수동 진단 — Excel 업로드
            </h2>
            <p className="text-xs text-blue-600 mt-1">
              자동 수집이 불가한 <strong>{manualCount}개</strong> 항목은 Excel로 일괄 제출합니다.
              {autoRunning && " (자동 수집과 동시 진행 가능)"}
            </p>
          </div>

          <div className="px-5 py-5 space-y-4">
            <ol className="text-sm text-gray-600 space-y-2 list-decimal list-inside">
              <li>아래 <strong>템플릿 다운로드</strong>로 빈 체크리스트(.xlsx)를 받습니다.</li>
              <li>각 항목의 <strong>★ 담당자 선택 (필수)</strong> 열에 드롭다운 값을 입력합니다.</li>
              <li>작성 완료 후 <strong>Excel 파일 선택</strong>으로 업로드하면 즉시 점수 계산이 시작됩니다.</li>
            </ol>

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
              지원 형식: .xlsx · 파일 내 시트는 <code className="text-gray-500">manual_diagnosis</code>, <code className="text-gray-500">judgment_mapping</code>이 필요합니다.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
