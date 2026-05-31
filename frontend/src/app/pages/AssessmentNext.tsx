import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router";
import { toast } from "sonner";
import {
  ArrowRight,
  CheckCircle,
  Download,
  FileSpreadsheet,
  Info,
  Loader2,
  SkipForward,
  Upload,
  XCircle,
} from "lucide-react";
import {
  ApiError,
  downloadSessionManualTemplate,
  finalizeAssessment,
  getAssessmentResult,
  uploadManualExcel,
} from "../../config/api";
import { maturityLabel } from "../lib/maturity";
import type { AssessmentResultResponse, ChecklistItemResult } from "../../types/api";

/**
 * 진단 자동 수집 완료 직후, Reporting 직행 대신 들어가는 중간 페이지.
 * - 자동 수집 결과의 잠정 요약 (충족·부분충족·미충족·평가불가 카운트 + 잠정 점수)
 * - 동적 수동 보완 양식 다운로드 (자동 충족 항목 제외 — backend 처리)
 * - 작성 파일 업로드 → finalize → Reporting 이동
 * - "건너뛰기" 옵션 (시연/사용자 편의)
 */
export function AssessmentNext() {
  const navigate = useNavigate();
  const { sessionId } = useParams();
  const sid = sessionId && sessionId !== "demo" ? sessionId : null;

  const [result, setResult] = useState<AssessmentResultResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [finalizing, setFinalizing] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // ── 결과 로드 ──────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!sid) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    getAssessmentResult(sid)
      .then((res) => {
        if (!cancelled) setResult(res);
      })
      .catch((err) => {
        console.warn("[assessment-next] getAssessmentResult:", err);
        toast.error("자동 진단 결과를 불러오지 못했습니다.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [sid]);

  // ── 결과 카운트 집계 ────────────────────────────────────────────────────────
  const summary = useMemo(() => {
    const items: ChecklistItemResult[] = result?.checklist_results ?? [];
    let pass = 0;
    let partial = 0;
    let fail = 0;
    let na = 0;
    items.forEach((it) => {
      switch (it.result) {
        case "충족":
          pass += 1;
          break;
        case "부분충족":
          partial += 1;
          break;
        case "미충족":
          fail += 1;
          break;
        case "평가불가":
          na += 1;
          break;
      }
    });
    return { pass, partial, fail, na, total: items.length };
  }, [result]);

  const provisionalScore = result?.overall_score ?? result?.total_score ?? 0;
  const provisionalLevel = result?.overall_level ?? result?.maturity_level ?? "기존";

  // ── 양식 다운로드 ──────────────────────────────────────────────────────────
  const handleDownload = async () => {
    if (!sid) {
      toast.error("세션 ID가 없어 양식을 다운로드할 수 없습니다.");
      return;
    }
    setDownloading(true);
    try {
      await downloadSessionManualTemplate(sid);
      toast.success("수동 보완 양식을 다운로드했습니다.");
    } catch (err) {
      console.warn("[assessment-next] template download:", err);
      toast.error("양식 다운로드에 실패했습니다.");
    } finally {
      setDownloading(false);
    }
  };

  // ── 업로드 + finalize → Reporting ──────────────────────────────────────────
  const handleUpload = async (file: File) => {
    if (!sid) {
      toast.error("세션 ID가 없어 업로드할 수 없습니다.");
      return;
    }
    if (!file.name.toLowerCase().endsWith(".xlsx")) {
      toast.error(".xlsx 파일만 업로드 가능합니다.");
      return;
    }
    setUploading(true);
    try {
      const res = await uploadManualExcel(sid, file);
      toast.success(`수동 보완 ${res.parsed_count}건이 반영되었습니다.`);
      // 업로드 직후 자동 finalize 후 Reporting 으로 이동
      try {
        await finalizeAssessment(sid);
      } catch (err) {
        // finalize 가 중복 호출이거나 이미 끝났을 수 있음 → warning 만
        console.warn("[assessment-next] finalize after upload:", err);
      }
      toast.success("최종 결과를 갱신했습니다.");
      navigate(`/reporting/${sid}`);
    } catch (err) {
      console.warn("[assessment-next] excel upload:", err);
      if (err instanceof ApiError) {
        toast.error(err.message || "업로드 중 오류가 발생했습니다.");
      } else {
        toast.error("업로드 중 오류가 발생했습니다.");
      }
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) void handleUpload(f);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files?.[0];
    if (f) void handleUpload(f);
  };

  // ── "건너뛰기" → finalize → Reporting ──────────────────────────────────────
  const handleSkip = async () => {
    if (!sid) {
      navigate("/reporting");
      return;
    }
    setFinalizing(true);
    try {
      await finalizeAssessment(sid);
      toast.success("자동 결과만으로 진단을 마무리합니다.");
      navigate(`/reporting/${sid}`);
    } catch (err) {
      console.warn("[assessment-next] skip finalize:", err);
      // finalize 실패해도 결과 페이지로 이동은 가능
      toast.error("결과 확정 중 오류 — 결과 페이지로 이동합니다.");
      navigate(`/reporting/${sid}`);
    } finally {
      setFinalizing(false);
    }
  };

  const handleViewFinal = () => {
    if (!sid) {
      navigate("/reporting");
      return;
    }
    navigate(`/reporting/${sid}`);
  };

  // ── 렌더 ──────────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="max-w-screen-lg mx-auto flex items-center justify-center py-32">
        <Loader2 size={28} className="animate-spin text-blue-600" />
        <span className="ml-3 text-sm text-gray-500">자동 결과 요약 불러오는 중…</span>
      </div>
    );
  }

  return (
    <div className="max-w-screen-lg mx-auto space-y-6">
      {/* 헤더 */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <CheckCircle size={22} className="text-green-600" />
          <h1>자동 진단 완료 — 다음 단계: 수동 보완</h1>
        </div>
        <p className="text-sm text-gray-500">
          자동 수집된 결과를 확인하고, 자동으로 검증할 수 없는 항목은 양식을 작성해 업로드하세요.
        </p>
      </div>

      {/* 자동 결과 잠정 요약 */}
      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-semibold text-gray-800">자동 결과 잠정 요약</h2>
          <span className="inline-flex items-center gap-1 text-xs text-gray-500">
            <Info size={13} /> 잠정값 — 수동 보완 반영 후 갱신됩니다.
          </span>
        </div>

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
          <SummaryStat label="충족" value={summary.pass} tone="success" />
          <SummaryStat label="부분충족" value={summary.partial} tone="warning" />
          <SummaryStat label="미충족" value={summary.fail} tone="error" />
          <SummaryStat label="평가불가" value={summary.na} tone="muted" />
        </div>

        <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3 pt-3 border-t border-gray-100">
          <div>
            <p className="text-xs text-gray-500">자동 항목 수집 완료</p>
            <p className="text-sm font-medium text-gray-800">
              {summary.total} / {summary.total} 항목
            </p>
          </div>
          <div className="text-right">
            <p className="text-xs text-gray-500">잠정 점수</p>
            <p className="text-2xl font-bold text-blue-700">
              {provisionalScore.toFixed(2)}{" "}
              <span className="text-sm font-medium text-gray-500">/ 4.0</span>
              <span className="ml-2 inline-block px-2 py-0.5 rounded-full text-xs font-medium bg-blue-50 text-blue-700 border border-blue-100">
                {maturityLabel(String(provisionalLevel))} 단계
              </span>
            </p>
          </div>
        </div>
      </div>

      {/* 수동 보완 양식 */}
      <div className="bg-white rounded-xl border border-blue-200 overflow-hidden">
        <div className="px-5 py-3 border-b border-blue-100 bg-blue-50">
          <h2 className="text-base font-semibold text-blue-800 flex items-center gap-2">
            <FileSpreadsheet size={18} />
            수동 보완 양식
          </h2>
          <p className="text-xs text-blue-700 mt-1">
            자동 진단에서 <strong>미충족·평가불가</strong>된 항목과 자동→수동 폴백된 항목만
            양식에 포함됩니다. <strong>자동 충족 항목은 자동으로 제외</strong>됩니다.
          </p>
        </div>

        <div className="px-5 py-5 space-y-5">
          {/* 다운로드 */}
          <div>
            <p className="text-sm text-gray-700 mb-2">
              <span className="font-semibold">1단계.</span> 이 세션 전용 보완 양식(.xlsx)을 다운로드하세요.
            </p>
            <button
              type="button"
              onClick={handleDownload}
              disabled={downloading || !sid}
              className={`inline-flex items-center gap-2 px-4 py-2.5 text-sm rounded-lg ${
                downloading || !sid
                  ? "bg-gray-100 text-gray-400 cursor-not-allowed"
                  : "bg-white border border-gray-300 text-gray-700 hover:bg-gray-50"
              }`}
            >
              {downloading ? (
                <>
                  <Loader2 size={15} className="animate-spin" /> 다운로드 중…
                </>
              ) : (
                <>
                  <Download size={15} /> 수동 보완 양식 다운로드 (.xlsx)
                </>
              )}
            </button>
          </div>

          {/* 업로드 */}
          <div>
            <p className="text-sm text-gray-700 mb-2">
              <span className="font-semibold">2단계.</span> 작성을 마친 파일을 업로드하면 최종 결과가
              자동으로 갱신됩니다.
            </p>
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              className={`relative border-2 border-dashed rounded-lg p-6 text-center transition-colors ${
                dragOver
                  ? "border-blue-500 bg-blue-50"
                  : uploading
                  ? "border-gray-200 bg-gray-50"
                  : "border-gray-300 bg-gray-50 hover:border-blue-400 hover:bg-blue-50/40"
              }`}
            >
              {uploading ? (
                <div className="flex flex-col items-center gap-2 text-sm text-gray-600">
                  <Loader2 size={22} className="animate-spin text-blue-600" />
                  업로드 중… 잠시만 기다려 주세요.
                </div>
              ) : (
                <>
                  <Upload size={26} className="mx-auto text-gray-400 mb-2" />
                  <p className="text-sm text-gray-700">
                    파일을 이 영역에 끌어다 놓거나{" "}
                    <label className="text-blue-600 hover:underline cursor-pointer font-medium">
                      클릭해서 선택
                      <input
                        ref={fileInputRef}
                        type="file"
                        accept=".xlsx"
                        className="hidden"
                        onChange={handleFileInput}
                        disabled={uploading || !sid}
                      />
                    </label>
                  </p>
                  <p className="text-xs text-gray-500 mt-1">.xlsx 파일만 지원</p>
                </>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* 액션 — 최종 결과 보기 / 건너뛰기 */}
      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div className="text-sm text-gray-600">
            <p className="font-medium text-gray-800 mb-0.5">바로 결과를 확인하려면?</p>
            <p className="text-xs text-gray-500">
              수동 보완 없이도 자동 진단 결과만으로 Reporting 페이지를 열 수 있습니다.
              (Reporting에서도 양식 업로드는 계속 가능합니다.)
            </p>
          </div>
          <div className="flex flex-wrap gap-2 justify-end">
            <button
              type="button"
              onClick={handleSkip}
              disabled={finalizing}
              className={`inline-flex items-center gap-1.5 px-4 py-2 text-sm rounded-lg ${
                finalizing
                  ? "bg-gray-100 text-gray-400 cursor-not-allowed"
                  : "bg-white border border-gray-300 text-gray-700 hover:bg-gray-50"
              }`}
            >
              {finalizing ? (
                <>
                  <Loader2 size={14} className="animate-spin" /> 확정 중…
                </>
              ) : (
                <>
                  <SkipForward size={14} /> 건너뛰기 — 자동 결과만으로 완료
                </>
              )}
            </button>
            <button
              type="button"
              onClick={handleViewFinal}
              disabled={!sid}
              className={`inline-flex items-center gap-2 px-5 py-2.5 text-sm font-medium rounded-lg ${
                !sid
                  ? "bg-gray-200 text-gray-400 cursor-not-allowed"
                  : "bg-blue-600 text-white hover:bg-blue-700"
              }`}
            >
              최종 결과 보기
              <ArrowRight size={15} />
            </button>
          </div>
        </div>

        {!sid && (
          <div className="mt-3 flex items-center gap-2 text-xs text-red-600">
            <XCircle size={13} /> 세션 ID를 찾을 수 없어 일부 기능이 비활성화됩니다.
          </div>
        )}
      </div>
    </div>
  );
}

// ── 작은 카운트 카드 ────────────────────────────────────────────────────────
function SummaryStat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: "success" | "warning" | "error" | "muted";
}) {
  const toneClass: Record<typeof tone, string> = {
    success: "bg-green-50 border-green-100 text-green-700",
    warning: "bg-amber-50 border-amber-100 text-amber-700",
    error: "bg-red-50 border-red-100 text-red-700",
    muted: "bg-gray-50 border-gray-200 text-gray-600",
  };
  return (
    <div className={`rounded-lg border px-3 py-2.5 ${toneClass[tone]}`}>
      <p className="text-xs font-medium opacity-80">{label}</p>
      <p className="text-2xl font-bold mt-0.5">{value}</p>
    </div>
  );
}
