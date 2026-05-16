import { useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate, useParams } from "react-router";
import {
  Area, AreaChart, CartesianGrid,
  PolarAngleAxis, PolarGrid, PolarRadiusAxis,
  Radar, RadarChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import {
  AlertTriangle, CheckCircle, Clock, Database, Download,
  Loader2, Paperclip, Server, Shield, Upload,
} from "lucide-react";
import { toast } from "sonner";
import { PILLARS } from "../data/constants";
import {
  getAssessmentStatus, finalizeAssessment, getManualItems, uploadManualExcel, uploadEvidence,
  evidenceDownloadUrl, ApiError,
  type AssessmentStatusResponse,
} from "../../config/api";
import { pillarMatchesKey } from "../lib/pillar";
import type { ManualItemDetail } from "../../types/api";

const TOOL_NAMES = ["Keycloak", "Wazuh", "Nmap", "Trivy"] as const;
const TOOL_KEY_MAP: Record<string, typeof TOOL_NAMES[number]> = {
  keycloak: "Keycloak", wazuh: "Wazuh", nmap: "Nmap", trivy: "Trivy",
};
const PILLAR_COLORS = ["#2563eb", "#059669", "#f59e0b", "#0891b2", "#7c3aed", "#dc2626"];
const TOOL_COLORS: Record<string, string> = {
  Keycloak: PILLAR_COLORS[1],
  Wazuh:    PILLAR_COLORS[0],
  Nmap:     PILLAR_COLORS[3],
  Trivy:    PILLAR_COLORS[2],
};

const PIPELINE_STEPS = [
  { label: "자산 발견",   sublabel: "Asset Discovery" },
  { label: "신원 확인",   sublabel: "Identity Check" },
  { label: "정책 분석",   sublabel: "Policy Analysis" },
  { label: "보고서 생성", sublabel: "Report Generation" },
];

const INITIAL_LOGS = [
  { time: "00:00", type: "info" as const,    message: "진단 세션 초기화 완료" },
  { time: "00:01", type: "success" as const, message: "백엔드 collector 연결 확인" },
];

const DEMO_LOG_EVENTS = [
  { type: "info",    message: "Keycloak /admin/realms 사용자 목록 조회" },
  { type: "success", message: "Keycloak 사용자·역할 매핑 수집 완료" },
  { type: "info",    message: "Wazuh /security/events 조회" },
  { type: "warning", message: "Wazuh 인증 실패 이벤트 일부 탐지" },
  { type: "info",    message: "Nmap 네트워크 세그먼테이션 스캔" },
  { type: "success", message: "Nmap 포트 노출 후보 분류 완료" },
  { type: "info",    message: "Trivy 컨테이너 이미지 취약점 DB 동기화" },
  { type: "warning", message: "Trivy HIGH 등급 취약점 탐지" },
  { type: "info",    message: "Wazuh SIEM 룰 활성 상태 확인" },
  { type: "success", message: "Keycloak MFA 정책 검증 완료" },
] as const;

type LogEntry = { time: string; type: "info" | "success" | "warning"; message: string };

function formatTime() {
  return new Date().toLocaleTimeString("ko-KR", {
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  });
}

function nextLogVolume(previous: number | undefined, progress: number) {
  const baseline = 24 + Math.sin(progress / 12) * 8;
  const target = baseline + (progress < 35 ? 18 : progress < 75 ? 28 : 14);
  const current = previous ?? target;
  const drift = (target - current) * 0.28;
  const jitter = (Math.random() - 0.5) * 8;
  return Math.max(8, Math.min(92, Math.round(current + drift + jitter)));
}

function getLogTool(message: string) {
  return TOOL_NAMES.find((tool) => message.includes(tool));
}

function renderLogMessage(message: string) {
  const tool = getLogTool(message);
  if (!tool) return message;
  const [before, ...afterParts] = message.split(tool);
  return (
    <>
      {before}
      <span className="font-semibold" style={{ color: TOOL_COLORS[tool] }}>{tool}</span>
      {afterParts.join(tool)}
    </>
  );
}

function CircularProgress({
  value, label, color, active, completedCount, totalCount,
}: {
  value: number; label: string; color: string; active: boolean;
  completedCount: number; totalCount: number;
}) {
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.min(value, 100) / 100) * circumference;
  const completed = value >= 100;

  return (
    <div
      className={`rounded-2xl border p-4 transition-all ${
        completed   ? "border-gray-200 bg-gray-100 text-gray-500"
        : active    ? "border-blue-300 bg-blue-50 shadow-sm"
                    : "border-gray-200 bg-white"
      }`}
    >
      <div className="mx-auto mb-3 h-24 w-24 relative">
        <svg viewBox="0 0 96 96" className="h-24 w-24 -rotate-90">
          <circle cx="48" cy="48" r={radius} fill="none" stroke="#e5e7eb" strokeWidth="9" />
          <circle
            cx="48" cy="48" r={radius} fill="none" stroke={color}
            strokeLinecap="round" strokeWidth="9"
            strokeDasharray={circumference} strokeDashoffset={offset}
            className="transition-all duration-500"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-xl font-bold text-gray-900">{Math.round(value)}%</span>
          <span className="text-[11px] text-gray-400">{active ? "진행 중" : completed ? "완료" : "대기"}</span>
        </div>
      </div>
      <p className="text-center text-sm font-semibold text-gray-700">{label}</p>
      <div className="mt-3 rounded-xl bg-white/70 p-3 text-left">
        <div className="mb-2 flex items-center justify-between text-xs">
          <span className="text-gray-500">체크리스트</span>
          <span className="font-semibold text-gray-800">
            {completedCount} / {totalCount}개
          </span>
        </div>
        <div className="h-1.5 rounded-full bg-gray-200">
          <div
            className="h-1.5 rounded-full transition-all duration-500"
            style={{ width: `${totalCount ? (completedCount / totalCount) * 100 : 0}%`, backgroundColor: color }}
          />
        </div>
      </div>
    </div>
  );
}

export function InProgress() {
  const navigate = useNavigate();
  const { sessionId } = useParams();
  const location = useLocation();
  const { excludedTools = "", orgName = "", manager = "" } = (location.state ?? {}) as {
    excludedTools?: string; orgName?: string; manager?: string;
  };

  const sid = sessionId && sessionId !== "demo" ? sessionId : null;

  // 백엔드 상태
  const [status, setStatus] = useState<AssessmentStatusResponse | null>(null);
  const [manualCount, setManualCount] = useState(0);
  const [manualItems, setManualItems] = useState<ManualItemDetail[]>([]);

  // 증적 업로드 상태 (P1-7)
  const [evidenceShow, setEvidenceShow] = useState(false);
  const [evidenceUploading, setEvidenceUploading] = useState<Record<number, boolean>>({});
  const [uploadedEvidence, setUploadedEvidence] = useState<Record<number, { id: number; name: string }>>({});

  // UI
  const [logs, setLogs] = useState<LogEntry[]>(INITIAL_LOGS);
  const [areaData, setAreaData] = useState<{ time: string; volume: number }[]>([]);
  const [metrics, setMetrics] = useState({
    totalItems: 0, detectedEvents: 0, policyViolations: 0, analyzedAssets: 0,
  });
  const [uploading, setUploading] = useState(false);
  const [finalizing, setFinalizing] = useState(false);
  const [finalized, setFinalized] = useState(false);
  const logContainerRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── 진행률 계산 ─────────────────────────────────────────────────────────────
  // backend 실제 진행률
  const realProgress = useMemo(() => {
    if (!status || status.auto_total === 0) return status?.collection_done ? 100 : 0;
    return Math.min(100, Math.round((status.collected_count / status.auto_total) * 100));
  }, [status]);

  // 시연용 부드러운 진행 — 페이지 진입 후 최소 SMOOTH_TOTAL_MS에 걸쳐 0→99% 램프.
  // backend가 더 느리면 backend를 따라가고, 더 빠르면 램프가 캡으로 작용.
  const SMOOTH_TOTAL_MS = 90_000;
  const [mountedAt] = useState(() => Date.now());
  const [now, setNow] = useState(() => Date.now());
  const collectionDone = status?.collection_done ?? false;

  // 100% 도달 후에는 setInterval을 정지해 자원 낭비를 막는다.
  useEffect(() => {
    if (collectionDone && now - mountedAt >= SMOOTH_TOTAL_MS) return;
    const t = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(t);
  }, [collectionDone, now, mountedAt]);
  const elapsedMs = now - mountedAt;

  // backend 진행 속도(items/sec)를 측정해 실제 예상 소요시간을 동적으로 추정한다.
  // 진행 시작 후 collected_count가 양수가 되면 평균 속도를 계산할 수 있다.
  const collectedCount = status?.collected_count ?? 0;
  const autoTotal = status?.auto_total ?? 0;
  const estimatedTotalMs = (() => {
    if (autoTotal <= 0) return SMOOTH_TOTAL_MS;
    if (collectedCount <= 0 || elapsedMs < 1500) return SMOOTH_TOTAL_MS;
    const avgMsPerItem = elapsedMs / collectedCount;
    const projected = avgMsPerItem * autoTotal;
    // backend가 빠르면 90s 유지(시연용), 더 느리면 그 값으로 ramp 연장.
    return Math.max(SMOOTH_TOTAL_MS, Math.min(projected, 30 * 60 * 1000));
  })();

  const smoothCap = Math.min(99, Math.floor((elapsedMs / estimatedTotalMs) * 100));
  // 실제로 backend가 완료(realProgress===100 && collection_done)이고 시연시간도 다 지나야 100
  const progress = collectionDone && elapsedMs >= SMOOTH_TOTAL_MS
    ? 100
    : Math.min(realProgress, smoothCap);

  // 예상 남은 시간 (mm:ss) — 동적 추정 totalMs 기준
  const remainingMs = progress >= 100
    ? 0
    : Math.max(0, estimatedTotalMs - elapsedMs);
  const remainingLabel = (() => {
    if (progress >= 100) return "완료";
    const totalSec = Math.ceil(remainingMs / 1000);
    // 추정값이 거의 0인데 100%에 도달하지 못한 경우 — 후처리/마감 단계
    if (totalSec <= 1) return "마무리 중...";
    const m = Math.floor(totalSec / 60);
    const s = totalSec % 60;
    return m > 0 ? `약 ${m}분 ${s}초 남음` : `약 ${s}초 남음`;
  })();

  const pillarProgressMap = useMemo(() => {
    const map = new Map<string, { collected: number; expected: number }>();
    status?.pillar_progress.forEach((p) => map.set(p.pillar, p));
    return map;
  }, [status]);

  const pillars = useMemo(() => (
    PILLARS.map((p) => {
      const match = [...pillarProgressMap.entries()].find(([name]) => pillarMatchesKey(name, p.key));
      if (!match) return { ...p, progress: 0, collected: 0, expected: 0 };
      const { collected, expected } = match[1];
      const pct = expected > 0 ? Math.round((collected / expected) * 100) : 0;
      return { ...p, progress: pct, collected, expected };
    })
  ), [pillarProgressMap]);

  const toolProgress = useMemo(() => (
    TOOL_NAMES.map((toolName) => {
      const lowerKey = toolName.toLowerCase();
      const found = status?.tool_progress.find((t) => t.tool === lowerKey);
      return {
        name: toolName,
        collected: found?.collected ?? 0,
        total:     found?.expected ?? 0,
        fill:      TOOL_COLORS[toolName],
        selected:  status?.selected_tools.includes(lowerKey) ?? false,
      };
    })
  ), [status]);

  const activePillarIndex = pillars.findIndex((p) => p.progress > 0 && p.progress < 100);
  const safeActivePillarIndex = activePillarIndex >= 0
    ? activePillarIndex
    : pillars.findIndex((p) => p.progress < 100);

  // ── 데이터 로드 ──────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!sid) return;
    getManualItems(sid, excludedTools)
      .then((res) => {
        setManualCount(res.items.length);
        setManualItems(res.items);
      })
      .catch((err) => console.warn("[in-progress] manual items:", err));
  }, [sid, excludedTools]);

  // 항목별 증적 파일 업로드 핸들러 (P1-7)
  const handleEvidenceUpload = async (
    checkId: number,
    file: File,
  ) => {
    if (!sid) return;
    // 클라이언트 검증: 10MB 제한
    const MAX_BYTES = 10 * 1024 * 1024;
    if (file.size > MAX_BYTES) {
      toast.error("증적 파일은 10MB 이하만 업로드 가능합니다.");
      return;
    }
    // 클라이언트 검증: 허용 타입 (pdf/image)
    const isPdf = file.name.toLowerCase().endsWith(".pdf") || file.type === "application/pdf";
    const isImage = file.type.startsWith("image/");
    if (!isPdf && !isImage) {
      toast.error("PDF 또는 이미지 파일만 업로드 가능합니다.");
      return;
    }
    setEvidenceUploading((prev) => ({ ...prev, [checkId]: true }));
    try {
      const res = await uploadEvidence(sid, checkId, file);
      setUploadedEvidence((prev) => ({
        ...prev,
        [checkId]: { id: res.evidence_id, name: res.filename },
      }));
      toast.success(`증적이 업로드되었습니다: ${res.filename}`);
    } catch (err) {
      console.warn("[in-progress] evidence upload:", err);
      if (err instanceof ApiError) {
        if (err.status === 413) toast.error("파일 크기가 너무 큽니다.");
        else if (err.status === 415) toast.error("지원하지 않는 파일 형식입니다.");
        else toast.error("증적 업로드에 실패했습니다.");
      } else {
        toast.error("증적 업로드에 실패했습니다.");
      }
    } finally {
      setEvidenceUploading((prev) => ({ ...prev, [checkId]: false }));
    }
  };

  // 백엔드 폴링 (즉시 + 3초 간격)
  useEffect(() => {
    if (!sid) return;
    const check = () => {
      getAssessmentStatus(sid)
        .then((s) => {
          setStatus(s);
          if (s.collection_done && pollRef.current) {
            clearInterval(pollRef.current);
            pollRef.current = null;
          }
        })
        .catch((err) => console.warn("[in-progress] status:", err));
    };
    check();
    pollRef.current = setInterval(check, 3000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [sid]);

  // ── 시각 효과: 메트릭/AreaChart/로그 시뮬레이션 ─────────────────────────────
  useEffect(() => {
    if (collectionDone) return;
    const timer = window.setInterval(() => {
      setMetrics((prev) => ({
        totalItems:       prev.totalItems       + Math.floor(Math.random() * 18) + 5,
        detectedEvents:   prev.detectedEvents   + Math.floor(Math.random() * 4),
        policyViolations: prev.policyViolations + (Math.random() > 0.72 ? 1 : 0),
        analyzedAssets:   prev.analyzedAssets   + Math.floor(Math.random() * 6) + 2,
      }));
      setAreaData((prev) => {
        const prevVol = prev.at(-1)?.volume;
        return [...prev.slice(-19), { time: formatTime(), volume: nextLogVolume(prevVol, progress) }];
      });
    }, 800);
    return () => window.clearInterval(timer);
  }, [collectionDone, progress]);

  useEffect(() => {
    if (collectionDone) return;
    let eventIndex = 0;
    const timer = window.setInterval(() => {
      const event = DEMO_LOG_EVENTS[eventIndex % DEMO_LOG_EVENTS.length];
      eventIndex += 1;
      setLogs((prev) => [
        ...prev.slice(-140),
        { time: formatTime(), type: event.type as LogEntry["type"], message: event.message },
      ]);
    }, 500);
    return () => window.clearInterval(timer);
  }, [collectionDone]);

  useEffect(() => {
    const el = logContainerRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [logs]);

  // 완료 시 자동 finalize → /reporting (수동 항목 없을 때만)
  // 시연용 부드러운 진행을 위해 backend 완료 + smooth 진행률 100% 모두 만족해야 finalize.
  useEffect(() => {
    if (!sid || !collectionDone || progress < 100 || finalized || finalizing || manualCount > 0) return;
    setFinalizing(true);
    finalizeAssessment(sid)
      .then(() => {
        setFinalized(true);
        toast.success("자동 진단이 완료되었습니다.");
        setTimeout(() => navigate(`/reporting/${sid}`), 1500);
      })
      .catch((err) => {
        console.warn("[in-progress] finalize:", err);
        toast.error("결과 확정 중 오류가 발생했습니다.");
      })
      .finally(() => setFinalizing(false));
  }, [sid, collectionDone, progress, manualCount, finalized, finalizing, navigate]);

  // ── Excel 업로드 핸들러 ──────────────────────────────────────────────────────
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

  const radarData = PILLARS.map((p, i) => ({
    pillar: p.shortLabel,
    score: Number(((pillars[i]?.progress / 100) * 4).toFixed(1)),
  }));

  const activeStepIndex = Math.min(
    Math.floor((progress / 100) * PIPELINE_STEPS.length),
    PIPELINE_STEPS.length - 1
  );
  const totalQuestionCount = pillars.reduce((sum, p) => sum + p.expected, 0);
  const completedQuestionCount = pillars.reduce((sum, p) => sum + p.collected, 0);

  return (
    <div className="max-w-7xl mx-auto space-y-5">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Shield size={22} className="text-blue-600" />
            <h1>진단 진행 중</h1>
          </div>
          <p className="text-sm text-gray-500">
            {orgName || "진단 대상"}{manager ? ` · ${manager} 담당자` : ""}
          </p>
        </div>
        <div className={`flex items-center gap-2 ${
          progress >= 100 ? "text-green-600" : "text-blue-600"
        }`}>
          {progress >= 100 ? <CheckCircle size={18} /> : <Loader2 size={18} className="animate-spin" />}
          <span className="text-sm font-medium">{progress}% 완료</span>
        </div>
      </div>

      {/* 전체 진행률 */}
      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-gray-700">전체 진행률</span>
          <span className="text-sm font-semibold text-blue-600">
            {status ? `${status.collected_count} / ${status.auto_total}` : "-"} 항목 · {progress}%
          </span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-3">
          <div
            className={`h-3 rounded-full transition-all duration-500 ${progress >= 100 ? "bg-green-500" : "bg-blue-600"}`}
            style={{ width: `${progress}%` }}
          />
        </div>
        <div className="mt-3 flex items-center justify-between text-sm">
          <span className="text-gray-500">
            선택된 도구: {status?.selected_tools.length
              ? status.selected_tools.map((t) => t.toUpperCase()).join(" · ")
              : "없음"}
          </span>
          <span className={progress >= 100 ? "font-semibold text-green-600" : "font-semibold text-blue-700"}>
            {progress >= 100 ? "수집 완료" : remainingLabel}
          </span>
        </div>
      </div>

      {/* 메트릭 카드 */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "총 수집 항목", value: status?.collected_count ?? metrics.totalItems,       icon: Database,       color: "text-blue-600",   bg: "bg-blue-50",   border: "border-blue-100" },
          { label: "탐지 이벤트",   value: metrics.detectedEvents,                              icon: AlertTriangle, color: "text-yellow-600", bg: "bg-yellow-50", border: "border-yellow-100" },
          { label: "정책 위반",     value: metrics.policyViolations,                            icon: Shield,         color: "text-red-600",    bg: "bg-red-50",    border: "border-red-100" },
          { label: "분석 자산",     value: metrics.analyzedAssets,                              icon: Server,         color: "text-green-600",  bg: "bg-green-50",  border: "border-green-100" },
        ].map(({ label, value, icon: Icon, color, bg, border }) => (
          <div key={label} className={`${bg} border ${border} rounded-xl p-4`}>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-gray-500">{label}</span>
              <Icon size={16} className={color} />
            </div>
            <p className={`text-2xl font-bold ${color}`}>{value.toLocaleString()}</p>
          </div>
        ))}
      </div>

      {/* 필러별 진행률 */}
      <div className="bg-white rounded-xl border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h2>필러별 진행률</h2>
            <p className="mt-1 text-sm text-gray-500">각 필러의 자동 수집 진행 상황과 항목 개수입니다.</p>
          </div>
          <span className="rounded-full bg-blue-50 px-3 py-1 text-sm font-semibold text-blue-700">
            {completedQuestionCount} / {totalQuestionCount}개 항목
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {pillars.map((pillar, index) => (
            <CircularProgress
              key={pillar.key}
              value={pillar.progress}
              label={pillar.label}
              color={PILLAR_COLORS[index]}
              active={safeActivePillarIndex === index && !collectionDone}
              completedCount={pillar.collected}
              totalCount={pillar.expected}
            />
          ))}
        </div>
      </div>

      {/* 파이프라인 + 로그 볼륨 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="mb-4">진단 파이프라인</h2>
          <div className="space-y-0">
            {PIPELINE_STEPS.map((step, idx) => {
              const done = idx < activeStepIndex || progress >= 100;
              const active = idx === activeStepIndex && progress < 100;
              return (
                <div key={step.label} className="flex items-start gap-3">
                  <div className="flex flex-col items-center">
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center border-2 shrink-0 ${
                      done   ? "border-green-500 bg-green-50"
                      : active ? "border-blue-500 bg-blue-50 ring-2 ring-blue-400/30"
                              : "border-gray-300 bg-gray-50"
                    }`}>
                      {done   ? <CheckCircle size={14} className="text-green-500" />
                       : active ? <Loader2 size={14} className="text-blue-500 animate-spin" />
                               : <Clock size={14} className="text-gray-400" />}
                    </div>
                    {idx < PIPELINE_STEPS.length - 1 && (
                      <div className={`w-0.5 h-8 mt-0.5 ${done ? "bg-green-300" : "bg-gray-200"}`} />
                    )}
                  </div>
                  <div className="pb-6">
                    <p className={`text-sm font-medium ${
                      done ? "text-green-600" : active ? "text-blue-600" : "text-gray-400"
                    }`}>{step.label}</p>
                    <p className="text-xs text-gray-400 mt-0.5">{step.sublabel}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="mb-1">실시간 로그 볼륨</h2>
          <p className="text-xs text-gray-400 mb-3">수집 이벤트 변화</p>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={areaData}>
              <defs>
                <linearGradient id="areaGradLight" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#3b82f6" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
              <XAxis dataKey="time" stroke="#d1d5db" tick={{ fontSize: 9, fill: "#9ca3af" }} interval="preserveStartEnd" />
              <YAxis stroke="#d1d5db" tick={{ fontSize: 10, fill: "#9ca3af" }} domain={[0, 100]} />
              <Tooltip contentStyle={{ backgroundColor: "#fff", border: "1px solid #e5e7eb", borderRadius: 8, fontSize: 12 }} />
              <Area type="monotone" dataKey="volume" stroke="#3b82f6" fill="url(#areaGradLight)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 레이더 + 도구 현황 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="mb-1">필러별 현재 성숙도</h2>
          <p className="text-xs text-gray-400 mb-3">진행률 기반 실시간 추정치</p>
          <ResponsiveContainer width="100%" height={240}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#e5e7eb" />
              <PolarAngleAxis dataKey="pillar" stroke="#9ca3af" tick={{ fontSize: 11, fill: "#6b7280" }} />
              <PolarRadiusAxis angle={90} domain={[0, 4]} tick={false} axisLine={false} />
              <Radar name="현재 점수" dataKey="score" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.2} strokeWidth={2} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="mb-4">플레이북 도구 현황</h2>
          <div className="grid grid-cols-2 gap-3">
            {toolProgress.map((tool, index) => {
              const ratio = tool.total > 0 ? Math.round((tool.collected / tool.total) * 100) : 0;
              const color = PILLAR_COLORS[index];
              return (
                <div key={tool.name} className={`p-3 rounded-lg border ${tool.selected ? "bg-gray-50 border-gray-100" : "bg-gray-50/50 border-gray-100 opacity-50"}`}>
                  <div className="flex items-center justify-between mb-2">
                    <p className="font-medium text-sm">{tool.name}</p>
                    <span className="text-xs font-semibold" style={{ color }}>
                      {tool.selected ? `${ratio}%` : "미선택"}
                    </span>
                  </div>
                  <p className="text-xs text-gray-500 mb-2">
                    {tool.selected ? `${tool.collected} / ${tool.total} 항목` : "사용 안 함"}
                  </p>
                  <div className="w-full bg-gray-100 rounded-full h-1.5">
                    <div
                      className="h-1.5 rounded-full transition-all duration-500"
                      style={{ width: `${ratio}%`, backgroundColor: color }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* 실시간 진단 로그 (시뮬레이션) */}
      <div className="bg-white rounded-xl border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2>실시간 진단 로그</h2>
            <p className="text-sm text-gray-500 mt-1">tail -f 로그처럼 진단 이벤트를 시간순으로 스트리밍합니다.</p>
          </div>
          <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold ${
            collectionDone ? "bg-green-100 text-green-700" : "bg-blue-100 text-blue-700"
          }`}>
            <span className={`h-2 w-2 rounded-full ${collectionDone ? "bg-green-500" : "bg-blue-500 animate-pulse"}`} />
            {collectionDone ? "수집 완료" : "수집 중"}
          </span>
        </div>
        <div className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-inner">
          <div className="flex items-center gap-2 border-b border-gray-100 bg-gray-50 px-4 py-2">
            <span className="h-2.5 w-2.5 rounded-full bg-red-400" />
            <span className="h-2.5 w-2.5 rounded-full bg-amber-400" />
            <span className="h-2.5 w-2.5 rounded-full bg-green-400" />
            <span className="ml-2 font-mono text-xs text-gray-500">
              zt-assessment@readyz-t:~/diagnosis/logs$ tail -f assessment.out
            </span>
          </div>

          <div ref={logContainerRef} className="max-h-72 overflow-y-auto bg-white px-4 py-3 font-mono text-[13px] leading-6 text-gray-900">
            <div className="text-gray-500">********** Readyz-T diagnosis stream **********</div>
            <div className="text-gray-500">
              session: {orgName || "진단 대상"} / progress: {progress}%
            </div>
            {logs.map((log, i) => {
              const tool = getLogTool(log.message);
              const prefix = log.type === "success" ? "====" : log.type === "warning" ? ">>>>" : "----";
              const typeText = log.type === "success" ? "SUCCESS" : log.type === "warning" ? "WARN" : "INFO";

              return (
                <div key={`${log.time}-${i}`} className="flex min-w-max gap-2 whitespace-pre">
                  <span className="text-gray-400">{prefix}</span>
                  <span className="text-sky-600">[{log.time}]</span>
                  <span className={
                    log.type === "warning" ? "text-amber-600" :
                    log.type === "success" ? "text-green-600" : "text-gray-500"
                  }>
                    {typeText}
                  </span>
                  {tool && (
                    <span className="rounded bg-gray-100 px-1.5 font-semibold" style={{ color: TOOL_COLORS[tool] }}>
                      {tool}
                    </span>
                  )}
                  <span>{renderLogMessage(log.message)}</span>
                </div>
              );
            })}
            <div className="text-gray-400">********** waiting for next event **********</div>
          </div>
        </div>
      </div>

      {/* Excel 업로드 (수동 항목 있을 때만) */}
      {manualCount > 0 && (
        <div className="bg-white rounded-xl border border-blue-200 overflow-hidden">
          <div className="px-5 py-3 border-b border-blue-100 bg-blue-50">
            <h2 className="text-sm font-semibold text-blue-800 flex items-center gap-2">
              <Upload size={16} />
              수동 진단 항목 Excel 업로드
            </h2>
            <p className="text-xs text-blue-600 mt-1">
              자동 수집이 불가한 <strong>{manualCount}개</strong> 항목은 Excel 일괄 업로드로 제출합니다.
              {!collectionDone && " 자동 수집과 동시에 진행 가능합니다."}
            </p>
          </div>

          <div className="px-5 py-5 space-y-4">
            <ol className="text-sm text-gray-600 space-y-2 list-decimal list-inside">
              <li><strong>템플릿 다운로드</strong>로 빈 체크리스트(.xlsx)를 받습니다.</li>
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
              <label className={`flex items-center gap-2 px-4 py-2 text-sm rounded-lg cursor-pointer transition-colors ${
                uploading ? "bg-gray-100 text-gray-400 cursor-not-allowed" : "bg-blue-600 text-white hover:bg-blue-700"
              }`}>
                {uploading ? (
                  <><Loader2 size={15} className="animate-spin" /> 업로드 중...</>
                ) : (
                  <><Upload size={15} /> Excel 파일 선택</>
                )}
                <input
                  ref={fileInputRef}
                  type="file" accept=".xlsx" className="hidden"
                  disabled={uploading} onChange={handleExcelUpload}
                />
              </label>
            </div>
          </div>
        </div>
      )}

      {/* 항목별 증적 파일 업로드 (P1-7) */}
      {manualCount > 0 && (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <button
            type="button"
            onClick={() => setEvidenceShow((v) => !v)}
            className="w-full flex items-center justify-between px-5 py-3 border-b border-gray-100 bg-gray-50 hover:bg-gray-100 transition-colors"
          >
            <span className="text-sm font-semibold text-gray-800 flex items-center gap-2">
              <Paperclip size={16} className="text-blue-600" />
              수동 항목별 증적 파일 업로드 (선택)
              <span className="ml-1 text-xs text-gray-500 font-normal">
                — Excel 외에 항목별 PDF/이미지 증적을 첨부할 수 있습니다.
              </span>
            </span>
            <span className="text-xs text-gray-500">{evidenceShow ? "접기" : "펼치기"}</span>
          </button>
          {evidenceShow && (
            <div className="p-5 space-y-2 max-h-[480px] overflow-y-auto">
              {manualItems.map((item) => {
                const uploading = !!evidenceUploading[item.check_id];
                const uploaded = uploadedEvidence[item.check_id];
                return (
                  <div
                    key={item.check_id}
                    className="flex items-center gap-3 px-3 py-2 border border-gray-200 rounded-lg hover:bg-gray-50"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-gray-800 truncate">
                        {item.item_id} · {item.item_name}
                      </p>
                      <p className="text-xs text-gray-500 mt-0.5">
                        {item.pillar} · {item.category}
                      </p>
                      {uploaded && (
                        <a
                          href={evidenceDownloadUrl(uploaded.id)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 mt-1 text-xs text-blue-600 hover:underline"
                        >
                          <Paperclip size={11} />
                          {uploaded.name}
                        </a>
                      )}
                    </div>
                    <label
                      className={`shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg cursor-pointer ${
                        uploading
                          ? "bg-gray-100 text-gray-400 cursor-not-allowed"
                          : "bg-white border border-gray-300 text-gray-700 hover:bg-blue-50 hover:border-blue-300"
                      }`}
                    >
                      {uploading ? (
                        <><Loader2 size={12} className="animate-spin" /> 업로드 중</>
                      ) : (
                        <><Paperclip size={12} /> {uploaded ? "교체" : "파일 첨부"}</>
                      )}
                      <input
                        type="file"
                        accept=".pdf,image/*"
                        className="hidden"
                        disabled={uploading}
                        onChange={(e) => {
                          const f = e.target.files?.[0];
                          if (f) handleEvidenceUpload(item.check_id, f);
                          e.target.value = "";
                        }}
                      />
                    </label>
                  </div>
                );
              })}
              {manualItems.length === 0 && (
                <p className="text-sm text-gray-400 text-center py-4">수동 항목이 없습니다.</p>
              )}
            </div>
          )}
        </div>
      )}

      {/* 자동 진단만 사용 + 완료 시 안내 */}
      {manualCount === 0 && collectionDone && (
        <div className="bg-green-50 border border-green-200 rounded-xl p-6 text-center">
          <CheckCircle size={40} className="mx-auto text-green-500 mb-3" />
          <p className="font-semibold text-gray-700">자동 진단 완료</p>
          <p className="text-sm text-gray-500 mt-1 mb-4">
            결과 페이지로 자동 이동합니다...
            {finalizing && <Loader2 size={14} className="inline animate-spin ml-2" />}
          </p>
        </div>
      )}
    </div>
  );
}
