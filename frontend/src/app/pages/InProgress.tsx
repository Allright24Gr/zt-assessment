import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router";
import {
  Area,
  AreaChart,
  CartesianGrid,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  AlertTriangle,
  CheckCircle,
  CirclePause,
  CirclePlay,
  Clock,
  Database,
  Loader2,
  Server,
  Shield,
} from "lucide-react";
import { PILLARS } from "../data/constants";
import { CHECKLIST_ITEMS } from "../data/checklistItems";
import { sessions } from "../data/mockData";

const TOOL_TOTALS = [892, 234, 156, 310];
const TOOL_NAMES = ["Wazuh", "Keycloak", "Trivy", "Nmap"];
const PILLAR_COLORS = ["#2563eb", "#059669", "#f59e0b", "#0891b2", "#7c3aed", "#dc2626"];
const TOOL_COLORS: Record<string, string> = {
  Wazuh: PILLAR_COLORS[0],
  Keycloak: PILLAR_COLORS[1],
  Trivy: PILLAR_COLORS[2],
  Nmap: PILLAR_COLORS[3],
};
const PILLAR_TO_TOOL: Record<string, string> = {
  Identify: "Keycloak",
  Device: "Wazuh",
  Network: "Nmap",
  Application: "Trivy",
  Data: "Wazuh",
  System: "Wazuh",
};
const PILLAR_PROGRESS_STEPS = [9, 8, 7, 6, 7, 6];
const DEMO_SESSION_ID = 7;

const CHECKLISTS = PILLARS.map((pillar) =>
  CHECKLIST_ITEMS
    .filter((item) => item.pillar === pillar.label || item.category === pillar.label)
    .map((item) => `${item.item} · ${item.question}`)
);

const PIPELINE_STEPS = [
  { label: "자산 발견", sublabel: "Asset Discovery" },
  { label: "신원 확인", sublabel: "Identity Check" },
  { label: "정책 분석", sublabel: "Policy Analysis" },
  { label: "보고서 생성", sublabel: "Report Generation" },
];

const INITIAL_LOGS = [
  { time: "00:00", type: "info", message: "진단 세션 초기화 완료" },
  { time: "00:01", type: "success", message: "Wazuh 에이전트 연결 성공" },
  { time: "00:02", type: "info", message: "Keycloak 정책 수집 시작" },
];

const DEMO_LOG_EVENTS = [
  { type: "info", message: "Keycloak /admin/realms/readyz/users?briefRepresentation=true 호출" },
  { type: "success", message: "Keycloak enabled 사용자 128건 수집 완료" },
  { type: "info", message: "Wazuh /security/events?rule.groups=authentication_failure 조회" },
  { type: "warning", message: "Wazuh 인증 실패 이벤트 3건 탐지" },
  { type: "info", message: "Nmap 192.168.10.0/24 TCP 포트 스캔 진행" },
  { type: "success", message: "Nmap 관리 포트 노출 후보 2건 분류" },
  { type: "info", message: "Trivy application-api:latest 이미지 취약점 DB 동기화" },
  { type: "warning", message: "Trivy HIGH 취약점 1건 발견" },
  { type: "info", message: "Wazuh SIEM 룰 활성 상태 확인" },
  { type: "success", message: "Keycloak MFA required action 정책 확인 완료" },
  { type: "info", message: "Nmap 세그먼테이션 정책 검증 대상 큐 적재" },
  { type: "success", message: "Wazuh 로그 수집 파이프라인 정상 응답" },
] as const;

function formatTime() {
  return new Date().toLocaleTimeString("ko-KR", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
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
      <span className="font-semibold" style={{ color: TOOL_COLORS[tool] }}>
        {tool}
      </span>
      {afterParts.join(tool)}
    </>
  );
}

function CircularProgress({
  value,
  label,
  color,
  active,
  completedCount,
  totalCount,
}: {
  value: number;
  label: string;
  color: string;
  active: boolean;
  completedCount: number;
  totalCount: number;
}) {
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.min(value, 100) / 100) * circumference;
  const completed = value >= 100;

  return (
    <div
      className={`rounded-2xl border p-4 transition-all ${
        completed
          ? "border-gray-200 bg-gray-100 text-gray-500"
          : active
          ? "border-blue-300 bg-blue-50 shadow-sm"
          : "border-gray-200 bg-white"
      }`}
    >
      <div className="mx-auto mb-3 h-24 w-24 relative">
        <svg viewBox="0 0 96 96" className="h-24 w-24 -rotate-90">
          <circle cx="48" cy="48" r={radius} fill="none" stroke="#e5e7eb" strokeWidth="9" />
          <circle
            cx="48"
            cy="48"
            r={radius}
            fill="none"
            stroke={color}
            strokeLinecap="round"
            strokeWidth="9"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
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

function formatRemainingTime(progress: number) {
  if (progress >= 100) return "완료";
  const totalSeconds = 90;
  const remainingSeconds = Math.max(1, Math.ceil(totalSeconds * (1 - progress / 100)));
  const minutes = Math.floor(remainingSeconds / 60);
  const seconds = remainingSeconds % 60;
  return minutes > 0 ? `약 ${minutes}분 ${seconds}초 남음` : `약 ${seconds}초 남음`;
}

function getOverallProgress(nextPillars: { progress: number }[]) {
  const total = nextPillars.reduce((sum, pillar) => sum + pillar.progress, 0);
  return Math.min(100, Math.round(total / nextPillars.length));
}

export function InProgress() {
  const navigate = useNavigate();
  const { sessionId } = useParams();
  const reportSessionId = sessionId && !Number.isNaN(Number(sessionId)) ? sessionId : String(DEMO_SESSION_ID);
  const session = sessions.find((item) => String(item.id) === reportSessionId) ?? sessions.find((item) => item.id === DEMO_SESSION_ID);
  const [progress, setProgress] = useState(0);
  const [isPaused, setIsPaused] = useState(false);
  const [showComplete, setShowComplete] = useState(false);
  const [pillars, setPillars] = useState(PILLARS.map((p) => ({ ...p, progress: 0 })));
  const [logs, setLogs] = useState(INITIAL_LOGS);
  const [metrics, setMetrics] = useState({ totalItems: 0, detectedEvents: 0, policyViolations: 0, analyzedAssets: 0 });
  const [areaData, setAreaData] = useState<{ time: string; volume: number }[]>([]);
  const [toolProgress, setToolProgress] = useState(
    TOOL_NAMES.map((name, i) => ({ name, collected: 0, total: TOOL_TOTALS[i], fill: PILLAR_COLORS[i] }))
  );
  const logContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isPaused || progress >= 100) return;

    const timer = window.setInterval(() => {
      let activeIndexForTick = 0;

      setPillars((prev) => {
        activeIndexForTick = prev.findIndex((pillar) => pillar.progress < 100);
        const next = prev.map((pillar, index) => {
          if (index !== activeIndexForTick) return pillar;

          return {
            ...pillar,
            progress: Math.min(pillar.progress + PILLAR_PROGRESS_STEPS[index], 100),
          };
        });

        return next;
      });

      setMetrics((prev) => ({
        totalItems: prev.totalItems + Math.floor(Math.random() * 18) + 5,
        detectedEvents: prev.detectedEvents + Math.floor(Math.random() * 4),
        policyViolations: prev.policyViolations + (Math.random() > 0.72 ? 1 : 0),
        analyzedAssets: prev.analyzedAssets + Math.floor(Math.random() * 6) + 2,
      }));

      setAreaData((prev) => {
        const previousVolume = prev.at(-1)?.volume;
        return [
          ...prev.slice(-19),
          { time: formatTime(), volume: nextLogVolume(previousVolume, progress) },
        ];
      });

      setToolProgress((prev) =>
        prev.map((tool, i) => ({
          ...tool,
          collected:
            TOOL_NAMES[i] === PILLAR_TO_TOOL[PILLARS[activeIndexForTick]?.key]
              ? Math.min(tool.collected + Math.floor(TOOL_TOTALS[i] * 0.04), tool.total)
              : tool.collected,
        }))
      );
    }, 600);

    return () => window.clearInterval(timer);
  }, [isPaused, progress]);

  useEffect(() => {
    const nextProgress = getOverallProgress(pillars);
    setProgress(nextProgress);
    if (nextProgress >= 100) setShowComplete(true);
  }, [pillars]);

  useEffect(() => {
    const activePillar = pillars.find((p) => p.progress > 0 && p.progress < 100) ?? pillars.find((p) => p.progress < 100);
    if (!activePillar || isPaused) return;

    const pillarIndex = PILLARS.findIndex((p) => p.key === activePillar.key);
    const activeChecklist = CHECKLISTS[pillarIndex] ?? [];
    const checklistIndex = Math.min(
      Math.floor((activePillar.progress / 100) * activeChecklist.length),
      Math.max(activeChecklist.length - 1, 0)
    );
    const toolName = PILLAR_TO_TOOL[activePillar.key] ?? "Wazuh";
    const message = `${toolName} ${activePillar.shortLabel} 필러 - ${activeChecklist[checklistIndex] ?? "체크리스트 항목"} 실행 중`;

    setLogs((prev) => {
      if (prev.at(-1)?.message === message) return prev;
      return [...prev.slice(-80), { time: formatTime(), type: "info", message }];
    });
  }, [pillars, isPaused]);

  useEffect(() => {
    if (isPaused || progress >= 100) return;

    let eventIndex = 0;
    const timer = window.setInterval(() => {
      const event = DEMO_LOG_EVENTS[eventIndex % DEMO_LOG_EVENTS.length];
      eventIndex += 1;

      setLogs((prev) => [
        ...prev.slice(-140),
        { time: formatTime(), type: event.type, message: event.message },
      ]);
    }, 260);

    return () => window.clearInterval(timer);
  }, [isPaused, progress]);

  useEffect(() => {
    const el = logContainerRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [logs]);

  const activePillarIndex = pillars.findIndex((p) => p.progress > 0 && p.progress < 100);
  const safeActivePillarIndex = activePillarIndex >= 0 ? activePillarIndex : pillars.findIndex((p) => p.progress < 100);
  const radarData = PILLARS.map((p, i) => ({
    pillar: p.shortLabel,
    score: Number(((pillars[i]?.progress / 100) * 4).toFixed(1)),
  }));

  const activeStepIndex = Math.min(Math.floor((progress / 100) * PIPELINE_STEPS.length), PIPELINE_STEPS.length - 1);
  const estimatedRemainingTime = formatRemainingTime(progress);
  const totalQuestionCount = CHECKLISTS.reduce((sum, checklist) => sum + checklist.length, 0);
  const completedQuestionCount = pillars.reduce((sum, pillar, index) => {
    const total = CHECKLISTS[index]?.length ?? 0;
    return sum + Math.min(Math.floor((pillar.progress / 100) * total), total);
  }, 0);

  return (
    <div className="max-w-7xl mx-auto space-y-5">
      {showComplete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="bg-white rounded-2xl shadow-2xl p-10 max-w-md w-full mx-4 text-center">
            <div className="w-20 h-20 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-6">
              <CheckCircle size={40} className="text-green-500" />
            </div>
            <h2 className="text-2xl font-bold text-gray-900 mb-2">진단 완료!</h2>
            <p className="text-gray-500 mb-8">모든 필러 분석이 완료되었습니다.</p>
            <button
              onClick={() => navigate(`/reporting/${reportSessionId}`)}
              className="w-full py-3 bg-blue-600 text-white rounded-xl font-semibold hover:bg-blue-700 transition-colors"
            >
              결과 보고서 보기
            </button>
          </div>
        </div>
      )}

      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1>진단 진행 중</h1>
          <p className="text-sm text-gray-500 mt-1">
            {session?.org ?? "진단 대상"} / {session?.manager ?? "담당자"} 담당
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsPaused((value) => !value)}
            className={`inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold transition-colors ${
              isPaused ? "bg-green-600 text-white hover:bg-green-700" : "bg-amber-500 text-white hover:bg-amber-600"
            }`}
          >
            {isPaused ? <CirclePlay size={18} /> : <CirclePause size={18} />}
            {isPaused ? "진단 재개" : "진단 일시 정지"}
          </button>
          <div className={`flex items-center gap-2 ${progress >= 100 ? "text-green-600" : isPaused ? "text-amber-600" : "text-blue-600"}`}>
            {progress >= 100 ? <CheckCircle size={18} /> : isPaused ? <CirclePause size={18} /> : <Loader2 size={18} className="animate-spin" />}
            <span className="text-sm font-medium">{progress}% 완료</span>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-5">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-gray-700">전체 진행률</span>
          <span className="text-sm font-semibold text-blue-600">{progress}%</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-3">
          <div className="bg-blue-600 h-3 rounded-full transition-all duration-500" style={{ width: `${progress}%` }} />
        </div>
        <div className="mt-3 flex items-center justify-between text-sm">
          <span className="text-gray-500">예상 소요 시간</span>
          <span className={progress >= 100 ? "font-semibold text-green-600" : "font-semibold text-gray-700"}>
            {estimatedRemainingTime}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "총 수집 항목", value: metrics.totalItems, icon: Database, color: "text-blue-600", bg: "bg-blue-50", border: "border-blue-100" },
          { label: "탐지 이벤트", value: metrics.detectedEvents, icon: AlertTriangle, color: "text-yellow-600", bg: "bg-yellow-50", border: "border-yellow-100" },
          { label: "정책 위반", value: metrics.policyViolations, icon: Shield, color: "text-red-600", bg: "bg-red-50", border: "border-red-100" },
          { label: "분석 자산", value: metrics.analyzedAssets, icon: Server, color: "text-green-600", bg: "bg-green-50", border: "border-green-100" },
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

      <div className="bg-white rounded-xl border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h2>필러별 진행률</h2>
            <p className="mt-1 text-sm text-gray-500">각 필러의 진행률과 질문 처리 개수를 함께 표시합니다.</p>
          </div>
          <span className="rounded-full bg-blue-50 px-3 py-1 text-sm font-semibold text-blue-700">
            {completedQuestionCount} / {totalQuestionCount}개 질문
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {pillars.map((pillar, index) => {
            const checklist = CHECKLISTS[index] ?? [];
            const completedCount = Math.min(
              Math.floor((pillar.progress / 100) * checklist.length),
              checklist.length
            );
            return (
              <CircularProgress
                key={pillar.key}
                value={pillar.progress}
                label={pillar.label}
                color={PILLAR_COLORS[index]}
                active={safeActivePillarIndex === index && !isPaused && progress < 100}
                completedCount={completedCount}
                totalCount={checklist.length}
              />
            );
          })}
        </div>
      </div>

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
                      done ? "border-green-500 bg-green-50" : active ? "border-blue-500 bg-blue-50 ring-2 ring-blue-400/30" : "border-gray-300 bg-gray-50"
                    }`}>
                      {done ? <CheckCircle size={14} className="text-green-500" /> : active ? <Loader2 size={14} className="text-blue-500 animate-spin" /> : <Clock size={14} className="text-gray-400" />}
                    </div>
                    {idx < PIPELINE_STEPS.length - 1 && <div className={`w-0.5 h-8 mt-0.5 ${done ? "bg-green-300" : "bg-gray-200"}`} />}
                  </div>
                  <div className="pb-6">
                    <p className={`text-sm font-medium ${done ? "text-green-600" : active ? "text-blue-600" : "text-gray-400"}`}>{step.label}</p>
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
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.25} />
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
              const ratio = Math.round((tool.collected / tool.total) * 100);
              return (
                <div key={tool.name} className="p-3 bg-gray-50 rounded-lg border border-gray-100">
                  <div className="flex items-center justify-between mb-2">
                    <p className="font-medium text-sm">{tool.name}</p>
                    <span className="text-xs font-semibold" style={{ color: PILLAR_COLORS[index] }}>{ratio}%</span>
                  </div>
                  <p className="text-xs text-gray-500 mb-2">{tool.collected} / {tool.total} 항목</p>
                  <div className="w-full bg-gray-100 rounded-full h-1.5">
                    <div className="h-1.5 rounded-full transition-all duration-500" style={{ width: `${ratio}%`, backgroundColor: PILLAR_COLORS[index] }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2>실시간 진단 로그</h2>
            <p className="text-sm text-gray-500 mt-1">tail -f 로그처럼 진단 이벤트를 시간순으로 스트리밍합니다.</p>
          </div>
          <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold ${
            isPaused ? "bg-amber-100 text-amber-700" : "bg-blue-100 text-blue-700"
          }`}>
            <span className={`h-2 w-2 rounded-full ${isPaused ? "bg-amber-500" : "bg-blue-500 animate-pulse"}`} />
            {isPaused ? "일시 정지" : "수집 중"}
          </span>
        </div>
        <div className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-inner">
          <div className="flex items-center gap-2 border-b border-gray-100 bg-gray-50 px-4 py-2">
            <span className="h-2.5 w-2.5 rounded-full bg-red-400" />
            <span className="h-2.5 w-2.5 rounded-full bg-amber-400" />
            <span className="h-2.5 w-2.5 rounded-full bg-green-400" />
            <span className="ml-2 font-mono text-xs text-gray-500">zt-assessment@readyz-t:~/diagnosis/logs$ tail -f assessment.out</span>
          </div>

          <div ref={logContainerRef} className="max-h-72 overflow-y-auto bg-white px-4 py-3 font-mono text-[13px] leading-6 text-gray-900">
            <div className="text-gray-500">********** Readyz-T diagnosis stream **********</div>
            <div className="text-gray-500">session: {session?.org ?? "진단 대상"} / progress: {progress}%</div>
            {logs.map((log, i) => {
              const tool = getLogTool(log.message);
              const prefix = log.type === "success" ? "====" : log.type === "warning" ? ">>>>" : "----";
              const typeText = log.type === "success" ? "SUCCESS" : log.type === "warning" ? "WARN" : "INFO";

              return (
                <div key={`${log.time}-${i}`} className="flex min-w-max gap-2 whitespace-pre">
                  <span className="text-gray-400">{prefix}</span>
                  <span className="text-sky-600">[{log.time}]</span>
                  <span className={log.type === "warning" ? "text-amber-600" : log.type === "success" ? "text-green-600" : "text-gray-500"}>
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
    </div>
  );
}
