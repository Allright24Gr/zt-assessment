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
import { sessions } from "../data/mockData";

const TOOL_TOTALS = [892, 234, 156, 310];
const TOOL_NAMES = ["Wazuh", "Keycloak", "Trivy", "Nmap"];
const PILLAR_COLORS = ["#2563eb", "#059669", "#f59e0b", "#7c3aed", "#dc2626", "#0891b2"];
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
const DEMO_SESSION_ID = 7;

const CHECKLISTS = [
  [
    "IAM 계정 동기화 상태 확인",
    "MFA 적용률 분석",
    "관리자 권한 변경 이력 점검",
    "휴면 계정 자동 잠금 정책 검증",
  ],
  [
    "단말 에이전트 연결 상태 수집",
    "고위험 CVE 패치 여부 확인",
    "디스크 암호화 정책 점검",
    "분실 단말 원격 차단 정책 검증",
  ],
  [
    "오픈 포트 및 서비스 식별",
    "망 분리 정책 적용 범위 확인",
    "관리 포트 외부 노출 점검",
    "마이크로 세그먼테이션 후보 산출",
  ],
  [
    "API 인증 정책 확인",
    "권한 없는 호출 실패 로그 점검",
    "관리자 API 감사 로그 수집",
    "취약 라이브러리 스캔 결과 분석",
  ],
  [
    "민감 데이터 분류 정책 확인",
    "저장 데이터 암호화 상태 점검",
    "전송 구간 TLS 적용 검증",
    "백업 저장소 접근 권한 분석",
  ],
  [
    "SIEM 로그 수집 상태 확인",
    "탐지 룰 활성화 여부 점검",
    "알림 채널 연동 테스트",
    "대응 플레이북 매핑 상태 검증",
  ],
];

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
}: {
  value: number;
  label: string;
  color: string;
  active: boolean;
}) {
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.min(value, 100) / 100) * circumference;

  return (
    <div className={`rounded-2xl border p-4 transition-all ${active ? "border-blue-300 bg-blue-50 shadow-sm" : "border-gray-200 bg-white"}`}>
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
          <span className="text-[11px] text-gray-400">{active ? "진행 중" : value >= 100 ? "완료" : "대기"}</span>
        </div>
      </div>
      <p className="text-center text-sm font-semibold text-gray-700">{label}</p>
    </div>
  );
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
      setProgress((prev) => {
        const next = Math.min(prev + 2, 100);
        if (next >= 100) setShowComplete(true);
        return next;
      });

      setPillars((prev) =>
        prev.map((p, i) => ({
          ...p,
          progress: Math.min(p.progress + [3, 2.5, 1.8, 1.5, 1.2, 1][i], 100),
        }))
      );

      setMetrics((prev) => ({
        totalItems: prev.totalItems + Math.floor(Math.random() * 18) + 5,
        detectedEvents: prev.detectedEvents + Math.floor(Math.random() * 4),
        policyViolations: prev.policyViolations + (Math.random() > 0.72 ? 1 : 0),
        analyzedAssets: prev.analyzedAssets + Math.floor(Math.random() * 6) + 2,
      }));

      setAreaData((prev) => [
        ...prev.slice(-19),
        { time: formatTime(), volume: Math.floor(Math.random() * 70) + 10 },
      ]);

      setToolProgress((prev) =>
        prev.map((tool, i) => ({
          ...tool,
          collected: Math.min(tool.collected + Math.floor(TOOL_TOTALS[i] * 0.025), tool.total),
        }))
      );
    }, 600);

    return () => window.clearInterval(timer);
  }, [isPaused, progress]);

  useEffect(() => {
    const activePillar = pillars.find((p) => p.progress > 0 && p.progress < 100) ?? pillars.find((p) => p.progress < 100);
    if (!activePillar || isPaused) return;

    const checklistIndex = Math.min(Math.floor((activePillar.progress / 100) * CHECKLISTS[0].length), CHECKLISTS[0].length - 1);
    const pillarIndex = PILLARS.findIndex((p) => p.key === activePillar.key);
    const toolName = PILLAR_TO_TOOL[activePillar.key] ?? "Wazuh";
    const message = `${toolName} ${activePillar.shortLabel} 필러 - ${CHECKLISTS[pillarIndex][checklistIndex]} 실행 중`;

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
  const activeChecklistIndex = safeActivePillarIndex >= 0
    ? Math.min(Math.floor((pillars[safeActivePillarIndex].progress / 100) * CHECKLISTS[0].length), CHECKLISTS[0].length - 1)
    : CHECKLISTS[0].length - 1;

  const radarData = PILLARS.map((p, i) => ({
    pillar: p.shortLabel,
    score: Number(((pillars[i]?.progress / 100) * 4).toFixed(1)),
  }));

  const activeStepIndex = Math.min(Math.floor((progress / 100) * PIPELINE_STEPS.length), PIPELINE_STEPS.length - 1);

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

      <div className="grid grid-cols-1 xl:grid-cols-[1.25fr_0.75fr] gap-5">
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <div className="flex items-center justify-between mb-5">
            <h2>필러별 진행률</h2>
            <span className="text-xs text-gray-400">원형 진행률</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            {pillars.map((pillar, index) => (
              <CircularProgress
                key={pillar.key}
                value={pillar.progress}
                label={pillar.label}
                color={PILLAR_COLORS[index]}
                active={safeActivePillarIndex === index && !isPaused && progress < 100}
              />
            ))}
          </div>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h2 className="mb-2">현재 실행 중 체크리스트</h2>
          <p className="text-sm text-gray-500 mb-5">
            {safeActivePillarIndex >= 0 ? PILLARS[safeActivePillarIndex].label : "모든 필러"} 기준으로 진행 중입니다.
          </p>
          <div className="space-y-3">
            {(safeActivePillarIndex >= 0 ? CHECKLISTS[safeActivePillarIndex] : CHECKLISTS[0]).map((item, index) => {
              const done = safeActivePillarIndex < 0 || index < activeChecklistIndex;
              const active = safeActivePillarIndex >= 0 && index === activeChecklistIndex && progress < 100;
              return (
                <div
                  key={item}
                  className={`rounded-xl border p-3 ${
                    done ? "border-green-200 bg-green-50" : active ? "border-blue-300 bg-blue-50" : "border-gray-200 bg-gray-50"
                  }`}
                >
                  <div className="flex items-start gap-3">
                    <div className={`mt-0.5 h-6 w-6 rounded-full flex items-center justify-center ${
                      done ? "bg-green-500 text-white" : active ? "bg-blue-500 text-white" : "bg-gray-200 text-gray-500"
                    }`}>
                      {done ? <CheckCircle size={14} /> : active ? <Loader2 size={14} className="animate-spin" /> : <Clock size={14} />}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-800">{item}</p>
                      <p className="text-xs text-gray-500 mt-0.5">{done ? "완료" : active ? isPaused ? "일시 정지됨" : "실행 중" : "대기"}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
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
