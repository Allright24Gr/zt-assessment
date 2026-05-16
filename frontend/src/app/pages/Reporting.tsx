import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router";
import { toast } from "sonner";
import { API_BASE } from "../../config/api";
import { FileText, Download, TrendingUp, AlertTriangle, AlertCircle, ArrowRight, ChevronDown, RotateCcw } from "lucide-react";
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ResponsiveContainer, Legend,
} from "recharts";
import { useAuth } from "../context/AuthContext";
import { sessions as mockSessions, improvements as mockImprovements } from "../data/mockData";
import type { ChecklistDetail, Improvement, Session } from "../data/mockData";
import { PILLARS } from "../data/constants";
import { getMaturityLevel, getScoreColor, maturityLabel } from "../lib/maturity";
import { getAssessmentResult, getImprovement } from "../../config/api";
import { PILLAR_NAME_TO_KEY } from "../lib/pillar";
import type { ChecklistItemResult, ImprovementItem } from "../../types/api";

const DEFAULT_SCORES = [2.5, 3.0, 2.0, 2.2, 2.8, 1.5];
const TARGET_SCORES  = [3.5, 3.5, 3.0, 3.5, 3.5, 3.0];

// 백엔드 enum → 프론트 카드용 결과 라벨로 매핑
// 부분충족·미충족 둘 다 "미흡"으로 표시 (UI 구분이 단순)하되 색상은 result로 결정
function _displayResult(r: string): "충족" | "미흡" | "해당 없음" {
  if (r === "충족") return "충족";
  if (r === "평가불가") return "해당 없음";
  return "미흡";   // 미충족, 부분충족
}

function adaptChecklistResult(item: ChecklistItemResult): ChecklistDetail & { rawResult: string } {
  return {
    id: item.id,
    pillar: PILLAR_NAME_TO_KEY[item.pillar] ?? item.pillar,
    category: item.category,
    item: item.item,
    maturity: item.maturity,
    maturityScore: item.maturity_score ?? 0,
    question: (item as ChecklistItemResult & { question?: string }).question ?? item.item,
    diagnosisType: item.diagnosis_type ?? "",
    tool: item.tool,
    result: _displayResult(item.result),
    score: item.score,
    evidence: item.evidence,
    criteria: item.criteria,
    fields: item.fields,
    logic: item.logic,
    exceptions: item.exceptions,
    recommendation: item.recommendation,
    evidenceSummary: item.evidence_summary,
    relatedImprovementIds: item.related_improvement_ids,
    rawResult: item.result,
  };
}

function adaptImprovement(item: ImprovementItem): Improvement {
  return {
    id: item.id,
    task: item.task,
    priority: item.priority,
    term: item.term,
    pillar: item.pillar,
    duration: item.duration,
    difficulty: item.difficulty,
    owner: item.owner,
    expectedGain: item.expected_gain,
    relatedItem: item.related_item,
    steps: item.steps,
    expectedEffect: item.expected_effect,
  };
}

// 백엔드 error.pillar(한글) → 프론트 PILLAR.key(영문) 변환
function _pillarKeyOf(pillar?: string): string {
  if (!pillar) return "all";
  return PILLAR_NAME_TO_KEY[pillar] ?? pillar;
}

function formatGap(value: number) {
  return value > 0 ? `+${value.toFixed(1)}` : value.toFixed(1);
}

function getDemoFinding(detail: {
  tool: string;
  result: string;
  score: number;
  pillar: string;
  item: string;
  evidenceSummary?: {
    source: string;
    observed: string;
    location: string;
    reason: string;
    impact: number;
  };
}) {
  if (detail.evidenceSummary) return detail.evidenceSummary;

  const isFailed = detail.result === "미흡" || detail.result === "부분충족" || detail.result === "미충족";
  const impact = isFailed ? Number(Math.max(0.1, 4 - detail.score).toFixed(1)) : 0;

  if (detail.tool.includes("Keycloak")) {
    return {
      source: "Keycloak Admin API",
      observed: isFailed
        ? "활성 사용자 128명 중 정책 미충족 사용자 17명 확인"
        : "활성 사용자 128명 중 기준 충족 사용자 비율 96.1%",
      location: "/admin/realms/readyz/users, /authentication/flows",
      reason: isFailed
        ? "필수 MFA 또는 역할 부여 기준을 충족하지 못한 계정이 발견되어 감점되었습니다."
        : "사용자·역할·인증 흐름이 판정 기준을 충족했습니다.",
      impact,
    };
  }

  if (detail.tool.includes("Wazuh")) {
    return {
      source: "Wazuh Security Events",
      observed: isFailed
        ? "최근 24시간 기준 중요 이벤트 3건, 룰 비활성 후보 2건 확인"
        : "최근 24시간 기준 수집 파이프라인 정상, 중요 룰 활성 상태 확인",
      location: "/security/events, /manager/rules",
      reason: isFailed
        ? "탐지 룰 또는 로그 수집 증적이 목표 기준보다 부족해 감점되었습니다."
        : "로그 수집과 탐지 룰 활성 상태가 판정 기준을 충족했습니다.",
      impact,
    };
  }

  if (detail.tool.includes("Nmap")) {
    return {
      source: "Nmap Scan Result",
      observed: isFailed
        ? "관리 포트 후보 2개가 외부 대역에서 응답"
        : "업무 구간 외 관리 포트 노출 없음",
      location: "192.168.10.0/24 TCP scan",
      reason: isFailed
        ? "세그멘테이션 또는 포트 노출 기준을 충족하지 못해 네트워크 위험으로 분류되었습니다."
        : "스캔 결과가 네트워크 접근 기준을 충족했습니다.",
      impact,
    };
  }

  return {
    source: detail.tool === "수동" ? "Manual Evidence Review" : `${detail.tool} Result`,
    observed: isFailed
      ? "필수 증적 미제출 또는 운영 기준 미달"
      : "제출 증적과 운영 기준 일치",
    location: detail.item,
    reason: isFailed
      ? "문서·정책·운영 증적이 판정 기준을 충분히 만족하지 못했습니다."
      : "제출된 증적이 판정 기준을 만족했습니다.",
    impact,
  };
}

function getRoadmapMeta(task: {
  task: string;
  priority: string;
  term: string;
  pillar: string;
  owner?: string;
  duration?: string;
  difficulty?: string;
  expectedGain?: string;
  relatedItem?: string;
  steps?: string[];
}) {
  const ownerByPillar: Record<string, string> = {
    Identify: "IAM 관리자",
    Device: "엔드포인트 보안 담당",
    Network: "네트워크 보안 담당",
    System: "보안 운영 담당",
    Application: "애플리케이션 보안 담당",
    Data: "데이터 보안 담당",
  };
  const relatedByPillar: Record<string, string> = {
    Identify: "1.2.1 다중인증(MFA) / 1.4.2 최소 권한 접근",
    Device: "2.1.1 기기 감지 및 규정 준수 / 2.4.2 패치 관리 자동화",
    Network: "3.1.1 매크로 세그멘테이션 / 3.1.2 마이크로 세그멘테이션",
    System: "4.1.1 접근통제 / 4.2.1 PAM",
    Application: "5.4.1 안전한 애플리케이션 배포 / 5.5.2 소프트웨어 위험 관리",
    Data: "6.2.1 데이터 접근제어 / 6.5.1 DLP",
  };
  const stepsByPillar: Record<string, string[]> = {
    Identify: ["미충족 사용자·권한 목록 추출", "관리자·외부 접근 계정 우선 적용", "예외 계정 승인 절차 등록", "재진단으로 적용률 확인"],
    Device: ["미연결 단말과 고위험 CVE 목록 추출", "업무 중요도 기준 우선순위 지정", "패치·에이전트 조치 수행", "Wazuh 수집 결과로 증적 보관"],
    Network: ["노출 포트와 세그먼트 현황 수집", "업무 구간별 허용 정책 정의", "차단·분리 정책 단계 적용", "Nmap 재스캔으로 잔여 노출 확인"],
    System: ["특권 계정과 정책 예외 목록 정리", "PAM·접근통제 적용 범위 확정", "로그·알림 룰 활성화", "운영 증적을 보고서에 첨부"],
    Application: ["애플리케이션 인벤토리 정리", "배포 전 보안 검사 기준 설정", "취약점 결과를 릴리즈 승인에 연결", "재검사 결과를 릴리즈 기록에 저장"],
    Data: ["중요 데이터와 저장 위치 식별", "접근권한·암호화 적용 현황 점검", "DLP·라벨링 정책 적용", "정책 증적과 예외 승인 이력 보관"],
  };

  const durationByTerm: Record<string, string> = {
    단기: "1~2주",
    중기: "1~2개월",
    장기: "3~6개월",
  };
  const difficultyByPriority: Record<string, string> = {
    Critical: "중",
    High: "중",
    Medium: "하",
  };
  const gainByPriority: Record<string, string> = {
    Critical: "+0.3~0.5",
    High: "+0.2~0.4",
    Medium: "+0.1~0.2",
  };

  return {
    owner: task.owner ?? ownerByPillar[task.pillar] ?? "보안 담당",
    duration: task.duration ?? durationByTerm[task.term] ?? "2~4주",
    difficulty: task.difficulty ?? difficultyByPriority[task.priority] ?? "중",
    expectedGain: task.expectedGain ?? gainByPriority[task.priority] ?? "+0.1",
    relatedItem: task.relatedItem ?? relatedByPillar[task.pillar] ?? "관련 체크리스트 항목",
    steps: task.steps ?? stepsByPillar[task.pillar] ?? ["대상 목록 추출", "정책 적용", "증적 확인", "재진단"],
  };
}

const TERM_LABELS: Record<string, string> = { 단기: "단기 (0–6개월)", 중기: "중기 (6–18개월)", 장기: "장기 (18개월+)" };
const TERM_COLORS: Record<string, string> = {
  단기: "border-red-200 bg-red-50",
  중기: "border-yellow-200 bg-yellow-50",
  장기: "border-blue-200 bg-blue-50",
};
const TERM_HEADER: Record<string, string> = {
  단기: "text-red-700",
  중기: "text-yellow-700",
  장기: "text-blue-700",
};

export function Reporting() {
  const { sessionId } = useParams();
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState("overall");
  const [detailPillarFilter, setDetailPillarFilter] = useState("all");
  const [detailQuestionQuery, setDetailQuestionQuery] = useState("");
  const [selectedRiskCode, setSelectedRiskCode] = useState<string | null>(null);
  const [pdfDownloading, setPdfDownloading] = useState(false);

  const fallbackSession: Session = mockSessions.find((s) => s.id === Number(sessionId)) ?? mockSessions[0];
  const [session, setSession] = useState<Session>(fallbackSession);
  const [isDemo, setIsDemo] = useState(false);
  const [usedFallback, setUsedFallback] = useState(false);
  const [currentScores, setCurrentScores] = useState(DEFAULT_SCORES);
  const [checklistDetails, setChecklistDetails] = useState<ChecklistDetail[]>(fallbackSession.checklistDetails);
  const [improvements, setImprovements] = useState<Improvement[]>(mockImprovements);

  useEffect(() => {
    if (!sessionId) return;

    getAssessmentResult(sessionId)
      .then((data) => {
        setUsedFallback(false);
        setSession({
          id: Number(data.session.id),
          org: data.session.org,
          date: data.session.date,
          manager: data.session.manager,
          userId: String(data.session.user_id ?? ""),
          level: data.session.level,
          status: data.session.status,
          score: data.session.score,
          errors: (data.session.errors ?? []).map((e) => ({
            code: e.code,
            message: e.message,
            severity: e.severity,
            area: e.area,
            pillar: e.pillar,
            fail_count: e.fail_count,
            miss_count: e.miss_count,
          })),
          checklistDetails: [],
        });
        setIsDemo(Boolean(data.session.is_demo));

        const scores = PILLARS.map((p, i) => {
          const match = data.pillar_scores.find((ps) =>
            (PILLAR_NAME_TO_KEY[ps.pillar] ?? ps.pillar) === p.key
          );
          return match ? match.score : DEFAULT_SCORES[i];
        });
        setCurrentScores(scores);

        setChecklistDetails(data.checklist_results.map(adaptChecklistResult));
      })
      .catch((err) => {
        console.warn("[reporting] result fetch failed:", err);
        toast.error("진단 결과를 불러오지 못했습니다.");
        setUsedFallback(true);
      });

    getImprovement(sessionId)
      .then((data) => setImprovements(data.items.map(adaptImprovement)))
      .catch((err) => {
        console.warn("[reporting] improvement fetch failed:", err);
        setUsedFallback(true);
      });
  }, [sessionId]);

  const normalizedQuestionQuery = detailQuestionQuery.trim().toLowerCase();
  const filteredChecklistDetails = checklistDetails.filter((detail) => {
    const matchesPillar = detailPillarFilter === "all" || detail.pillar === detailPillarFilter;
    const searchable = `${detail.item} ${detail.question} ${detail.tool} ${detail.evidence} ${detail.criteria} ${detail.fields} ${detail.logic} ${detail.recommendation}`.toLowerCase();
    const matchesQuestion = normalizedQuestionQuery.length === 0 || searchable.includes(normalizedQuestionQuery);
    return matchesPillar && matchesQuestion;
  });
  const checklistGroups = PILLARS.map((pillar) => ({
    pillar,
    items: filteredChecklistDetails.filter((detail) => detail.pillar === pillar.key),
  })).filter((group) => group.items.length > 0);

  const radarData = PILLARS.map((p, i) => ({
    pillar: p.shortLabel,
    "현재(AS-IS)": currentScores[i],
    "목표(TO-BE)": TARGET_SCORES[i],
  }));

  const pillarScores = PILLARS.map((p, i) => ({
    key: p.key,
    name: p.label,
    score: currentScores[i],
    target: TARGET_SCORES[i],
    level: getMaturityLevel(currentScores[i]),
    gap: parseFloat((currentScores[i] - TARGET_SCORES[i]).toFixed(1)),
  }));

  const currentAvg = useMemo(
    () => currentScores.reduce((a, b) => a + b, 0) / Math.max(currentScores.length, 1),
    [currentScores],
  );
  const targetAvg = useMemo(
    () => TARGET_SCORES.reduce((a, b) => a + b, 0) / TARGET_SCORES.length,
    [],
  );

  const byTerm = ["단기", "중기", "장기"].map((term) => ({
    term,
    tasks: improvements.filter((t) => t.term === term),
  }));

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {usedFallback && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <div>
            <p className="font-semibold">백엔드 연결 실패 — 예시 데이터로 표시 중</p>
            <p className="mt-0.5 text-xs text-amber-800">
              실제 진단 결과를 불러오지 못해 시연용 mock 데이터를 표시하고 있습니다. 백엔드 상태를 확인한 뒤 새로고침해주세요.
            </p>
          </div>
        </div>
      )}
      {isDemo && (
        <div className="rounded-lg border border-amber-300 bg-amber-50 px-4 py-2 text-sm text-amber-900">
          <span className="font-semibold">데모 데이터</span> — 실제 진단 결과가 아닙니다. 시연용 사전 시드된 결과입니다.
        </div>
      )}
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1>진단 결과</h1>
          <p className="text-sm text-gray-600 mt-1">
            {session.org} — {session.manager} ({session.date})
          </p>
        </div>
        <Link
          to="/new-assessment"
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          <RotateCcw size={20} />
          재진단 시작
        </Link>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <div className="flex gap-1">
          {[
            { id: "overall", label: "종합 결과" },
            { id: "details", label: "세부 항목" },
            { id: "improvements", label: "개선 로드맵" },
            { id: "export", label: "보고서 출력" },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-5 py-2.5 border-b-2 text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? "border-blue-600 text-blue-600"
                  : "border-transparent text-gray-500 hover:text-gray-800"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── 종합 결과 ── */}
      {activeTab === "overall" && (
        <div className="space-y-6">
          {/* 위험 영역 (관리자) */}
          {user?.role === "admin" && session.errors.length > 0 && (
            <div className="bg-red-50 border border-red-200 rounded-xl p-6">
              <div className="flex items-center gap-2 mb-4">
                <AlertCircle className="text-red-600" size={20} />
                <h2 className="text-red-900">위험 영역</h2>
              </div>
              <div className="space-y-2">
                {session.errors.map((error, i) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-white rounded-lg border border-red-100">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-sm font-bold text-red-700">{error.code}</span>
                        <span className="text-sm font-semibold text-gray-800">{error.area ?? error.pillar ?? error.message}</span>
                        <span className={`px-2 py-1 rounded text-xs font-medium ${
                          error.severity === "Critical" ? "bg-red-100 text-red-700" :
                          error.severity === "High"     ? "bg-orange-100 text-orange-700" :
                                                          "bg-yellow-100 text-yellow-700"
                        }`}>
                          {error.severity}
                        </span>
                      </div>
                      <p className="mt-1 text-sm text-gray-600">{error.message}</p>
                      {(error.fail_count ?? 0) > 0 && (
                        <p className="mt-1 text-xs text-gray-500">
                          미충족 {error.miss_count ?? 0}건 · 부분충족 {(error.fail_count ?? 0) - (error.miss_count ?? 0)}건
                        </p>
                      )}
                    </div>
                    <button
                      onClick={() => {
                        setActiveTab("details");
                        setSelectedRiskCode(error.code);
                        setDetailPillarFilter(_pillarKeyOf(error.pillar));
                        setDetailQuestionQuery("");
                      }}
                      className="ml-4 shrink-0 text-sm font-medium text-red-700 hover:underline"
                    >
                      자세히 보기
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 종합 등급 배너 */}
          <div className="bg-gradient-to-r from-blue-600 to-blue-700 text-white rounded-xl p-8">
            <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <p className="text-blue-200 text-sm mb-1">종합 성숙도 등급</p>
                <h1 className="text-6xl font-bold mb-2">
                  {session.score !== null ? session.score : "-"}
                  <span className="ml-2 text-2xl font-semibold text-blue-200">/ 4.0</span>
                </h1>
                <p className="text-blue-200">
                  종합 점수 · {maturityLabel(session.level)} 단계
                </p>
              </div>
              {/* 단계 진행 표시 */}
              <div className="flex flex-col gap-2">
                <div className="text-sm font-semibold text-blue-100">향상 단계</div>
                <div className="flex items-center gap-2">
                {(["기존", "초기", "향상", "최적화"] as const).map((step, i, arr) => (
                  <div key={step} className="flex items-center gap-2">
                    <div className={`flex flex-col items-center`}>
                      <div className={`w-10 h-10 rounded-full border-2 flex items-center justify-center text-xs font-bold ${
                        step === session.level
                          ? "bg-white text-blue-600 border-white"
                          : "border-blue-400 text-blue-300"
                      }`}>
                        {i + 1}
                      </div>
                      <span className={`text-xs mt-1 ${step === session.level ? "text-white font-semibold" : "text-blue-400"}`}>
                        {maturityLabel(step)}
                      </span>
                    </div>
                    {i < arr.length - 1 && (
                      <ArrowRight size={16} className="text-blue-400 mb-5" />
                    )}
                  </div>
                ))}
                </div>
              </div>
            </div>
          </div>

          {/* AS-IS / TO-BE 레이더 */}
          <div className="bg-white rounded-xl border border-gray-200 p-6">
            <div className="flex items-center gap-2 mb-2">
              <TrendingUp className="text-blue-600" size={20} />
              <h2>AS-IS / TO-BE 비교</h2>
            </div>
            <p className="text-sm text-gray-500 mb-4">현재 성숙도와 목표 성숙도 간의 GAP을 시각화합니다</p>
            <div className="flex items-center gap-4 mb-2">
              <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-full bg-blue-500 opacity-80" /><span className="text-xs text-gray-600">현재 (AS-IS)</span></div>
              <div className="flex items-center gap-1.5"><div className="w-3 h-3 rounded-full bg-emerald-500 opacity-60" /><span className="text-xs text-gray-600">목표 (TO-BE)</span></div>
            </div>
            <ResponsiveContainer width="100%" height={380}>
              <RadarChart data={radarData}>
                <PolarGrid stroke="#e5e7eb" />
                <PolarAngleAxis dataKey="pillar" stroke="#6b7280" tick={{ fontSize: 12 }} />
                <PolarRadiusAxis domain={[0, 4]} stroke="#d1d5db" tick={{ fontSize: 10 }} />
                <Radar name="현재(AS-IS)" dataKey="현재(AS-IS)" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.5} strokeWidth={2} />
                <Radar name="목표(TO-BE)" dataKey="목표(TO-BE)" stroke="#10b981" fill="#10b981" fillOpacity={0.25} strokeWidth={2} strokeDasharray="5 3" />
                <Legend wrapperStyle={{ fontSize: 12 }} />
              </RadarChart>
            </ResponsiveContainer>
          </div>

          {/* 필라별 점수 카드 */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {pillarScores.map((pillar) => {
              const colors = getScoreColor(pillar.score);
              const pct = (pillar.score / 4) * 100;
              return (
                <div key={pillar.key} className="bg-white rounded-xl border border-gray-200 p-5">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-sm font-semibold text-gray-700">{pillar.name}</h3>
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${colors.badge}`}>{maturityLabel(pillar.level)}</span>
                  </div>
                  <div className="flex items-baseline gap-1 mb-3">
                    <span className={`text-3xl font-bold ${colors.text}`}>{pillar.score}</span>
                    <span className="text-gray-400 text-sm">/ 4.0</span>
                  </div>
                  {/* 점수 바 */}
                  <div className="relative w-full bg-gray-100 rounded-full h-2 mb-2">
                    <div className={`${colors.bar} h-2 rounded-full`} style={{ width: `${pct}%` }} />
                    {/* 목표 마커 */}
                    <div
                      className="absolute top-1/2 -translate-y-1/2 w-0.5 h-4 bg-emerald-500 rounded"
                      style={{ left: `${(pillar.target / 4) * 100}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-xs text-gray-400">
                    <span>현재 {pillar.score}</span>
                    <span className={pillar.gap < 0 ? "text-red-600" : "text-emerald-600"}>
                      목표 {pillar.target} ({formatGap(pillar.gap)})
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── 세부 항목 ── */}
      {activeTab === "details" && (
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <div className="flex flex-col gap-4 mb-5 xl:flex-row xl:items-end xl:justify-between">
            <div>
              <h2>필러별 세부 항목 결과</h2>
              <p className="text-sm text-gray-500 mt-1">
                각 체크리스트를 클릭하면 판정 근거와 개선 권고를 확인할 수 있습니다.
              </p>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-[180px_minmax(240px,360px)]">
              <label className="block">
                <span className="mb-1 block text-xs font-semibold text-gray-500">필러 검색</span>
                <select
                  value={detailPillarFilter}
                  onChange={(event) => setDetailPillarFilter(event.target.value)}
                  className="h-10 w-full rounded-lg border border-gray-200 bg-white px-3 text-sm text-gray-700 outline-none focus:border-blue-400 focus:ring-2 focus:ring-blue-100"
                >
                  <option value="all">전체 필러</option>
                  {PILLARS.map((pillar) => (
                    <option key={pillar.key} value={pillar.key}>{pillar.label}</option>
                  ))}
                </select>
              </label>
              <label className="block">
                <span className="mb-1 block text-xs font-semibold text-gray-500">질문 검색</span>
                <input
                  value={detailQuestionQuery}
                  onChange={(event) => setDetailQuestionQuery(event.target.value)}
                  placeholder="질문, 항목명, 도구, 증적 검색"
                  className="h-10 w-full rounded-lg border border-gray-200 px-3 text-sm text-gray-700 outline-none placeholder:text-gray-400 focus:border-blue-400 focus:ring-2 focus:ring-blue-100"
                />
              </label>
            </div>
          </div>

          <div className="mb-4 flex items-center justify-between rounded-xl bg-gray-50 px-4 py-3 text-sm text-gray-600">
            <span>총 {checklistDetails.length}개 중 {filteredChecklistDetails.length}개 표시</span>
            {(detailPillarFilter !== "all" || detailQuestionQuery) && (
              <button
                onClick={() => {
                  setDetailPillarFilter("all");
                  setDetailQuestionQuery("");
                  setSelectedRiskCode(null);
                }}
                className="text-blue-600 hover:underline"
              >
                검색 초기화
              </button>
            )}
          </div>

          {selectedRiskCode && (() => {
            const err = session.errors.find((e) => e.code === selectedRiskCode);
            if (!err) return null;
            return (
              <div className="mb-4 rounded-xl border border-red-200 bg-red-50 p-4">
                <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                  <div>
                    <div className="mb-1 flex flex-wrap items-center gap-2">
                      <span className="rounded-full bg-red-100 px-2 py-0.5 font-mono text-xs font-bold text-red-700">
                        {selectedRiskCode}
                      </span>
                      <h3 className="font-semibold text-red-900">{err.area ?? err.pillar}</h3>
                    </div>
                    <p className="text-sm text-red-800">{err.message}</p>
                  </div>
                  <span className="rounded-full bg-white px-3 py-1 text-xs font-semibold text-red-700">
                    관련 항목 {filteredChecklistDetails.length}개 표시
                  </span>
                </div>
              </div>
            );
          })()}

          <div className="space-y-6">
            {checklistGroups.map(({ pillar, items }) => (
              <section key={pillar.key} className="rounded-2xl border border-gray-200 bg-gray-50/70 p-4">
                <div className="mb-3 flex items-center justify-between">
                  <div>
                    <h3 className="font-semibold text-gray-900">{pillar.label}</h3>
                    <p className="text-xs text-gray-500">{pillar.shortLabel} 필러 체크리스트</p>
                  </div>
                  <span className="rounded-full bg-white px-3 py-1 text-xs font-semibold text-blue-700 shadow-sm">
                    {items.length}개 항목
                  </span>
                </div>

                <div className="space-y-3">
                  {items.map((detail) => {
                    const scoreColors = getScoreColor(detail.score);
                    const finding = getDemoFinding(detail);
                    const raw = (detail as ChecklistDetail & { rawResult?: string }).rawResult ?? detail.result;
                    const resultCardClass = raw === "충족"
                      ? "border-green-200 bg-green-50 open:border-green-300 open:bg-green-100/60"
                      : raw === "미충족"
                      ? "border-rose-200 bg-rose-50 open:border-rose-300 open:bg-rose-100/60"
                      : raw === "부분충족"
                      ? "border-amber-200 bg-amber-50 open:border-amber-300 open:bg-amber-100/60"
                      : "border-gray-200 bg-white open:border-blue-200 open:bg-blue-50/30";

                    return (
                      <details
                        key={detail.id}
                        className={`group rounded-xl border p-4 transition-colors ${resultCardClass}`}
                      >
                        <summary className="flex cursor-pointer list-none items-center justify-between gap-4">
                          <div className="min-w-0">
                            <div className="mb-2 flex flex-wrap items-center gap-2">
                              <span className="rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-600">
                                {detail.category}
                              </span>
                              <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${
                                raw === "충족"
                                  ? "bg-green-100 text-green-700"
                                  : raw === "미충족"
                                  ? "bg-red-100 text-red-700"
                                  : raw === "부분충족"
                                  ? "bg-amber-100 text-amber-700"
                                  : "bg-gray-100 text-gray-500"
                              }`}>
                                {raw}
                              </span>
                              <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${scoreColors.badge}`}>
                                {maturityLabel(getMaturityLevel(detail.score))}
                              </span>
                              <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600">
                                {detail.diagnosisType} / {detail.tool}
                              </span>
                            </div>
                            <p className="mb-1 text-xs font-semibold text-gray-500">{detail.item} · {maturityLabel(detail.maturity)}</p>
                            <p className="font-medium text-gray-900">{detail.question}</p>
                          </div>
                          <div className="flex shrink-0 items-center gap-4">
                            <div className="text-right">
                              <p className="text-lg font-bold text-blue-600">{detail.score}</p>
                              <p className="text-xs text-gray-400">/ 4.0</p>
                            </div>
                            <ChevronDown size={18} className="text-gray-400 transition-transform group-open:rotate-180" />
                          </div>
                        </summary>

                        <div className="mt-4 rounded-xl border border-slate-200 bg-white p-4">
                          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                            <div>
                              <p className="text-xs font-semibold text-slate-500">진단 근거 스냅샷</p>
                              <p className="mt-1 text-sm font-semibold text-slate-900">{finding.source}</p>
                            </div>
                            <span className={`rounded-full px-2 py-1 text-xs font-semibold ${
                              finding.impact > 0 ? "bg-red-100 text-red-700" : "bg-green-100 text-green-700"
                            }`}>
                              점수 영향 {finding.impact > 0 ? `-${finding.impact}` : "없음"}
                            </span>
                          </div>
                          <div className="grid gap-3 md:grid-cols-3">
                            <div className="rounded-lg bg-slate-50 p-3">
                              <p className="mb-1 text-xs font-semibold text-slate-500">수집값</p>
                              <p className="text-sm leading-relaxed text-slate-700">{finding.observed}</p>
                            </div>
                            <div className="rounded-lg bg-slate-50 p-3">
                              <p className="mb-1 text-xs font-semibold text-slate-500">발견 위치</p>
                              <p className="text-sm leading-relaxed text-slate-700">{finding.location}</p>
                            </div>
                            <div className="rounded-lg bg-slate-50 p-3">
                              <p className="mb-1 text-xs font-semibold text-slate-500">판정 이유</p>
                              <p className="text-sm leading-relaxed text-slate-700">{finding.reason}</p>
                            </div>
                          </div>
                        </div>

                        <div className="mt-4 grid gap-3 md:grid-cols-2">
                          <div className="rounded-lg border border-gray-100 bg-white p-3">
                            <p className="mb-1 text-xs font-semibold text-gray-500">증적</p>
                            <p className="text-sm leading-relaxed text-gray-700">{detail.evidence}</p>
                          </div>
                          <div className="rounded-lg border border-gray-100 bg-white p-3">
                            <p className="mb-1 text-xs font-semibold text-gray-500">판정 기준</p>
                            <p className="whitespace-pre-line text-sm leading-relaxed text-gray-700">{detail.criteria}</p>
                          </div>
                          <div className="rounded-lg border border-gray-100 bg-white p-3">
                            <p className="mb-1 text-xs font-semibold text-gray-500">추출 필드</p>
                            <p className="whitespace-pre-line text-sm leading-relaxed text-gray-700">{detail.fields}</p>
                          </div>
                          <div className="rounded-lg border border-gray-100 bg-white p-3">
                            <p className="mb-1 text-xs font-semibold text-gray-500">처리 로직</p>
                            <p className="whitespace-pre-line text-sm leading-relaxed text-gray-700">{detail.logic}</p>
                          </div>
                          <div className="rounded-lg border border-gray-100 bg-white p-3">
                            <p className="mb-1 text-xs font-semibold text-gray-500">예외 처리</p>
                            <p className="whitespace-pre-line text-sm leading-relaxed text-gray-700">{detail.exceptions}</p>
                          </div>
                          <div className="rounded-lg border border-gray-100 bg-white p-3">
                            <p className="mb-1 text-xs font-semibold text-gray-500">개선 권고</p>
                            <p className="text-sm leading-relaxed text-gray-700">{detail.recommendation}</p>
                          </div>
                        </div>
                      </details>
                    );
                  })}
                </div>
              </section>
            ))}
            {filteredChecklistDetails.length === 0 && (
              <div className="rounded-xl border border-dashed border-gray-200 p-10 text-center text-sm text-gray-500">
                검색 조건에 맞는 체크리스트가 없습니다.
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── 개선 로드맵 (칸반) ── */}
      {activeTab === "improvements" && (
        <div className="space-y-6">
          {/* GAP 요약 */}
          <div className="bg-amber-50 border border-amber-200 rounded-xl p-5">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle className="text-amber-600" size={18} />
              <h2 className="text-amber-900">GAP 분석 요약</h2>
            </div>
            <p className="text-sm text-gray-700">
              현재 평균 성숙도 <strong>{currentAvg.toFixed(2)}</strong>에서 목표 <strong>{targetAvg.toFixed(2)}</strong>으로 향상하기 위한
              {" "}<strong>{improvements.length}개</strong>의 개선 과제가 있습니다.
              Critical {improvements.filter(t => t.priority === "Critical").length}건,
              High {improvements.filter(t => t.priority === "High").length}건,
              Medium {improvements.filter(t => t.priority === "Medium").length}건.
            </p>
          </div>

          {/* 칸반 보드 */}
          <div className="grid grid-cols-1 items-start gap-4 md:grid-cols-3">
            {byTerm.map(({ term, tasks }) => (
              <div key={term} className={`rounded-xl border p-4 ${TERM_COLORS[term]}`}>
                <h3 className={`text-sm font-bold mb-3 ${TERM_HEADER[term]}`}>{TERM_LABELS[term]}</h3>
                <div className="space-y-3">
                  {tasks.length === 0 ? (
                    <p className="text-xs text-gray-400 text-center py-4">과제 없음</p>
                  ) : tasks.map((task, i) => {
                    const meta = getRoadmapMeta(task);

                    return (
                    <div key={i} className="bg-white rounded-lg p-3 border border-gray-200 shadow-sm">
                      <div className="flex items-start justify-between gap-2 mb-2">
                        <p className="text-sm font-medium text-gray-800 leading-snug">{task.task}</p>
                        <span className={`shrink-0 text-xs px-1.5 py-0.5 rounded font-medium ${
                          task.priority === "Critical" ? "bg-red-100 text-red-700" :
                          task.priority === "High"     ? "bg-orange-100 text-orange-700" :
                                                         "bg-gray-100 text-gray-600"
                        }`}>
                          {task.priority}
                        </span>
                      </div>
                      <p className="text-xs text-gray-500">
                        {PILLARS.find((p) => p.key === task.pillar)?.label ?? task.pillar} 필러
                      </p>

                      <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
                        <div className="rounded-lg bg-gray-50 px-2 py-1.5">
                          <span className="block text-gray-400">예상 기간</span>
                          <strong className="text-gray-700">{meta.duration}</strong>
                        </div>
                        <div className="rounded-lg bg-gray-50 px-2 py-1.5">
                          <span className="block text-gray-400">난이도</span>
                          <strong className="text-gray-700">{meta.difficulty}</strong>
                        </div>
                        <div className="rounded-lg bg-gray-50 px-2 py-1.5">
                          <span className="block text-gray-400">담당</span>
                          <strong className="text-gray-700">{meta.owner}</strong>
                        </div>
                        <div className="rounded-lg bg-emerald-50 px-2 py-1.5">
                          <span className="block text-emerald-500">기대 점수</span>
                          <strong className="text-emerald-700">{meta.expectedGain}</strong>
                        </div>
                      </div>

                      <details className="mt-3 rounded-lg border border-gray-100 bg-gray-50 p-2">
                        <summary className="cursor-pointer text-xs font-semibold text-gray-600">
                          실행 계획 보기
                        </summary>
                        <div className="mt-2 space-y-2">
                          <p className="rounded bg-white px-2 py-1.5 text-xs text-gray-600">
                            관련 항목: {meta.relatedItem}
                          </p>
                          <ol className="space-y-1 text-xs text-gray-600">
                            {meta.steps.map((step, stepIndex) => (
                              <li key={step} className="flex gap-2">
                                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-blue-100 text-[11px] font-bold text-blue-700">
                                  {stepIndex + 1}
                                </span>
                                <span className="leading-5">{step}</span>
                              </li>
                            ))}
                          </ol>
                        </div>
                      </details>
                    </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── 보고서 출력 ── */}
      {activeTab === "export" && (
        <div className="space-y-6">
          <div className="bg-white rounded-xl border border-gray-200 p-10 text-center">
            <FileText className="mx-auto text-blue-500 mb-4" size={56} />
            <h2 className="mb-2">보고서 PDF 내보내기</h2>
            <p className="text-gray-500 mb-2">진단 결과 전체를 PDF 문서로 다운로드합니다.</p>
            <p className="text-sm text-gray-400 mb-8">
              표지 · 필러별 점수 · 체크리스트 세부항목 · 개선 권고 순으로 구성됩니다.
            </p>
            <div className="flex justify-center">
              <a
                href={`${API_BASE}/api/report/generate?session_id=${sessionId}&fmt=pdf`}
                download={`zt-report-${sessionId}.pdf`}
                onClick={() => {
                  setPdfDownloading(true);
                  setTimeout(() => setPdfDownloading(false), 3000);
                }}
                className={`px-6 py-3 rounded-lg flex items-center gap-2 font-medium transition-colors ${
                  pdfDownloading
                    ? "bg-gray-300 text-gray-500 pointer-events-none"
                    : "bg-blue-600 text-white hover:bg-blue-700"
                }`}
              >
                <Download size={18} />
                {pdfDownloading ? "생성 중..." : "PDF 다운로드"}
              </a>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
