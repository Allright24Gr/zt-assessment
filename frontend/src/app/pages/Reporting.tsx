import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router";
import { toast } from "sonner";
import {
  createAssessmentShare,
  downloadReportPdf,
  downloadEvidenceRegister,
  downloadDecisionLog,
  listAssessmentShares,
  revokeAssessmentShare,
  getOcsfEvents,
  downloadOcsfJson,
  ApiError,
  type OcsfSessionResponse,
  type OcsfEvent,
} from "../../config/api";
import {
  FileText, Download, TrendingUp, AlertTriangle, AlertCircle, ArrowRight, ChevronDown, RotateCcw,
  Share2, Copy, X, Loader2, Trash2, ShieldAlert, BookOpen,
} from "lucide-react";
import type { AssessmentShareListItem } from "../../types/api";
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
import type { AssessmentResultResponse, ChecklistItemResult, ImprovementItem, EvaluationMeta } from "../../types/api";

import { getStoredTargetScores } from "../lib/settingsStore";

const DEFAULT_SCORES = [2.5, 3.0, 2.0, 2.2, 2.8, 1.5];

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
    unevaluableReasonCode:  item.unevaluable_reason_code,
    unevaluableReasonLabel: item.unevaluable_reason_label,
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

// SKT 가이드 §8 30/60/90일 개선 로드맵 톤에 맞춤. 각 단계에 권장 활동 안내.
const TERM_LABELS: Record<string, string> = {
  단기: "단기 (30일 — quick win)",
  중기: "중기 (60일 — 정착)",
  장기: "장기 (90일 — 운영)",
};
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
// SKT 가이드 §8 — 각 단계별 권장 활동 + 완료 증거.
const TERM_GUIDE_ACTIVITIES: Record<string, { activities: string; evidence: string }> = {
  단기: {
    activities:
      "평가 범위 확정 · 데모/운영 데이터 분리 · 관리자 MFA 강제 · " +
      "Vercel·Railway·Supabase·Notion·Drive 권한 목록 정리 · CORS·보안 헤더 검토",
    evidence: "권한 표, 설정 캡처, deployment id, 보안 헤더 diff",
  },
  중기: {
    activities:
      "API 인증/인가 점검 · Supabase RLS 검증 · Drive/Notion 공유 최소화 · " +
      "secret rotation · dependency/Trivy 스캔 정례화",
    evidence: "테스트 결과, rotation 로그, Trivy/SCA 리포트",
  },
  장기: {
    activities:
      "audit log·보관 기간 정책 확정 · LLM 데이터 처리 정책 문서화 · " +
      "incident runbook 작성 · Readyz-T 재평가 수행",
    evidence: "정책 문서, 로그 샘플, 재평가 점수 비교표",
  },
};

export function Reporting() {
  const { sessionId } = useParams();
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState("overall");
  // Settings 페이지의 사용자 정의 목표치 동기화 (없으면 디폴트)
  const TARGET_SCORES = useMemo(() => getStoredTargetScores(), []);
  const [detailPillarFilter, setDetailPillarFilter] = useState("all");
  const [detailQuestionQuery, setDetailQuestionQuery] = useState("");
  const [selectedRiskCode, setSelectedRiskCode] = useState<string | null>(null);
  const [pdfDownloading, setPdfDownloading] = useState(false);
  // OCSF (Open Cybersecurity Schema Framework) 변환 결과
  const [ocsfData, setOcsfData] = useState<OcsfSessionResponse | null>(null);
  const [ocsfLoading, setOcsfLoading] = useState(false);
  const [ocsfError, setOcsfError] = useState<string | null>(null);
  const [ocsfDownloading, setOcsfDownloading] = useState(false);
  const [ocsfSelectedTool, setOcsfSelectedTool] = useState<string>("all");

  // 공유 링크 모달 (P1-11)
  const [shareOpen, setShareOpen] = useState(false);
  const [shareExpiresDays, setShareExpiresDays] = useState(30);
  const [shareList, setShareList] = useState<AssessmentShareListItem[]>([]);
  const [shareCreating, setShareCreating] = useState(false);
  const [lastShareUrl, setLastShareUrl] = useState<string | null>(null);
  const shareCloseBtnRef = useRef<HTMLButtonElement>(null);

  const fallbackSession: Session = mockSessions.find((s) => s.id === Number(sessionId)) ?? mockSessions[0];
  const [session, setSession] = useState<Session>(fallbackSession);
  const [isDemo, setIsDemo] = useState(false);
  const [usedFallback, setUsedFallback] = useState(false);
  const [currentScores, setCurrentScores] = useState(DEFAULT_SCORES);
  const [checklistDetails, setChecklistDetails] = useState<ChecklistDetail[]>(fallbackSession.checklistDetails);
  const [improvements, setImprovements] = useState<Improvement[]>(mockImprovements);
  // B-3: pillar별 평가불가 카운트 (pillar key 영문 기준)
  const [pillarUnevaluable, setPillarUnevaluable] = useState<Record<string, number>>({});
  // B-3: backend가 보내는 신뢰도 (없으면 checklist에서 직접 계산)
  const [backendConfidence, setBackendConfidence] = useState<number | null>(null);
  const [backendEvaluableCount, setBackendEvaluableCount] = useState<number | null>(null);
  const [backendUnevaluableCount, setBackendUnevaluableCount] = useState<number | null>(null);
  // SKT 가이드 §3 §4 §7 §9 — 평가 메타 (스캔 모드/도구 범위/승인 기록)
  const [evalMeta, setEvalMeta] = useState<EvaluationMeta | null>(null);

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

        // B-3: pillar별 평가불가 (한글 키 → 영문 key)
        const unevalMap: Record<string, number> = {};
        const rawPu = (data as AssessmentResultResponse).pillar_unevaluable ?? {};
        Object.entries(rawPu).forEach(([k, v]) => {
          const mapped = PILLAR_NAME_TO_KEY[k] ?? k;
          unevalMap[mapped] = (unevalMap[mapped] ?? 0) + Number(v ?? 0);
        });
        setPillarUnevaluable(unevalMap);
        setBackendConfidence(
          typeof (data as AssessmentResultResponse).confidence === "number"
            ? Number((data as AssessmentResultResponse).confidence)
            : null,
        );
        setBackendEvaluableCount(
          typeof (data as AssessmentResultResponse).evaluable_items === "number"
            ? Number((data as AssessmentResultResponse).evaluable_items)
            : null,
        );
        setBackendUnevaluableCount(
          typeof (data as AssessmentResultResponse).unevaluable_items === "number"
            ? Number((data as AssessmentResultResponse).unevaluable_items)
            : null,
        );
        setEvalMeta((data as AssessmentResultResponse).evaluation_meta ?? null);
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

  // OCSF — 탭 진입 시 lazy load
  useEffect(() => {
    if (activeTab !== "ocsf" || !sessionId || ocsfData || ocsfLoading) return;
    setOcsfLoading(true);
    setOcsfError(null);
    getOcsfEvents(sessionId)
      .then((data) => setOcsfData(data))
      .catch((err) => {
        console.warn("[reporting] ocsf fetch failed:", err);
        setOcsfError(err instanceof Error ? err.message : "OCSF 이벤트를 불러오지 못했습니다.");
      })
      .finally(() => setOcsfLoading(false));
  }, [activeTab, sessionId, ocsfData, ocsfLoading]);

  // 공유 모달 — ESC 닫기 + 토큰 목록 로드
  useEffect(() => {
    if (!shareOpen || !sessionId) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !shareCreating) setShareOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    const t = window.setTimeout(() => shareCloseBtnRef.current?.focus(), 0);

    listAssessmentShares(sessionId)
      .then((items) => setShareList(items))
      .catch((err) => {
        // 백엔드가 list endpoint 없는 경우도 대응 — 단순화: 무시
        console.warn("[reporting] share list failed:", err);
      });

    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.clearTimeout(t);
    };
  }, [shareOpen, sessionId, shareCreating]);

  const handleCreateShare = async () => {
    if (!sessionId) return;
    setShareCreating(true);
    try {
      const res = await createAssessmentShare(sessionId, shareExpiresDays);
      const url = res.share_url ?? `${window.location.origin}/shared/${res.token}`;
      setLastShareUrl(url);
      toast.success("공유 링크가 발급되었습니다.");
      // 목록 갱신
      listAssessmentShares(sessionId).then((items) => setShareList(items)).catch(() => {});
    } catch (err) {
      console.warn("[reporting] create share:", err);
      if (err instanceof ApiError && err.status === 403) {
        toast.error("공유 권한이 없습니다.");
      } else {
        toast.error("공유 링크 발급에 실패했습니다.");
      }
    } finally {
      setShareCreating(false);
    }
  };

  const handleRevokeShare = async (shareId: number) => {
    if (!sessionId) return;
    try {
      await revokeAssessmentShare(shareId);
      toast.success("공유가 취소되었습니다.");
      setShareList((prev) => prev.filter((s) => s.share_id !== shareId));
    } catch (err) {
      console.warn("[reporting] revoke share:", err);
      toast.error("공유 취소에 실패했습니다.");
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success("링크가 클립보드에 복사되었습니다.");
    } catch {
      toast.error("복사에 실패했습니다. 직접 선택해서 복사해주세요.");
    }
  };

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

  const pillarScores = PILLARS.map((p, i) => {
    const unevalCount = pillarUnevaluable[p.key] ?? 0;
    // backend가 보낸 pillar_unevaluable에 해당 pillar가 있고 currentScores가
    // 0이면 (평가가능 항목 없음 = 측정 불가)로 간주
    const isUnmeasurable = unevalCount > 0 && currentScores[i] === 0;
    return {
      key: p.key,
      name: p.label,
      score: currentScores[i],
      target: TARGET_SCORES[i],
      level: isUnmeasurable ? "평가불가" : getMaturityLevel(currentScores[i]),
      gap: parseFloat((currentScores[i] - TARGET_SCORES[i]).toFixed(1)),
      unevaluable: unevalCount,
      unmeasurable: isUnmeasurable,
    };
  });

  // B-3: 신뢰도 계산 — backend가 보낸 값 우선, 없으면 checklist로 직접 계산
  const confidenceStats = useMemo(() => {
    if (
      backendConfidence !== null &&
      backendEvaluableCount !== null &&
      backendUnevaluableCount !== null
    ) {
      const total = backendEvaluableCount + backendUnevaluableCount;
      return {
        confidence: backendConfidence,
        evaluable: backendEvaluableCount,
        unevaluable: backendUnevaluableCount,
        total,
      };
    }
    const total = checklistDetails.length;
    if (total === 0) return { confidence: 0, evaluable: 0, unevaluable: 0, total: 0 };
    let unevaluable = 0;
    for (const d of checklistDetails) {
      const raw = (d as ChecklistDetail & { rawResult?: string }).rawResult ?? d.result;
      if (raw === "평가불가" || raw === "해당 없음") unevaluable += 1;
    }
    const evaluable = total - unevaluable;
    return { confidence: total > 0 ? evaluable / total : 0, evaluable, unevaluable, total };
  }, [backendConfidence, backendEvaluableCount, backendUnevaluableCount, checklistDetails]);

  const confidencePct = Math.round(confidenceStats.confidence * 100);
  const confidenceColor =
    confidencePct >= 80
      ? { bar: "bg-green-500", text: "text-green-700", bg: "bg-green-50", border: "border-green-200" }
      : confidencePct >= 50
      ? { bar: "bg-yellow-500", text: "text-yellow-700", bg: "bg-yellow-50", border: "border-yellow-200" }
      : { bar: "bg-red-500", text: "text-red-700", bg: "bg-red-50", border: "border-red-200" };

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

  // 자동/자가 비율 — checklistDetails 의 tool / rawResult 를 source 별로 카운트
  const sourceBreakdown = useMemo(() => {
    let autoExternal = 0;  // nmap / trivy
    let autoApi = 0;       // keycloak / wazuh / entra
    let manual = 0;        // 수동
    let unscored = 0;      // tool_unavailable / 평가불가
    for (const d of checklistDetails) {
      const tool = (d.tool ?? "").toLowerCase();
      const raw = (d as ChecklistDetail & { rawResult?: string }).rawResult ?? d.result;
      // 미진단(도구 미설정 또는 평가불가)을 먼저 우선 분류
      if (tool.includes("tool_unavailable") || tool.includes("미설정") || raw === "평가불가") {
        unscored += 1;
        continue;
      }
      if (tool.includes("nmap") || tool.includes("trivy")) {
        autoExternal += 1;
      } else if (tool.includes("keycloak") || tool.includes("wazuh") || tool.includes("entra")) {
        autoApi += 1;
      } else if (tool.includes("수동") || tool.includes("manual")) {
        manual += 1;
      } else {
        // 매핑되지 않은 도구 — 자동 API로 분류 (보수적)
        autoApi += 1;
      }
    }
    return { autoExternal, autoApi, manual, unscored };
  }, [checklistDetails]);
  const totalSourceCount =
    sourceBreakdown.autoExternal + sourceBreakdown.autoApi + sourceBreakdown.manual + sourceBreakdown.unscored;

  return (
    <div className="max-w-screen-2xl mx-auto space-y-6">
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
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShareOpen(true)}
            className="flex items-center gap-2 px-4 py-2 border border-blue-200 text-blue-700 bg-white rounded-lg hover:bg-blue-50"
            title="공유 링크 발급"
          >
            <Share2 size={18} />
            공유
          </button>
          <Link
            to="/new-assessment"
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            <RotateCcw size={20} />
            재진단 시작
          </Link>
        </div>
      </div>

      {/* SKT 가이드 §9 — 평가 목적 안내 */}
      {evalMeta && (
        <div className="rounded-xl border border-emerald-200 bg-emerald-50/40 px-4 py-3 text-xs leading-relaxed text-emerald-900">
          <span className="font-semibold">평가 목적 (SKT 가이드 §9)</span> — 이번 평가는 점수 산출이 아니라
          실제 운영 구조에서 통제가 어디까지 증명되는지 확인하는 작업입니다.
          자동수집 항목과 수동 증적이 분리되어 있고, 자동수집이 안 되는 항목은 평가불가가 아닌
          수동 증적으로 판정되어야 합니다.
        </div>
      )}

      {/* SKT 가이드 §3 §4 §7 §9 — 평가 메타 (스캔 모드 · 도구 범위 · 승인 기록) */}
      {evalMeta && (
        <div className={`rounded-xl border p-4 ${
          evalMeta.scan_mode === "live"
            ? "border-red-200 bg-red-50/40"
            : "border-blue-200 bg-blue-50/40"
        }`}>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <p className="text-sm font-semibold text-gray-800">평가 기준 시점 · 범위</p>
                <span className={`inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-semibold rounded-full ${
                  evalMeta.scan_mode === "live"
                    ? "bg-red-600 text-white"
                    : "bg-blue-600 text-white"
                }`}>
                  {evalMeta.scan_mode === "live" ? "실 스캔" : "데모"}
                </span>
              </div>
              <p className="text-xs text-gray-600 mt-0.5">
                보고서 PDF 첫 장에 동일하게 표기됩니다.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              {(evalMeta.selected_tools || []).map((t) => (
                <span
                  key={`sel-${t}`}
                  className="px-2 py-0.5 text-[11px] rounded bg-green-100 text-green-800 border border-green-200"
                  title="이번 진단에서 수행된 자동 도구"
                >
                  ✓ {t}
                </span>
              ))}
              {(evalMeta.excluded_tools || []).map((t) => (
                <span
                  key={`exc-${t}`}
                  className="px-2 py-0.5 text-[11px] rounded bg-gray-100 text-gray-500 border border-gray-200 line-through"
                  title="이번 진단에서 제외된 도구 (수동 폴백 대상)"
                >
                  {t}
                </span>
              ))}
            </div>
          </div>

          <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-x-4 gap-y-1.5 text-xs">
            <div>
              <span className="text-gray-500">IdP</span>
              <span className="ml-1.5 font-medium text-gray-800">
                {evalMeta.profile_select?.idp_type || "none"}
              </span>
            </div>
            <div>
              <span className="text-gray-500">SIEM</span>
              <span className="ml-1.5 font-medium text-gray-800">
                {evalMeta.profile_select?.siem_type || "none"}
              </span>
            </div>
            {evalMeta.scan_targets?.nmap && (
              <div className="col-span-1 sm:col-span-2">
                <span className="text-gray-500">Nmap 대상</span>
                <span className="ml-1.5 font-mono text-gray-800 break-all">
                  {evalMeta.scan_targets.nmap}
                </span>
              </div>
            )}
            {evalMeta.scan_targets?.trivy && (
              <div className="col-span-1 sm:col-span-2">
                <span className="text-gray-500">Trivy 대상</span>
                <span className="ml-1.5 font-mono text-gray-800 break-all">
                  {evalMeta.scan_targets.trivy}
                </span>
              </div>
            )}
          </div>

          {/* 외부 스캔 승인 기록 — 실 스캔이고 메타가 있을 때만 */}
          {evalMeta.scan_mode === "live" && evalMeta.scan_consent &&
           Object.keys(evalMeta.scan_consent).length > 0 && (
            <div className="mt-3 p-3 rounded-lg border border-yellow-300 bg-yellow-50">
              <p className="text-xs font-semibold text-gray-800 mb-1.5">
                외부 스캔 승인 기록
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 text-xs">
                {evalMeta.scan_consent.approver && (
                  <div>
                    <span className="text-gray-500">승인자</span>
                    <span className="ml-1.5 text-gray-800">{evalMeta.scan_consent.approver}</span>
                  </div>
                )}
                {evalMeta.scan_consent.emergency_contact && (
                  <div>
                    <span className="text-gray-500">비상 연락처</span>
                    <span className="ml-1.5 text-gray-800">{evalMeta.scan_consent.emergency_contact}</span>
                  </div>
                )}
                {evalMeta.scan_consent.scheduled_window && (
                  <div>
                    <span className="text-gray-500">시간대</span>
                    <span className="ml-1.5 text-gray-800">{evalMeta.scan_consent.scheduled_window}</span>
                  </div>
                )}
                {evalMeta.scan_consent.intensity && (
                  <div>
                    <span className="text-gray-500">강도</span>
                    <span className="ml-1.5 text-gray-800">{evalMeta.scan_consent.intensity}</span>
                  </div>
                )}
                {evalMeta.scan_consent.exclude_paths && (
                  <div className="sm:col-span-2">
                    <span className="text-gray-500">제외 경로</span>
                    <span className="ml-1.5 text-gray-800 break-all">{evalMeta.scan_consent.exclude_paths}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* SKT 가이드 §3 평가 착수 전 확정사항 — 버전 / 자산 / 데이터 등급 / 판정자 */}
          {(evalMeta.evaluation_version || evalMeta.evaluation_scope_assets ||
            evalMeta.data_classifications || evalMeta.reviewers) && (
            <details className="mt-3 rounded-lg border border-gray-200 bg-white">
              <summary className="cursor-pointer px-3 py-2 text-xs font-semibold text-gray-700 hover:bg-gray-50">
                평가 착수 전 확정사항 (SKT 가이드 §3)
              </summary>
              <div className="px-3 pb-3 pt-1 space-y-3 text-xs">
                {evalMeta.evaluation_version && Object.keys(evalMeta.evaluation_version).length > 0 && (
                  <div>
                    <p className="font-semibold text-gray-700 mb-1">평가 대상 버전</p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-0.5 text-gray-700">
                      {evalMeta.evaluation_version.version_label && (
                        <div><span className="text-gray-500">라벨</span> <span className="ml-1">{evalMeta.evaluation_version.version_label}</span></div>
                      )}
                      {evalMeta.evaluation_version.git_commit && (
                        <div><span className="text-gray-500">commit</span> <span className="ml-1 font-mono">{evalMeta.evaluation_version.git_commit}</span></div>
                      )}
                      {evalMeta.evaluation_version.frontend_deployment && (
                        <div><span className="text-gray-500">frontend</span> <span className="ml-1">{evalMeta.evaluation_version.frontend_deployment}</span></div>
                      )}
                      {evalMeta.evaluation_version.backend_deployment && (
                        <div><span className="text-gray-500">backend</span> <span className="ml-1">{evalMeta.evaluation_version.backend_deployment}</span></div>
                      )}
                    </div>
                  </div>
                )}
                {evalMeta.evaluation_scope_assets && evalMeta.evaluation_scope_assets.length > 0 && (
                  <div>
                    <p className="font-semibold text-gray-700 mb-1">평가 범위 자산 목록</p>
                    <ul className="space-y-0.5 text-gray-700">
                      {evalMeta.evaluation_scope_assets.map((a, i) => (
                        <li key={i} className="flex items-baseline gap-1.5">
                          <span className={`inline-block w-12 text-[10px] font-semibold ${a.included ? "text-emerald-700" : "text-gray-400 line-through"}`}>
                            {a.included ? "포함" : "제외"}
                          </span>
                          <span className="text-gray-600">{a.name}</span>
                          <span className="ml-1 font-mono text-gray-800 break-all">{a.value}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {evalMeta.data_classifications && evalMeta.data_classifications.length > 0 && (
                  <div>
                    <p className="font-semibold text-gray-700 mb-1">데이터 등급 분류</p>
                    <ul className="space-y-0.5 text-gray-700">
                      {evalMeta.data_classifications.map((d, i) => (
                        <li key={i} className="flex items-baseline gap-1.5">
                          <span className={`inline-block w-12 text-[10px] font-semibold ${
                            d.sensitivity === "높음" ? "text-red-700" :
                            d.sensitivity === "중간" ? "text-amber-700" : "text-gray-500"
                          }`}>
                            {d.sensitivity}
                          </span>
                          <span className="text-gray-700">{d.name}</span>
                          {d.storage_location && (
                            <span className="ml-1 text-gray-500">— {d.storage_location}</span>
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {evalMeta.reviewers && Object.keys(evalMeta.reviewers).length > 0 && (
                  <div>
                    <p className="font-semibold text-gray-700 mb-1">판정자</p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-0.5 text-gray-700">
                      {evalMeta.reviewers.app_owner && <div><span className="text-gray-500">App owner</span> <span className="ml-1">{evalMeta.reviewers.app_owner}</span></div>}
                      {evalMeta.reviewers.backend_owner && <div><span className="text-gray-500">Backend</span> <span className="ml-1">{evalMeta.reviewers.backend_owner}</span></div>}
                      {evalMeta.reviewers.cloud_owner && <div><span className="text-gray-500">Cloud</span> <span className="ml-1">{evalMeta.reviewers.cloud_owner}</span></div>}
                      {evalMeta.reviewers.security_reviewer && <div><span className="text-gray-500">Security</span> <span className="ml-1">{evalMeta.reviewers.security_reviewer}</span></div>}
                    </div>
                  </div>
                )}
              </div>
            </details>
          )}
        </div>
      )}

      {/* 이 진단 결과의 출처 — 자동/자가 비율 배지 */}
      {totalSourceCount > 0 && (
        <div className="bg-white rounded-xl border border-gray-200 p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-semibold text-gray-800">이 진단 결과의 출처</p>
              <p className="text-xs text-gray-500 mt-0.5">
                총 {totalSourceCount}개 체크리스트 — 자동/자가/미진단 비율
              </p>
              {/* B-3: 데이터 신뢰도 mini-graph */}
              <div className="mt-2 flex items-center gap-2 max-w-xs">
                <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden" title="진단 가능 항목 비율">
                  <div
                    className={`h-full rounded-full ${confidenceColor.bar}`}
                    style={{ width: `${confidencePct}%` }}
                  />
                </div>
                <span className={`text-[11px] font-semibold ${confidenceColor.text} tabular-nums`}>
                  신뢰도 {confidencePct}%
                </span>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-700 border border-green-200"
                title="Nmap, Trivy 등 외부 자동 스캔으로 수집한 항목"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                자동 외부 스캔: {sourceBreakdown.autoExternal}건
              </span>
              <span
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-700 border border-green-200"
                title="Keycloak, Wazuh, Entra 등 도구 API로 수집한 항목"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-green-600" />
                자동 API 진단: {sourceBreakdown.autoApi}건
              </span>
              <span
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800 border border-yellow-200"
                title="담당자가 직접 답변·증적을 제출한 항목"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-yellow-500" />
                수동 진단: {sourceBreakdown.manual}건
              </span>
              {sourceBreakdown.unscored > 0 && (
                <span
                  className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-red-100 text-red-700 border border-red-200"
                  title="도구 미설정 또는 평가불가로 점수에 반영되지 않은 항목"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
                  미진단: {sourceBreakdown.unscored}건
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <div className="flex gap-1">
          {[
            { id: "overall", label: "종합 결과" },
            { id: "details", label: "세부 항목" },
            { id: "improvements", label: "개선 로드맵" },
            { id: "ocsf", label: "OCSF 표준" },
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

          {/* B-3: 진단 신뢰도 카드 */}
          <div
            className={`rounded-xl border ${confidenceColor.border} ${confidenceColor.bg} p-5`}
            title="평가불가 항목이 많을수록 진단 신뢰도가 낮아집니다. 미연결 도구 자격을 입력하면 신뢰도가 올라갑니다."
          >
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div className="flex items-center gap-3">
                <ShieldAlert className={confidenceColor.text} size={22} aria-hidden="true" />
                <div>
                  <p className="text-sm font-semibold text-gray-800">진단 신뢰도</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    평가 가능 {confidenceStats.evaluable} / {confidenceStats.total} (평가불가 {confidenceStats.unevaluable})
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3 lg:min-w-[320px]">
                <div className="flex-1 h-3 bg-white rounded-full overflow-hidden border border-gray-200">
                  <div
                    className={`h-full rounded-full ${confidenceColor.bar} transition-all`}
                    style={{ width: `${confidencePct}%` }}
                  />
                </div>
                <span className={`text-lg font-bold ${confidenceColor.text} tabular-nums w-12 text-right`}>
                  {confidencePct}%
                </span>
              </div>
            </div>
            {confidencePct < 80 && (
              <p className="mt-3 text-xs text-gray-600">
                {confidencePct < 50
                  ? "신뢰도가 낮습니다. 미연결 도구의 자격 정보를 입력하거나 수동 진단 항목을 제출하면 점수 신뢰도가 향상됩니다."
                  : "일부 항목이 평가불가 상태입니다. 미연결 도구 자격을 입력하면 신뢰도를 높일 수 있습니다."}
              </p>
            )}
          </div>

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
              // 평가불가 pillar: 회색 카드 + "측정 불가" 표시
              if (pillar.unmeasurable) {
                return (
                  <div
                    key={pillar.key}
                    className="bg-gray-50 rounded-xl border border-dashed border-gray-300 p-5"
                    title="해당 필러는 평가불가 항목만 있어 점수를 측정할 수 없습니다."
                  >
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-sm font-semibold text-gray-500">{pillar.name}</h3>
                      <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-gray-200 text-gray-600">
                        측정 불가
                      </span>
                    </div>
                    <div className="flex items-baseline gap-1 mb-3">
                      <span className="text-3xl font-bold text-gray-400">-</span>
                      <span className="text-gray-300 text-sm">/ 4.0</span>
                    </div>
                    <div className="rounded-lg bg-white border border-gray-200 p-2.5 text-xs text-gray-600">
                      <p className="font-medium mb-0.5">평가불가 {pillar.unevaluable}건</p>
                      <p className="text-gray-500">관련 도구 자격을 입력하면 측정이 가능합니다.</p>
                    </div>
                  </div>
                );
              }
              const colors = getScoreColor(pillar.score);
              const pct = (pillar.score / 4) * 100;
              return (
                <div key={pillar.key} className="bg-white rounded-xl border border-gray-200 p-5">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-sm font-semibold text-gray-700">{pillar.name}</h3>
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${colors.badge}`}>{maturityLabel(pillar.level)}</span>
                  </div>
                  <div className="flex items-baseline gap-1 mb-3">
                    <span className={`text-3xl font-bold ${colors.text}`}>{pillar.score.toFixed(1)}</span>
                    <span className="text-gray-400 text-sm">/ 4.0</span>
                    {pillar.unevaluable > 0 && (
                      <span
                        className="ml-2 text-xs text-gray-500"
                        title="이 필러에서 평가불가 처리된 항목 수"
                      >
                        (평가불가 {pillar.unevaluable})
                      </span>
                    )}
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
                  <div className="flex justify-between text-xs text-gray-500">
                    <span>현재 {pillar.score.toFixed(1)}</span>
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
                              {raw === "평가불가" && (detail.unevaluableReasonLabel || detail.unevaluableReasonCode) && (
                                <span
                                  className="rounded-full bg-amber-100 px-2 py-0.5 text-[11px] font-semibold text-amber-800 border border-amber-200"
                                  title={detail.unevaluableReasonLabel ?? detail.unevaluableReasonCode}
                                >
                                  사유: {detail.unevaluableReasonLabel ?? detail.unevaluableReasonCode}
                                </span>
                              )}
                            </div>
                            <p className="mb-1 text-xs font-semibold text-gray-500">{detail.item} · {maturityLabel(detail.maturity)}</p>
                            <p className="font-medium text-gray-900">{detail.question}</p>
                          </div>
                          <div className="flex shrink-0 items-center gap-4">
                            <div className="text-right">
                              <p className="text-lg font-bold text-blue-600">{detail.score.toFixed(1)}</p>
                              <p className="text-xs text-gray-500">/ 4.0</p>
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
            {byTerm.map(({ term, tasks }) => {
              const guide = TERM_GUIDE_ACTIVITIES[term];
              return (
              <div key={term} className={`rounded-xl border p-4 ${TERM_COLORS[term]}`}>
                <h3 className={`text-sm font-bold mb-2 ${TERM_HEADER[term]}`}>{TERM_LABELS[term]}</h3>
                {/* SKT 가이드 §8 — 각 단계별 권장 활동 안내 */}
                {guide && (
                  <div className="mb-3 rounded-lg border border-white/60 bg-white/70 p-2.5 text-[11px] leading-relaxed">
                    <p className="font-semibold text-gray-700 mb-0.5">SKT 가이드 §8 권장 활동</p>
                    <p className="text-gray-600">{guide.activities}</p>
                    <p className="mt-1 text-gray-500">
                      <span className="font-medium">완료 증거:</span> {guide.evidence}
                    </p>
                  </div>
                )}
                <div className="space-y-3">
                  {tasks.length === 0 ? (
                    <p className="text-xs text-gray-500 text-center py-4">과제 없음</p>
                  ) : tasks.map((task, i) => {
                    const meta = getRoadmapMeta(task);
                    // B-4: 환경 가이드 파싱 — "— 사용자 환경(X) 가이드: ..." 분리
                    const split = (task.task ?? "").split("\n— 사용자 환경(");
                    const mainTask = split[0]?.trim() ?? task.task;
                    const envGuides = split.slice(1).map((seg) => {
                      // "X) 가이드: 내용..." 형식
                      const closeIdx = seg.indexOf(")");
                      const envName = closeIdx >= 0 ? seg.slice(0, closeIdx).trim() : "환경";
                      const rest = closeIdx >= 0 ? seg.slice(closeIdx + 1) : seg;
                      const guideContent = rest.replace(/^[\s)]*가이드\s*:\s*/, "").trim();
                      return { envName, content: guideContent };
                    });

                    return (
                    <div key={i} className="bg-white rounded-lg p-3 border border-gray-200 shadow-sm">
                      <div className="flex items-start justify-between gap-2 mb-2">
                        <p className="text-sm font-medium text-gray-800 leading-snug">{mainTask}</p>
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

                      {/* B-4: 환경별 맞춤 가이드 */}
                      {envGuides.length > 0 && (
                        <div className="mt-3 space-y-2">
                          {envGuides.map((g, gi) => (
                            <div
                              key={gi}
                              className="rounded-lg border border-blue-200 bg-blue-50/60 p-2.5"
                            >
                              <div className="mb-1 flex items-center gap-1.5">
                                <BookOpen size={12} className="text-blue-600" />
                                <span className="text-[11px] font-semibold text-blue-700 inline-block px-1.5 py-0.5 rounded bg-white border border-blue-200">
                                  {g.envName} 가이드
                                </span>
                              </div>
                              <p className="text-xs leading-relaxed text-gray-700 whitespace-pre-line">
                                {g.content}
                              </p>
                            </div>
                          ))}
                        </div>
                      )}

                      <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
                        <div className="rounded-lg bg-gray-50 px-2 py-1.5">
                          <span className="block text-gray-600">예상 기간</span>
                          <strong className="text-gray-700">{meta.duration}</strong>
                        </div>
                        <div className="rounded-lg bg-gray-50 px-2 py-1.5">
                          <span className="block text-gray-600">난이도</span>
                          <strong className="text-gray-700">{meta.difficulty}</strong>
                        </div>
                        <div className="rounded-lg bg-gray-50 px-2 py-1.5">
                          <span className="block text-gray-600">담당</span>
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
              );
            })}
          </div>
        </div>
      )}

      {/* ── OCSF 표준 ── */}
      {activeTab === "ocsf" && (
        <div className="space-y-6">
          <div className="bg-white rounded-xl border border-gray-200 p-6">
            <div className="flex items-start justify-between gap-4 mb-4">
              <div>
                <h2 className="mb-1 flex items-center gap-2">
                  <BookOpen className="text-indigo-600" size={20} />
                  OCSF (Open Cybersecurity Schema Framework) {ocsfData?.ocsf_version ?? "1.1.0"}
                </h2>
                <p className="text-sm text-gray-600">
                  수집된 도구별 raw 데이터를 OCSF 표준 이벤트 형식으로 변환해 보여줍니다.
                  AWS·Splunk·IBM·Cloudflare 등 18+ 보안 벤더 공동 표준 (OASIS).
                </p>
                <p className="text-xs text-gray-500 mt-1">
                  매핑: Keycloak → IAM/Authentication (3002) · Wazuh → Findings/Detection Finding (2004)
                  · Nmap → Network Activity (4001) · Trivy → Vulnerability Finding (2002)
                </p>
              </div>
              <button
                type="button"
                onClick={async () => {
                  if (!sessionId || ocsfDownloading) return;
                  setOcsfDownloading(true);
                  try {
                    await downloadOcsfJson(sessionId);
                    toast.success("OCSF JSON 다운로드가 시작되었습니다.");
                  } catch (err) {
                    console.warn("[reporting] ocsf download:", err);
                    toast.error("OCSF JSON 다운로드에 실패했습니다.");
                  } finally {
                    setOcsfDownloading(false);
                  }
                }}
                disabled={!ocsfData || ocsfDownloading}
                className="inline-flex shrink-0 items-center gap-2 rounded-lg bg-indigo-600 text-white px-4 py-2 text-sm font-medium hover:bg-indigo-700 disabled:opacity-50"
              >
                {ocsfDownloading ? <Loader2 size={16} className="animate-spin" /> : <Download size={16} />}
                JSON 다운로드
              </button>
            </div>

            {ocsfLoading && (
              <div className="flex items-center justify-center py-10 text-gray-500 text-sm">
                <Loader2 size={18} className="animate-spin mr-2" />
                OCSF 이벤트 변환 중...
              </div>
            )}

            {ocsfError && (
              <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-700">
                {ocsfError}
              </div>
            )}

            {ocsfData && !ocsfLoading && (
              <>
                {/* 분포 요약 */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
                  <div className="rounded-lg border border-gray-200 p-3">
                    <p className="text-xs text-gray-500">전체 이벤트</p>
                    <p className="text-2xl font-bold text-indigo-600">{ocsfData.event_count}</p>
                  </div>
                  {Object.entries(ocsfData.by_severity).map(([sev, n]) => (
                    <div key={sev} className="rounded-lg border border-gray-200 p-3">
                      <p className="text-xs text-gray-500">{sev}</p>
                      <p className="text-2xl font-bold text-gray-900">{n}</p>
                    </div>
                  ))}
                </div>

                {/* 카테고리별 카운트 */}
                <div className="flex flex-wrap gap-2 mb-5">
                  {Object.entries(ocsfData.by_category).map(([cat, n]) => (
                    <span
                      key={cat}
                      className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-indigo-100 text-indigo-700 border border-indigo-200"
                    >
                      {cat}: {n}
                    </span>
                  ))}
                </div>

                {/* 도구 필터 */}
                <div className="flex gap-2 mb-3">
                  {["all", "keycloak", "wazuh", "nmap", "trivy"].map((t) => (
                    <button
                      key={t}
                      type="button"
                      onClick={() => setOcsfSelectedTool(t)}
                      className={`px-3 py-1 rounded-md text-xs font-medium border ${
                        ocsfSelectedTool === t
                          ? "bg-indigo-600 text-white border-indigo-600"
                          : "bg-white text-gray-600 border-gray-300 hover:bg-gray-50"
                      }`}
                    >
                      {t === "all" ? "전체" : t}
                    </button>
                  ))}
                </div>

                {/* 이벤트 미리보기 (상위 5개) */}
                <div className="space-y-2 max-h-[560px] overflow-y-auto">
                  {(() => {
                    const filtered = ocsfData.events.filter(
                      (e: OcsfEvent) =>
                        ocsfSelectedTool === "all" ||
                        e.metadata.product.name.toLowerCase() === ocsfSelectedTool,
                    );
                    if (filtered.length === 0) {
                      return (
                        <p className="text-sm text-gray-500 text-center py-8">
                          해당 도구의 이벤트가 없습니다.
                        </p>
                      );
                    }
                    return filtered.slice(0, 25).map((ev, idx) => (
                      <details
                        key={`${ev.class_uid}-${idx}`}
                        className="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2 group"
                      >
                        <summary className="cursor-pointer text-xs font-mono text-gray-700 flex items-center justify-between gap-2">
                          <span className="truncate">
                            <span className="inline-block px-1.5 py-0.5 mr-2 rounded bg-indigo-100 text-indigo-700 font-semibold">
                              {ev.class_uid}
                            </span>
                            <span className="font-semibold text-gray-900">{ev.class_name}</span>
                            <span className="text-gray-400 mx-1">·</span>
                            {ev.metadata.product.name}
                            <span className="text-gray-400 mx-1">·</span>
                            {ev.severity}
                            <span className="text-gray-400 mx-1">·</span>
                            {ev.status}
                          </span>
                          <ChevronDown size={14} className="text-gray-400 transition-transform group-open:rotate-180" />
                        </summary>
                        <pre className="mt-2 text-[10px] leading-relaxed text-gray-700 overflow-x-auto bg-white border border-gray-200 rounded p-2">
                          {JSON.stringify(ev, null, 2)}
                        </pre>
                      </details>
                    ));
                  })()}
                  {ocsfData.events.length > 25 && (
                    <p className="text-xs text-center text-gray-500 pt-2">
                      상위 25개만 표시 · 전체 {ocsfData.event_count}개는 JSON 다운로드로 확인
                    </p>
                  )}
                </div>
              </>
            )}
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
            <p className="text-sm text-gray-500 mb-8">
              표지(평가 메타·승인 기록) · 필러별 점수 · 체크리스트 세부항목 · 개선 권고 순으로 구성됩니다.
            </p>
            <div className="flex justify-center">
              <button
                type="button"
                onClick={async () => {
                  if (!sessionId || pdfDownloading) return;
                  setPdfDownloading(true);
                  try {
                    await downloadReportPdf(sessionId);
                    toast.success("PDF 다운로드가 시작되었습니다.");
                  } catch (err) {
                    const status = err instanceof ApiError ? err.status : 0;
                    if (status === 401) toast.error("로그인이 필요합니다. 다시 로그인해주세요.");
                    else if (status === 403) toast.error("PDF 다운로드 권한이 없습니다.");
                    else if (status === 404) toast.error("세션을 찾을 수 없습니다.");
                    else toast.error("PDF 생성에 실패했습니다.");
                  } finally {
                    setPdfDownloading(false);
                  }
                }}
                disabled={pdfDownloading || !sessionId}
                className={`px-6 py-3 rounded-lg flex items-center gap-2 font-medium transition-colors ${
                  pdfDownloading || !sessionId
                    ? "bg-gray-300 text-gray-500 cursor-not-allowed"
                    : "bg-blue-600 text-white hover:bg-blue-700"
                }`}
              >
                <Download size={18} />
                {pdfDownloading ? "생성 중..." : "PDF 다운로드"}
              </button>
            </div>
          </div>

          {/* 증적 목록 xlsx — 가이드 §7 산출물 evidence_register.xlsx */}
          <div className="bg-white rounded-xl border border-gray-200 p-8">
            <div className="flex items-start gap-4">
              <FileText className="text-emerald-500 shrink-0 mt-1" size={36} />
              <div className="flex-1 min-w-0">
                <h3 className="text-base font-semibold text-gray-800">증적 목록 (Excel)</h3>
                <p className="text-sm text-gray-500 mt-1">
                  자동 수집(CollectedData) + 수동 등록 증적(Evidence) 을 한 xlsx 로 정리.
                  항목별 결과 · 출처 · 파일명 · 위치 · 관찰 내용 · 수집 시각 18개 컬럼.
                </p>
                <p className="text-xs text-gray-400 mt-1">
                  SKT 가이드 §7 산출물 패키지 — <code>evidence_register.xlsx</code>
                </p>
              </div>
              <button
                type="button"
                onClick={async () => {
                  if (!sessionId) return;
                  try {
                    await downloadEvidenceRegister(sessionId);
                    toast.success("증적 목록 다운로드가 시작되었습니다.");
                  } catch (err) {
                    const status = err instanceof ApiError ? err.status : 0;
                    if (status === 401) toast.error("로그인이 필요합니다.");
                    else if (status === 403) toast.error("다운로드 권한이 없습니다.");
                    else if (status === 404) toast.error("세션을 찾을 수 없습니다.");
                    else toast.error("증적 목록 생성에 실패했습니다.");
                  }
                }}
                disabled={!sessionId}
                className="shrink-0 px-5 py-2.5 rounded-lg flex items-center gap-2 text-sm font-medium bg-emerald-600 text-white hover:bg-emerald-700 disabled:bg-gray-300 disabled:cursor-not-allowed"
              >
                <Download size={16} />
                xlsx 다운로드
              </button>
            </div>
          </div>

          {/* 판정 로그 markdown — 가이드 §7 산출물 decision_log.md */}
          <div className="bg-white rounded-xl border border-gray-200 p-8">
            <div className="flex items-start gap-4">
              <FileText className="text-purple-500 shrink-0 mt-1" size={36} />
              <div className="flex-1 min-w-0">
                <h3 className="text-base font-semibold text-gray-800">판정 로그 (Markdown)</h3>
                <p className="text-sm text-gray-500 mt-1">
                  부분충족·평가불가 항목의 판정 근거(자동 지표·평가불가 사유·관찰 내용)와
                  리뷰어 의견 빈 칸을 묶은 검토용 문서. PR/Notion 첨부에 적합한 .md 형식.
                </p>
                <p className="text-xs text-gray-400 mt-1">
                  SKT 가이드 §7 산출물 패키지 — <code>decision_log.md</code>
                </p>
              </div>
              <button
                type="button"
                onClick={async () => {
                  if (!sessionId) return;
                  try {
                    await downloadDecisionLog(sessionId);
                    toast.success("판정 로그 다운로드가 시작되었습니다.");
                  } catch (err) {
                    const status = err instanceof ApiError ? err.status : 0;
                    if (status === 401) toast.error("로그인이 필요합니다.");
                    else if (status === 403) toast.error("다운로드 권한이 없습니다.");
                    else if (status === 404) toast.error("세션을 찾을 수 없습니다.");
                    else toast.error("판정 로그 생성에 실패했습니다.");
                  }
                }}
                disabled={!sessionId}
                className="shrink-0 px-5 py-2.5 rounded-lg flex items-center gap-2 text-sm font-medium bg-purple-600 text-white hover:bg-purple-700 disabled:bg-gray-300 disabled:cursor-not-allowed"
              >
                <Download size={16} />
                md 다운로드
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 공유 링크 모달 (P1-11) */}
      {shareOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4"
          onClick={() => !shareCreating && setShareOpen(false)}
          aria-hidden="true"
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="share-modal-title"
            className="relative bg-white rounded-xl shadow-2xl w-full max-w-md p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              type="button"
              onClick={() => !shareCreating && setShareOpen(false)}
              className="absolute top-3 right-3 text-gray-400 hover:text-gray-600"
              aria-label="닫기"
              ref={shareCloseBtnRef}
            >
              <X size={18} />
            </button>
            <div className="flex items-center gap-2 mb-3">
              <Share2 size={18} className="text-blue-600" aria-hidden="true" />
              <h2 id="share-modal-title" className="text-base font-semibold text-gray-900">
                결과 공유 링크
              </h2>
            </div>
            <p className="text-xs text-gray-500 mb-4 leading-relaxed">
              읽기 전용 공유 링크를 발급합니다. 만료 후에는 자동으로 비활성화되며,
              언제든지 수동 취소할 수 있습니다.
            </p>

            <div className="mb-4">
              <label className="block text-xs text-gray-700 mb-1.5">만료 기간</label>
              <div className="grid grid-cols-3 gap-2">
                {[7, 30, 90].map((d) => (
                  <button
                    key={d}
                    type="button"
                    onClick={() => setShareExpiresDays(d)}
                    className={`px-3 py-2 rounded-lg text-sm font-medium border ${
                      shareExpiresDays === d
                        ? "border-blue-500 bg-blue-50 text-blue-700"
                        : "border-gray-200 bg-white text-gray-600 hover:bg-gray-50"
                    }`}
                  >
                    {d}일
                  </button>
                ))}
              </div>
            </div>

            <button
              type="button"
              onClick={handleCreateShare}
              disabled={shareCreating}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {shareCreating ? (
                <><Loader2 size={14} className="animate-spin" /> 발급 중...</>
              ) : (
                <><Share2 size={14} /> 새 공유 링크 발급</>
              )}
            </button>

            {lastShareUrl && (
              <div className="mt-4 p-3 bg-green-50 border border-green-200 rounded-lg">
                <p className="text-xs font-semibold text-green-800 mb-2">발급된 링크</p>
                <div className="flex items-center gap-2 bg-white rounded border border-green-200 px-2 py-1.5">
                  <code className="text-xs text-gray-700 truncate flex-1">{lastShareUrl}</code>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(lastShareUrl)}
                    className="shrink-0 p-1 text-gray-500 hover:text-blue-600"
                    title="복사"
                  >
                    <Copy size={14} />
                  </button>
                </div>
              </div>
            )}

            {shareList.length > 0 && (
              <div className="mt-5 border-t border-gray-100 pt-4">
                <p className="text-xs font-semibold text-gray-700 mb-2">
                  활성 공유 링크 ({shareList.length}개)
                </p>
                <ul className="space-y-1.5 max-h-40 overflow-y-auto">
                  {shareList.map((s) => {
                    const url = `${window.location.origin}/shared/${s.token}`;
                    const expired = new Date(s.expires_at).getTime() < Date.now();
                    return (
                      <li
                        key={s.share_id}
                        className={`flex items-center gap-2 px-2 py-1.5 rounded border ${
                          expired || s.revoked
                            ? "border-gray-200 bg-gray-50 opacity-60"
                            : "border-gray-200 bg-white"
                        }`}
                      >
                        <div className="min-w-0 flex-1">
                          <p className="text-[11px] font-mono text-gray-600 truncate">{s.token}</p>
                          <p className="text-[10px] text-gray-400">
                            만료: {new Date(s.expires_at).toLocaleDateString("ko-KR")}
                            {expired && <span className="ml-1 text-red-500">(만료됨)</span>}
                            {s.revoked && <span className="ml-1 text-gray-500">(취소됨)</span>}
                          </p>
                        </div>
                        {!expired && !s.revoked && (
                          <>
                            <button
                              type="button"
                              onClick={() => copyToClipboard(url)}
                              className="shrink-0 p-1 text-gray-500 hover:text-blue-600"
                              title="복사"
                            >
                              <Copy size={12} />
                            </button>
                            <button
                              type="button"
                              onClick={() => handleRevokeShare(s.share_id)}
                              className="shrink-0 p-1 text-gray-500 hover:text-red-600"
                              title="취소"
                            >
                              <Trash2 size={12} />
                            </button>
                          </>
                        )}
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
