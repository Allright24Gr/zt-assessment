import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router";
import { toast } from "sonner";
import {
  AlertTriangle,
  ArrowRight,
  Calendar,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  FileCheck,
  KeyRound,
  Minus,
  Target,
  TrendingUp,
  X,
} from "lucide-react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
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
import { useAuth } from "../context/AuthContext";
import { improvements, sessions } from "../data/mockData";
import { PILLARS } from "../data/constants";
import { MATURITY_STEPS, getMaturityLevel, getScoreColor, maturityLabel } from "../lib/maturity";
import {
  getAssessmentHistory,
  getImprovement,
  getScoreSummary,
  getScoreTrend,
} from "../../config/api";
import type { AssessmentSession, ImprovementItem, ScoreTrendPoint } from "../../types/api";
import { pillarMatchesKey } from "../lib/pillar";

const DEFAULT_PILLAR_SCORES = [2.5, 3.0, 2.0, 2.2, 2.8, 1.5];
const TARGET_SCORES = [3.5, 3.5, 3.0, 3.5, 3.5, 3.0];

export function Dashboard() {
  const { user } = useAuth();
  const navigate = useNavigate();

  // 시드 비번 사용 경고 배너 (작업 N) — 닫기 버튼은 표시만 닫고 sessionStorage는 유지
  const [seedPwBannerVisible, setSeedPwBannerVisible] = useState(() => {
    try {
      return sessionStorage.getItem("zt_seed_password_warning") === "true";
    } catch {
      return false;
    }
  });
  const [seedPwBannerDismissed, setSeedPwBannerDismissed] = useState(false);

  const [pillarScores, setPillarScores] = useState(DEFAULT_PILLAR_SCORES);
  const [avgScore, setAvgScore] = useState(
    Number((DEFAULT_PILLAR_SCORES.reduce((a, b) => a + b, 0) / DEFAULT_PILLAR_SCORES.length).toFixed(2))
  );
  const [prevScore, setPrevScore] = useState<number | null>(null);
  const [apiSessions, setApiSessions] = useState<AssessmentSession[] | null>(null);
  const [apiTopTasks, setApiTopTasks] = useState<ImprovementItem[] | null>(null);
  const [trendPoints, setTrendPoints] = useState<ScoreTrendPoint[] | null>(null);

  useEffect(() => {
    const orgFilter = user?.role === "user" ? user.orgName : undefined;

    getAssessmentHistory(orgFilter)
      .then((data) => {
        setApiSessions(data.sessions);
        const latestCompleted = data.sessions.find((s) => s.status === "완료");
        if (!latestCompleted) return;

        getScoreSummary(latestCompleted.id)
          .then((summary) => {
            const scores = PILLARS.map((p, i) => {
              const match = summary.pillar_scores.find((ps) =>
                pillarMatchesKey(ps.pillar, p.key)
              );
              return match ? match.score : DEFAULT_PILLAR_SCORES[i];
            });
            setPillarScores(scores);
            setAvgScore(summary.overall_score);
          })
          .catch((err) => console.warn("[dashboard] score summary:", err));

        // 같은 조직의 score trend 가져오기 (백엔드 /history가 org_id 포함)
        const orgId = data.sessions[0]?.org_id;
        if (orgId !== undefined) {
          getScoreTrend(orgId)
            .then(setTrendPoints)
            .catch((err) => console.warn("[dashboard] score trend:", err));
        }
      })
      .catch((err) => {
        console.warn("[dashboard] history fetch failed:", err);
        toast.error("진단 이력을 불러오지 못했습니다.");
      });

    getImprovement()
      .then((data) => setApiTopTasks(data.items))
      .catch((err) => console.warn("[dashboard] improvement:", err));
  }, [user?.role, user?.orgName]);

  // 완료된 세션에서 직전 점수 추출 → 트렌드 표시
  useEffect(() => {
    if (!apiSessions) return;
    const completed = apiSessions
      .filter((s) => s.status === "완료" && s.score !== null)
      .sort((a, b) => (a.date < b.date ? 1 : -1));
    if (completed.length >= 2 && typeof completed[1].score === "number") {
      setPrevScore(completed[1].score);
    }
  }, [apiSessions]);

  const TREND = prevScore !== null ? avgScore - prevScore : 0;

  const weakestPillar = PILLARS
    .map((p, i) => ({ ...p, score: pillarScores[i] }))
    .sort((a, b) => a.score - b.score)[0];

  const topTasks = apiTopTasks ? apiTopTasks.slice(0, 3) : improvements.slice(0, 3);

  const recentSessions: AssessmentSession[] = useMemo(() => {
    if (apiSessions) {
      // 이미 백엔드에서 org_name 기준 필터링됨 (role=user인 경우)
      return user?.role === "admin"
        ? apiSessions.slice(0, 5)
        : apiSessions.slice(0, 3);
    }
    // API 실패 시 mockSessions fallback (orgName 기준 매칭)
    const filtered = user?.role === "admin"
      ? sessions.slice(0, 5)
      : sessions.filter((s) => s.org === user?.orgName).slice(0, 3);
    return filtered.map((s) => ({
      id: s.id, org: s.org, date: s.date, manager: s.manager,
      user_id: s.userId, level: s.level, status: s.status,
      score: s.score, errors: s.errors,
    }));
  }, [apiSessions, user?.role, user?.orgName]);

  const radarData = PILLARS.map((p, i) => ({
    pillar: p.shortLabel,
    current: pillarScores[i],
    target: TARGET_SCORES[i],
  }));

  const targetAvg = Number((TARGET_SCORES.reduce((a, b) => a + b, 0) / TARGET_SCORES.length).toFixed(2));

  // 실제 trend API 응답이 있으면 사용, 없으면 history의 완료 세션으로 구성
  const trendData = useMemo(() => {
    const points = trendPoints && trendPoints.length > 0
      ? trendPoints.map((p) => ({
          date: (p.assessed_at ?? "").slice(0, 10),
          level: p.total_score,
        }))
      : (apiSessions ?? [])
          .filter((s) => s.status === "완료" && typeof s.score === "number")
          .slice()
          .reverse()
          .map((s) => ({ date: s.date.slice(0, 10), level: s.score as number }));
    return points.length > 0 ? points : [{ date: "현재", level: avgScore }];
  }, [trendPoints, apiSessions, avgScore]);

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <h1>Dashboard</h1>
        {user?.role === "admin" && (
          <span className="px-4 py-2 bg-blue-100 text-blue-700 rounded-lg text-sm font-medium">관리자 모드</span>
        )}
      </div>

      {/* 시드 비번 사용 경고 배너 (작업 N) */}
      {seedPwBannerVisible && !seedPwBannerDismissed && (
        <div
          role="alert"
          className="flex items-start gap-3 p-4 rounded-xl border border-amber-300 bg-amber-50 text-amber-900"
        >
          <AlertTriangle size={18} className="mt-0.5 shrink-0 text-amber-600" />
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold">기본 비밀번호를 사용 중입니다.</p>
            <p className="text-xs mt-0.5 text-amber-800">
              보안을 위해 Settings에서 비밀번호를 변경하세요.
            </p>
          </div>
          <button
            type="button"
            onClick={() =>
              navigate("/settings", { state: { openPasswordModal: true } })
            }
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-600 text-white text-xs font-medium hover:bg-amber-700"
          >
            <KeyRound size={14} />
            지금 변경
          </button>
          <button
            type="button"
            onClick={() => setSeedPwBannerDismissed(true)}
            className="text-amber-600 hover:text-amber-800 p-1"
            aria-label="배너 닫기"
            title="배너 닫기"
          >
            <X size={16} />
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-gradient-to-br from-blue-600 to-blue-700 text-white rounded-xl p-5 flex flex-col justify-between">
          <p className="text-blue-200 text-sm">종합 성숙도 점수</p>
          <div>
            <p className="text-5xl font-bold mt-2">{avgScore}</p>
            <p className="text-blue-200 text-sm mt-1">/ 4.0</p>
          </div>
          <div className="flex items-center gap-1 mt-3">
            {TREND > 0 ? (
              <>
                <ChevronUp size={16} className="text-green-300" />
                <span className="text-green-300 text-sm">+{TREND.toFixed(2)} 이전 대비</span>
              </>
            ) : TREND < 0 ? (
              <>
                <ChevronDown size={16} className="text-red-300" />
                <span className="text-red-300 text-sm">{TREND.toFixed(2)} 이전 대비</span>
              </>
            ) : (
              <>
                <Minus size={16} className="text-blue-200" />
                <span className="text-blue-200 text-sm">변화 없음</span>
              </>
            )}
          </div>
        </div>

        <div className="bg-white border border-gray-200 rounded-xl p-5">
          <p className="text-gray-500 text-sm mb-3">성숙도 단계</p>
          <p className="text-2xl font-bold text-gray-900 mb-4">{maturityLabel(getMaturityLevel(avgScore))}</p>
          <div className="space-y-1.5">
            {MATURITY_STEPS.map((step) => {
              const current = getMaturityLevel(avgScore) === step;
              return (
                <div key={step} className={`flex items-center gap-2 px-2 py-1 rounded ${current ? "bg-blue-50" : ""}`}>
                  <div className={`w-2 h-2 rounded-full ${current ? "bg-blue-500" : "bg-gray-200"}`} />
                  <span className={`text-xs ${current ? "text-blue-700 font-semibold" : "text-gray-400"}`}>{maturityLabel(step)}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="bg-red-50 border border-red-200 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle size={16} className="text-red-500" />
            <p className="text-red-600 text-sm font-medium">점수 낮은 영역</p>
          </div>
          <p className="text-lg font-bold text-red-700 mb-1">{weakestPillar.label}</p>
          <p className="text-3xl font-bold text-red-600 mb-3">
            {weakestPillar.score} <span className="text-sm font-normal text-red-400">/ 4.0</span>
          </p>
          <div className="w-full bg-red-100 rounded-full h-2">
            <div className="bg-red-500 h-2 rounded-full" style={{ width: `${(weakestPillar.score / 4) * 100}%` }} />
          </div>
          <p className="text-xs text-red-500 mt-2">즉각적인 개선이 필요합니다.</p>
        </div>

        <div className="bg-white border border-gray-200 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <CheckCircle2 size={16} className="text-blue-500" />
            <p className="text-gray-600 text-sm font-medium">우선 개선 과제</p>
          </div>
          <div className="space-y-2">
            {topTasks.map((task, i) => (
              <div key={task.task} className="flex items-start gap-2">
                <span className={`mt-0.5 shrink-0 w-4 h-4 rounded-full flex items-center justify-center text-xs text-white font-bold ${
                  task.priority === "Critical" ? "bg-red-500" : "bg-orange-400"
                }`}>{i + 1}</span>
                <p className="text-xs text-gray-700 leading-relaxed">{task.task}</p>
              </div>
            ))}
          </div>
          <Link to="/reporting" className="block mt-3 text-xs text-blue-600 hover:underline">전체 보기</Link>
        </div>
      </div>

      {user?.role === "user" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Link
            to="/new-assessment"
            className="bg-blue-600 text-white p-6 rounded-xl hover:bg-blue-700 transition-colors flex items-center justify-between"
          >
            <div>
              <h3>새 진단 시작</h3>
              <p className="text-sm text-blue-100 mt-1">새로운 성숙도 진단을 시작합니다.</p>
            </div>
            <ArrowRight size={24} />
          </Link>
          <Link
            to="/in-progress"
            className="bg-white border-2 border-gray-200 p-6 rounded-xl hover:border-blue-300 transition-colors flex items-center justify-between"
          >
            <div className="text-left">
              <h3>마지막 진단 이어보기</h3>
              <p className="text-sm text-gray-500 mt-1">진행 중인 진단을 계속합니다.</p>
            </div>
            <ArrowRight size={24} className="text-gray-400" />
          </Link>
        </div>
      )}

      <div className="bg-white rounded-xl border border-gray-200 p-6">
        <h2 className="mb-4">필러별 성숙도 현황</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-10 gap-y-4">
          {PILLARS.map((p, i) => {
            const score = pillarScores[i];
            const colors = getScoreColor(score);
            const pct = (score / 4) * 100;
            return (
              <div key={p.key}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm text-gray-700">{p.label}</span>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${colors.badge}`}>{maturityLabel(getMaturityLevel(score))}</span>
                    <span className={`text-sm font-semibold ${colors.text}`}>{score}</span>
                  </div>
                </div>
                <div className="w-full bg-gray-100 rounded-full h-2">
                  <div className={`${colors.bar} h-2 rounded-full transition-all`} style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[1fr_0.9fr] gap-6">
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <TrendingUp className="text-blue-600" size={20} />
              <h2>성숙도 레이더 차트</h2>
            </div>
            <div className="flex items-center gap-2 text-sm text-emerald-600 font-semibold">
              <Target size={16} />
              목표 평균 {targetAvg}
            </div>
          </div>
          <ResponsiveContainer width="100%" height={320}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#e5e7eb" />
              <PolarAngleAxis dataKey="pillar" stroke="#6b7280" tick={{ fontSize: 12 }} />
              <PolarRadiusAxis angle={90} domain={[0, 4]} tick={false} axisLine={false} />
              <Radar name="현재" dataKey="current" stroke="#2563eb" fill="#3b82f6" fillOpacity={0.4} strokeWidth={2} />
              <Radar name="목표" dataKey="target" stroke="#10b981" fill="#10b981" fillOpacity={0.16} strokeDasharray="5 4" strokeWidth={2} />
              <Legend />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <div className="flex items-center gap-2 mb-2">
            <Target className="text-emerald-600" size={20} />
            <h2>필러별 목표 대비 현황</h2>
          </div>
          <p className="text-sm text-gray-500 mb-5">현재 점수와 목표 점수의 차이를 필러별로 확인합니다. 목표값 변경은 설정에서 관리합니다.</p>
          <div className="space-y-3">
            {PILLARS.map((pillar, index) => {
              const current = pillarScores[index];
              const target = TARGET_SCORES[index];
              const gap = Number((current - target).toFixed(1));
              const colors = getScoreColor(current);

              return (
              <div key={pillar.key} className="rounded-lg border border-gray-100 bg-gray-50 p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-700">{pillar.label}</span>
                  <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${gap < 0 ? "bg-red-100 text-red-700" : "bg-emerald-100 text-emerald-700"}`}>
                    GAP {gap > 0 ? `+${gap.toFixed(1)}` : gap.toFixed(1)}
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2 mb-2">
                  <div className={`${colors.bar} h-2 rounded-full transition-all`} style={{ width: `${(current / 4) * 100}%` }} />
                </div>
                <div className="flex justify-between text-[11px] text-gray-500">
                  <span>현재 {current.toFixed(1)}</span>
                  <span className="font-semibold text-emerald-600">목표 {target.toFixed(1)}</span>
                </div>
              </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <div className="flex items-center gap-2 mb-4">
            <Calendar className="text-blue-600" size={20} />
            <h2>성숙도 추이</h2>
          </div>
          <ResponsiveContainer width="100%" height={280}>
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis dataKey="date" stroke="#6b7280" tick={{ fontSize: 12 }} />
              <YAxis domain={[0, 4]} stroke="#6b7280" tick={{ fontSize: 12 }} />
              <Tooltip
                contentStyle={{ borderRadius: 8, border: "1px solid #e5e7eb" }}
                formatter={(v: number) => [`${v}`, "성숙도 점수"]}
              />
              <Line type="monotone" dataKey="level" stroke="#2563eb" strokeWidth={2.5} dot={{ r: 5, fill: "#2563eb" }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <FileCheck className="text-blue-600" size={20} />
              <h2>최근 진단 세션</h2>
            </div>
            <Link to="/history" className="text-sm text-blue-600 hover:underline">전체 보기</Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 text-left">
                  <th className="pb-3 px-4 text-sm font-medium text-gray-500">기관명</th>
                  <th className="pb-3 px-4 text-sm font-medium text-gray-500">담당자</th>
                  <th className="pb-3 px-4 text-sm font-medium text-gray-500">진단 날짜</th>
                  <th className="pb-3 px-4 text-sm font-medium text-gray-500">성숙도</th>
                </tr>
              </thead>
              <tbody>
                {recentSessions.map((session) => (
                  <tr key={session.id} className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-3 px-4 font-medium">
                      <span className="inline-flex items-center gap-1.5">
                        {session.org}
                        {session.is_demo && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-100 text-amber-800 border border-amber-200">
                            데모
                          </span>
                        )}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-gray-600">{session.manager}</td>
                    <td className="py-3 px-4 text-gray-600">{session.date}</td>
                    <td className="py-3 px-4">
                      {session.score !== null ? (
                        <span className={`inline-block px-3 py-1 rounded-full text-xs font-medium ${getScoreColor(session.score ?? 0).badge}`}>
                          {maturityLabel(getMaturityLevel(session.score ?? 0))}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-sm text-blue-600">
                          <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />
                          진행 중
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
