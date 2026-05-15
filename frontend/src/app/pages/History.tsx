import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Clock,
  TrendingUp,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  PolarAngleAxis,
  PolarGrid,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { toast } from "sonner";
import { useAuth } from "../context/AuthContext";
import { sessions as mockSessions } from "../data/mockData";
import { PILLARS } from "../data/constants";
import { getAssessmentHistory, getScoreSummary } from "../../config/api";
import { pillarMatchesKey } from "../lib/pillar";
import type { AssessmentSession } from "../../types/api";

type SortKey = "org" | "date" | "manager";
type SortDir = "asc" | "desc";

const COMPARE_COLORS = ["#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899"];

function SortIcon({ active, dir }: { active: boolean; dir: SortDir }) {
  if (!active) return <ArrowUpDown size={13} className="text-gray-300" />;
  return dir === "asc"
    ? <ArrowUp size={13} className="text-blue-500" />
    : <ArrowDown size={13} className="text-blue-500" />;
}

function getLevelBadgeClass(level: string) {
  if (level === "기존") return "bg-red-100 text-red-700";
  if (level === "초기") return "bg-yellow-100 text-yellow-700";
  if (level === "향상") return "bg-blue-100 text-blue-700";
  if (level === "최적화") return "bg-green-100 text-green-700";
  return "bg-blue-100 text-blue-700";
}

function toApiSession(s: typeof mockSessions[0]): AssessmentSession {
  return {
    id: s.id,
    org: s.org,
    date: s.date,
    manager: s.manager,
    user_id: s.userId,
    level: s.level,
    status: s.status,
    score: s.score,
    errors: s.errors,
  };
}

export function History() {
  const { user } = useAuth();
  const [selectedSessions, setSelectedSessions] = useState<number[]>([]);
  const [sortKey, setSortKey] = useState<SortKey>("date");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [allSessions, setAllSessions] = useState<AssessmentSession[]>(
    mockSessions.map(toApiSession)
  );
  const [pillarScoresBySession, setPillarScoresBySession] = useState<Record<string | number, number[]>>({});

  useEffect(() => {
    const orgFilter = user?.role === "user" ? user.orgName : undefined;
    getAssessmentHistory(orgFilter)
      .then((data) => setAllSessions(data.sessions))
      .catch((err) => {
        console.warn("[history] fetch failed:", err);
        toast.error("이력을 불러오지 못했습니다.");
      });
  }, [user?.role, user?.orgName]);

  // 백엔드 호출이 org_name으로 이미 필터링되므로 클라이언트 필터링 불필요
  const baseSessions = allSessions;

  const sessions = useMemo(() => {
    return [...baseSessions].sort((a, b) => {
      const va = a[sortKey] ?? "";
      const vb = b[sortKey] ?? "";
      return sortDir === "asc" ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
    });
  }, [baseSessions, sortKey, sortDir]);

  const completedCount = sessions.filter((session) => session.status !== "진행 중").length;

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((dir) => (dir === "asc" ? "desc" : "asc"));
    else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  const toggleSession = (id: number) => {
    const session = sessions.find((item) => Number(item.id) === id);
    if (session?.status === "진행 중") return;
    setSelectedSessions((prev) => (
      prev.includes(id) ? prev.filter((sessionId) => sessionId !== id) : [...prev, id]
    ));
  };

  const selectedData = selectedSessions
    .map((id) => sessions.find((session) => Number(session.id) === id))
    .filter(Boolean) as AssessmentSession[];

  // 선택된 세션의 실제 필러 점수 fetch
  useEffect(() => {
    selectedData.forEach((session) => {
      if (pillarScoresBySession[session.id]) return;
      if (session.status !== "완료") return;
      getScoreSummary(session.id)
        .then((summary) => {
          const scores = PILLARS.map((p) => {
            const match = summary.pillar_scores.find((ps) => pillarMatchesKey(ps.pillar, p.key));
            return match ? match.score : 0;
          });
          setPillarScoresBySession((prev) => ({ ...prev, [session.id]: scores }));
        })
        .catch((err) => console.warn("[history] score summary:", err));
    });
  }, [selectedData, pillarScoresBySession]);

  function pillarScoresFor(session: AssessmentSession): number[] {
    return pillarScoresBySession[session.id] ?? PILLARS.map(() => 0);
  }

  const radarData = PILLARS.map((p, i) => {
    const entry: Record<string, string | number> = { pillar: p.shortLabel };
    selectedData.forEach((session) => {
      entry[`${session.org} (${session.date})`] = pillarScoresFor(session)[i];
    });
    return entry;
  });

  const barData = selectedData.map((session) => ({
    name: `${session.org}\n${session.date}`,
    score: session.score ?? 0,
    org: session.org,
    date: session.date,
  }));

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <h1>진단 이력</h1>
        {user?.role === "admin" && (
          <span className="px-4 py-2 bg-blue-100 text-blue-700 rounded-lg text-sm font-medium">
            전체 기관 이력 조회
          </span>
        )}
      </div>

      <div className="bg-white rounded-xl border border-gray-200 p-6">
        <div className="flex items-center gap-3 mb-4">
          <Clock className="text-blue-600" size={20} />
          <h2>
            세션 목록
            <span className="ml-2 text-sm font-normal text-gray-400">
              총 {sessions.length}개 / 완료 {completedCount}개
            </span>
          </h2>
          {selectedSessions.length > 0 && (
            <div className="ml-auto flex items-center gap-2">
              <span className="text-sm text-blue-600 font-medium">{selectedSessions.length}개 선택됨</span>
              <button
                onClick={() => setSelectedSessions([])}
                className="text-xs text-gray-400 hover:text-gray-600 underline"
              >
                전체 해제
              </button>
            </div>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200 text-left bg-gray-50">
                <th className="py-3 px-4 whitespace-nowrap text-sm font-medium text-gray-500">선택</th>
                {(["org", "date", "manager"] as SortKey[]).map((key) => (
                  <th key={key} className="py-3 px-4">
                    <button
                      onClick={() => toggleSort(key)}
                      className="flex items-center gap-1 text-sm font-medium text-gray-500 hover:text-gray-800"
                    >
                      {key === "org" ? "기관명" : key === "date" ? "진단 날짜" : "담당자"}
                      <SortIcon active={sortKey === key} dir={sortDir} />
                    </button>
                  </th>
                ))}
                <th className="py-3 px-4 text-sm font-medium text-gray-500">성숙도 등급</th>
                <th className="py-3 px-4 text-sm font-medium text-gray-500">점수</th>
                <th className="py-3 px-4 text-sm font-medium text-gray-500">상태</th>
                {user?.role === "admin" && (
                  <th className="py-3 px-4 text-sm font-medium text-gray-500">오류</th>
                )}
                <th className="py-3 px-4 text-sm font-medium text-gray-500">작업</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((session) => {
                const numId = Number(session.id);
                const isInProgress = session.status === "진행 중";
                const isSelected = selectedSessions.includes(numId);
                const selIdx = selectedSessions.indexOf(numId);

                return (
                  <tr
                    key={session.id}
                    className={`border-b border-gray-100 transition-colors ${
                      isInProgress ? "bg-blue-50/40" : isSelected ? "bg-blue-50" : "hover:bg-gray-50"
                    }`}
                  >
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => toggleSession(numId)}
                            disabled={isInProgress}
                            className="w-4 h-4 accent-blue-600 disabled:opacity-30 disabled:cursor-not-allowed"
                          />
                          {isSelected && (
                            <span
                              className="w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold text-white"
                              style={{ backgroundColor: COMPARE_COLORS[selIdx % COMPARE_COLORS.length] }}
                            >
                              {selIdx + 1}
                            </span>
                          )}
                        </div>
                      </td>
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
                      <td className="py-3 px-4 text-gray-600">{session.date}</td>
                      <td className="py-3 px-4 text-gray-600">{session.manager}</td>
                      <td className="py-3 px-4">
                        <span className={`inline-block px-3 py-1 rounded-full text-xs font-medium ${getLevelBadgeClass(session.level)}`}>
                          {session.level}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        {session.score !== null ? (
                          <>
                            <span className="font-semibold">{session.score}</span>
                            <span className="text-gray-400 text-sm"> / 4.0</span>
                          </>
                        ) : (
                          <span className="text-gray-400 text-sm italic">진행 중</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {isInProgress ? (
                          <span className="inline-flex items-center gap-1.5 px-2 py-1 bg-blue-100 text-blue-700 rounded text-sm">
                            <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
                            진행 중
                          </span>
                        ) : (
                          <span className="px-2 py-1 bg-green-100 text-green-700 rounded text-sm">완료</span>
                        )}
                      </td>
                      {user?.role === "admin" && (
                        <td className="py-3 px-4">
                          {(session.errors?.length ?? 0) > 0 ? (
                            <span className="px-2 py-1 bg-red-100 text-red-700 rounded text-sm">
                              {session.errors!.length}개
                            </span>
                          ) : (
                            <span className="text-green-600 text-sm">정상</span>
                          )}
                        </td>
                      )}
                      <td className="py-3 px-4">
                        {isInProgress ? (
                          <Link to={`/in-progress/${session.id}`} className="text-blue-600 hover:text-blue-800 text-sm font-medium">
                            진행 중 보기
                          </Link>
                        ) : (
                          <Link to={`/reporting/${session.id}`} className="text-blue-600 hover:text-blue-800 text-sm">
                            결과 보기
                          </Link>
                        )}
                      </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {selectedSessions.length >= 2 && (
        <div className="bg-white rounded-xl border border-gray-200 p-6 space-y-6">
          <div className="flex items-center gap-2">
            <TrendingUp className="text-blue-600" size={20} />
            <h2>세션 비교 ({selectedSessions.length}개 선택)</h2>
          </div>

          <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(${Math.min(selectedData.length, 3)}, 1fr)` }}>
            {selectedData.map((session, idx) => (
              <div
                key={session.id}
                className="rounded-xl p-4 border-2"
                style={{ borderColor: COMPARE_COLORS[idx % COMPARE_COLORS.length], backgroundColor: `${COMPARE_COLORS[idx % COMPARE_COLORS.length]}10` }}
              >
                <div className="flex items-center gap-2 mb-2">
                  <span
                    className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold text-white shrink-0"
                    style={{ backgroundColor: COMPARE_COLORS[idx % COMPARE_COLORS.length] }}
                  >
                    {idx + 1}
                  </span>
                  <p className="font-semibold text-sm truncate">{session.org}</p>
                </div>
                <p className="text-xs text-gray-500 mb-1">{session.date} / {session.manager}</p>
                <p className="text-2xl font-bold" style={{ color: COMPARE_COLORS[idx % COMPARE_COLORS.length] }}>
                  {session.score ?? "-"}
                  <span className="text-sm font-normal text-gray-400"> / 4.0</span>
                </p>
              </div>
            ))}
          </div>

          <div>
            <h3 className="text-sm font-semibold text-gray-600 mb-3">종합 점수 비교</h3>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={barData} layout="vertical" margin={{ left: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" horizontal={false} />
                <XAxis type="number" domain={[0, 4]} tick={{ fontSize: 12 }} stroke="#9ca3af" />
                <YAxis type="category" dataKey="org" tick={{ fontSize: 11 }} stroke="#9ca3af" width={90} />
                <Tooltip
                  formatter={(v: number) => [`${v} / 4.0`, "종합 점수"]}
                  contentStyle={{ borderRadius: 8, border: "1px solid #e5e7eb" }}
                />
                <Bar dataKey="score" radius={[0, 4, 4, 0]}>
                  {barData.map((_, i) => (
                    <Cell key={i} fill={COMPARE_COLORS[i % COMPARE_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div>
            <h3 className="text-sm font-semibold text-gray-600 mb-3">필러별 비교</h3>
            <ResponsiveContainer width="100%" height={380}>
              <RadarChart data={radarData}>
                <PolarGrid stroke="#e5e7eb" />
                <PolarAngleAxis dataKey="pillar" stroke="#6b7280" tick={{ fontSize: 12 }} />
                {selectedData.map((session, idx) => (
                  <Radar
                    key={session.id}
                    name={`${session.org} (${session.date})`}
                    dataKey={`${session.org} (${session.date})`}
                    stroke={COMPARE_COLORS[idx % COMPARE_COLORS.length]}
                    fill={COMPARE_COLORS[idx % COMPARE_COLORS.length]}
                    fillOpacity={0.15}
                    strokeWidth={2}
                  />
                ))}
                <Legend wrapperStyle={{ fontSize: 12 }} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
    </div>
  );
}
