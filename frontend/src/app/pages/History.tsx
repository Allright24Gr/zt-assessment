import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Clock,
  GitCompare,
  Loader2,
  Trash2,
  TrendingUp,
  X,
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
import {
  deleteAssessmentSession,
  getAssessmentHistory,
  getScoreSummary,
} from "../../config/api";
import { pillarMatchesKey } from "../lib/pillar";
import { maturityLabel } from "../lib/maturity";
import { formatSessionDate } from "../lib/datetime";
import type { AssessmentSession } from "../../types/api";

// 노션 2번 피드백 A-2: 점수 칼럼 정렬 추가 — date/org/manager 외 score 도 정렬 가능.
type SortKey = "org" | "date" | "manager" | "score";
type SortDir = "asc" | "desc";

const COMPARE_COLORS = ["#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899"];

function SortIcon({ active, dir }: { active: boolean; dir: SortDir }) {
  if (!active) return <ArrowUpDown size={13} className="text-gray-300" />;
  return dir === "asc"
    ? <ArrowUp size={13} className="text-blue-500" />
    : <ArrowDown size={13} className="text-blue-500" />;
}

// 노션 2번 피드백 D-1: maturity 단계 색상 통일 — 기존(빨강)/초기(노랑)/향상(파랑)/최적화(초록).
// MATURITY_COLOR 와 같은 톤이지만 History는 단순 클래스만 필요해 분리.
function getLevelBadgeClass(level: string) {
  if (level === "기존") return "bg-red-100 text-red-700";
  if (level === "초기") return "bg-yellow-100 text-yellow-800";
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
  const navigate = useNavigate();
  const [selectedSessions, setSelectedSessions] = useState<number[]>([]);
  const [sortKey, setSortKey] = useState<SortKey>("date");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [allSessions, setAllSessions] = useState<AssessmentSession[]>(
    mockSessions.map(toApiSession)
  );
  const [pillarScoresBySession, setPillarScoresBySession] = useState<Record<string | number, number[]>>({});
  // 세션 삭제 확인 모달
  const [deleteTarget, setDeleteTarget] = useState<AssessmentSession | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [query, setQuery] = useState("");

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await deleteAssessmentSession(deleteTarget.id);
      // 로컬 상태에서 즉시 제거 + 선택 목록에서도 제거
      setAllSessions((prev) => prev.filter((s) => s.id !== deleteTarget.id));
      setSelectedSessions((prev) => prev.filter((id) => id !== Number(deleteTarget.id)));
      toast.success(`'${deleteTarget.org}' 진단 세션이 삭제되었습니다.`);
      setDeleteTarget(null);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "세션 삭제 실패";
      toast.error(msg);
    } finally {
      setDeleting(false);
    }
  };

  useEffect(() => {
    const orgFilter = user?.role === "user" ? user.orgName : undefined;
    getAssessmentHistory(orgFilter)
      .then((data) => setAllSessions(data.sessions))
      .catch((err) => {
        console.warn("[history] fetch failed:", err);
        toast.error("이력을 불러오지 못했습니다.");
      });
  }, [user?.role, user?.orgName]);

  // SFR-IT-002 결과 검색 — 조직/담당자/레벨/상태/ID 부분 일치 (클라이언트 필터).
  const baseSessions = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return allSessions;
    return allSessions.filter((s) =>
      [s.id, s.org, s.manager, s.level, s.status]
        .map((v) => String(v ?? "").toLowerCase())
        .some((v) => v.includes(q)),
    );
  }, [allSessions, query]);

  const sessions = useMemo(() => {
    // 노션 2번 피드백 A-2: score 칼럼 추가 정렬. null 점수(진행중) 는 항상 맨 뒤로.
    return [...baseSessions].sort((a, b) => {
      if (sortKey === "score") {
        const sa = a.score;
        const sb = b.score;
        if (sa == null && sb == null) return 0;
        if (sa == null) return 1;
        if (sb == null) return -1;
        return sortDir === "asc" ? sa - sb : sb - sa;
      }
      const va = a[sortKey] ?? "";
      const vb = b[sortKey] ?? "";
      return sortDir === "asc"
        ? String(va).localeCompare(String(vb), "ko")
        : String(vb).localeCompare(String(va), "ko");
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
    <div className="max-w-screen-2xl mx-auto space-y-6">
      {/* 노션 2번 피드백 A-1: 우측 파란 배지 삭제 + 페이지 제목을 역할별로 분기. */}
      <div className="flex items-center justify-between">
        <h1>{user?.role === "admin" ? "전체 기관 진단 이력" : "내 조직 진단 이력"}</h1>
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
          {/* 노션 2번 피드백 A-4: 비교 버튼은 항상 표시하되 정확히 2개 선택 시에만 활성화. */}
          <div className="ml-auto flex items-center gap-2">
            {/* SFR-IT-002 결과 검색 */}
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="조직·담당자·레벨 검색"
              className="px-3 py-1.5 text-sm border border-gray-200 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-200 w-48"
            />
            {selectedSessions.length > 0 && (
              <span className="text-sm text-blue-600 font-medium">{selectedSessions.length}개 선택됨</span>
            )}
            <button
              type="button"
              disabled={selectedSessions.length !== 2}
              onClick={() => {
                if (selectedSessions.length !== 2) return;
                const [a, b] = selectedSessions;
                const sa = sessions.find((s) => Number(s.id) === a);
                const sb = sessions.find((s) => Number(s.id) === b);
                const fromId = (sa && sb && sa.date <= sb.date) ? a : b;
                const toId = fromId === a ? b : a;
                navigate(`/compare?from=${fromId}&to=${toId}`);
              }}
              className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium ${
                selectedSessions.length === 2
                  ? "bg-blue-600 text-white hover:bg-blue-700 cursor-pointer"
                  : "bg-gray-100 text-gray-400 cursor-not-allowed"
              }`}
              title={
                selectedSessions.length === 2
                  ? "선택한 2개 진단의 차이를 비교합니다"
                  : `비교는 정확히 2개 선택 시 활성화됩니다 (현재 ${selectedSessions.length}개)`
              }
            >
              <GitCompare size={12} />
              비교 모드
            </button>
            {selectedSessions.length > 0 && (
              <button
                onClick={() => setSelectedSessions([])}
                className="text-xs text-gray-400 hover:text-gray-600 underline"
              >
                전체 해제
              </button>
            )}
          </div>
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
                {/* 노션 2번 피드백 A-2: 점수 칼럼 정렬 가능 */}
                <th className="py-3 px-4">
                  <button
                    onClick={() => toggleSort("score")}
                    className="flex items-center gap-1 text-sm font-medium text-gray-500 hover:text-gray-800"
                  >
                    점수
                    <SortIcon active={sortKey === "score"} dir={sortDir} />
                  </button>
                </th>
                <th className="py-3 px-4 text-sm font-medium text-gray-500">상태</th>
                {user?.role === "admin" && (
                  <th className="py-3 px-4 text-sm font-medium text-gray-500">위험 영역</th>
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
                          {(session.is_demo || session.scan_mode === "demo") && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-100 text-amber-800 border border-amber-200">
                              데모
                            </span>
                          )}
                          {session.scan_mode === "live" && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200">
                              실 스캔
                            </span>
                          )}
                        </span>
                      </td>
                      {/* 노션 2번 피드백 A-3: ISO 날짜의 T 제거 → 스페이스 2칸 */}
                      <td className="py-3 px-4 text-gray-600 whitespace-nowrap">{formatSessionDate(session.date)}</td>
                      <td className="py-3 px-4 text-gray-600">{session.manager}</td>
                      <td className="py-3 px-4">
                        <span className={`inline-block px-3 py-1 rounded-full text-xs font-medium ${getLevelBadgeClass(session.level)}`}>
                          {maturityLabel(session.level)}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        {session.score !== null ? (
                          <>
                            <span className="font-semibold">
                              {typeof session.score === "number" ? session.score.toFixed(2) : session.score}
                            </span>
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
                        <div className="flex items-center gap-3">
                          {isInProgress ? (
                            <Link to={`/in-progress/${session.id}`} className="text-blue-600 hover:text-blue-800 text-sm font-medium">
                              진행 중 보기
                            </Link>
                          ) : (
                            <Link to={`/reporting/${session.id}`} className="text-blue-600 hover:text-blue-800 text-sm">
                              결과 보기
                            </Link>
                          )}
                          <button
                            type="button"
                            onClick={() => setDeleteTarget(session)}
                            aria-label={`'${session.org}' ${session.date} 진단 삭제`}
                            title="진단 세션 삭제"
                            className="p-1 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded transition-colors"
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
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
                  {typeof session.score === "number" ? session.score.toFixed(2) : "-"}
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
                {/* 노션 2번 피드백 A-5: 막대 색 따라가는 반투명 배경 + 소수점 둘째 자리 */}
                <Tooltip
                  cursor={{ fill: "rgba(0,0,0,0.04)" }}
                  formatter={(v: number) => [`${Number(v).toFixed(2)} / 4.00`, "종합 점수"]}
                  content={({ active, payload }) => {
                    if (!active || !payload || payload.length === 0) return null;
                    const p = payload[0];
                    const color = (p.payload && (p.payload as { color?: string }).color) ?? (p.color as string) ?? "#3b82f6";
                    const val = typeof p.value === "number" ? p.value : Number(p.value);
                    const row = p.payload as { org?: string; date?: string };
                    return (
                      <div
                        style={{
                          backgroundColor: `${color}D9`,  // alpha ~0.85
                          borderColor: color,
                        }}
                        className="rounded-md border px-3 py-2 text-xs text-white shadow-lg"
                      >
                        <div className="font-semibold">{row.org}</div>
                        <div className="opacity-90">{formatSessionDate(row.date)}</div>
                        <div className="mt-1 font-semibold">{val.toFixed(2)} / 4.00</div>
                      </div>
                    );
                  }}
                />
                <Bar dataKey="score" radius={[0, 4, 4, 0]}>
                  {barData.map((_, i) => (
                    <Cell key={i} fill={COMPARE_COLORS[i % COMPARE_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* 노션 2번 피드백 A-6, A-7: 레이더 차트 옆에 필러별 점수 테이블 + 차트 패딩 보강(시스템 글자 겹침 해소) */}
          <div>
            <h3 className="text-sm font-semibold text-gray-600 mb-3">필러별 비교</h3>
            <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_minmax(280px,420px)] gap-6 items-center">
              <div className="px-2 pb-4">
                <ResponsiveContainer width="100%" height={380}>
                  <RadarChart data={radarData} margin={{ top: 24, right: 28, bottom: 24, left: 28 }}>
                    <PolarGrid stroke="#e5e7eb" />
                    <PolarAngleAxis dataKey="pillar" stroke="#6b7280" tick={{ fontSize: 12 }} />
                    {selectedData.map((session, idx) => (
                      <Radar
                        key={session.id}
                        name={`${session.org} (${formatSessionDate(session.date)})`}
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
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="bg-gray-50 text-gray-500">
                      <th className="text-left px-3 py-2 font-medium">필러</th>
                      {selectedData.map((s, idx) => (
                        <th
                          key={s.id}
                          className="text-right px-3 py-2 font-medium whitespace-nowrap"
                          style={{ color: COMPARE_COLORS[idx % COMPARE_COLORS.length] }}
                        >
                          세션 {idx + 1}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {PILLARS.map((p, i) => (
                      <tr key={p.key} className="border-t border-gray-100">
                        <td className="px-3 py-1.5 text-gray-700">{p.shortLabel}</td>
                        {selectedData.map((s, idx) => (
                          <td
                            key={s.id}
                            className="px-3 py-1.5 text-right font-semibold tabular-nums"
                            style={{ color: COMPARE_COLORS[idx % COMPARE_COLORS.length] }}
                          >
                            {(pillarScoresFor(s)[i] ?? 0).toFixed(2)}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 진단 세션 삭제 확인 모달 */}
      {deleteTarget && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="delete-session-title"
          onClick={(e) => { if (e.target === e.currentTarget && !deleting) setDeleteTarget(null); }}
          onKeyDown={(e) => { if (e.key === "Escape" && !deleting) setDeleteTarget(null); }}
        >
          <div className="relative bg-white rounded-xl shadow-xl p-6 w-full max-w-md">
            <button
              type="button"
              onClick={() => !deleting && setDeleteTarget(null)}
              className="absolute top-3 right-3 text-gray-400 hover:text-gray-600"
              aria-label="닫기"
              disabled={deleting}
            >
              <X size={18} />
            </button>
            <div className="flex items-center gap-2 mb-3">
              <Trash2 size={20} className="text-red-600" aria-hidden="true" />
              <h2 id="delete-session-title" className="text-base font-semibold text-gray-900">
                진단 세션 삭제
              </h2>
            </div>
            <div className="space-y-2 mb-5 text-sm text-gray-600">
              <p>
                <span className="font-medium text-gray-900">{deleteTarget.org}</span> /{" "}
                {deleteTarget.date} / {deleteTarget.manager}
              </p>
              <p className="text-red-600">
                ⚠️ 이 세션의 수집 데이터·증적·점수·이력이 모두 삭제됩니다.{" "}
                {deleteTarget.status === "진행 중" && "진행 중인 진단도 즉시 중단됩니다."}{" "}
                <span className="font-semibold">복구할 수 없습니다.</span>
              </p>
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => !deleting && setDeleteTarget(null)}
                className="flex-1 bg-gray-100 text-gray-700 py-2 rounded-lg hover:bg-gray-200 text-sm font-medium"
                disabled={deleting}
              >
                취소
              </button>
              <button
                type="button"
                onClick={handleDelete}
                className={`flex-1 flex items-center justify-center gap-1.5 py-2 rounded-lg text-sm font-medium text-white ${
                  deleting ? "bg-red-400 cursor-not-allowed" : "bg-red-600 hover:bg-red-700"
                }`}
                disabled={deleting}
              >
                {deleting
                  ? <><Loader2 size={14} className="animate-spin" /> 삭제 중...</>
                  : <>삭제</>}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
