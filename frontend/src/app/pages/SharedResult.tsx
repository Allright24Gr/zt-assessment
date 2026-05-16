import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router";
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ResponsiveContainer, Legend,
} from "recharts";
import { Shield, Loader2, AlertTriangle, ChevronDown } from "lucide-react";
import { getSharedAssessment, ApiError } from "../../config/api";
import { PILLARS } from "../data/constants";
import { PILLAR_NAME_TO_KEY } from "../lib/pillar";
import { getMaturityLevel, getScoreColor, maturityLabel } from "../lib/maturity";
import type { AssessmentResultResponse } from "../../types/api";

const DEFAULT_SCORES = [0, 0, 0, 0, 0, 0];
const TARGET_SCORES = [3.5, 3.5, 3.0, 3.5, 3.5, 3.0];

export function SharedResult() {
  const { token } = useParams();
  const [data, setData] = useState<
    (AssessmentResultResponse & { shared?: { expires_at?: string; org?: string } }) | null
  >(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) {
      setError("공유 토큰이 없습니다.");
      setLoading(false);
      return;
    }
    setLoading(true);
    getSharedAssessment(token)
      .then((res) => {
        setData(res);
        setError(null);
      })
      .catch((err) => {
        console.warn("[shared-result] fetch failed:", err);
        if (err instanceof ApiError) {
          if (err.status === 404) setError("공유 링크를 찾을 수 없습니다.");
          else if (err.status === 410) setError("공유 링크가 만료되었습니다.");
          else if (err.status === 403) setError("공유 링크가 비활성화되었습니다.");
          else setError("공유 결과를 불러올 수 없습니다.");
        } else {
          setError("공유 결과를 불러올 수 없습니다.");
        }
      })
      .finally(() => setLoading(false));
  }, [token]);

  const currentScores = useMemo(() => {
    if (!data) return DEFAULT_SCORES;
    return PILLARS.map((p, i) => {
      const match = data.pillar_scores.find((ps) =>
        (PILLAR_NAME_TO_KEY[ps.pillar] ?? ps.pillar) === p.key
      );
      return match ? match.score : DEFAULT_SCORES[i];
    });
  }, [data]);

  const radarData = PILLARS.map((p, i) => ({
    pillar: p.shortLabel,
    "현재(AS-IS)": currentScores[i],
    "목표(TO-BE)": TARGET_SCORES[i],
  }));

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-blue-50">
        <div className="text-center">
          <Loader2 size={36} className="mx-auto animate-spin text-blue-500 mb-3" />
          <p className="text-sm text-gray-600">공유 결과를 불러오는 중...</p>
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-50 to-blue-50 px-4">
        <div className="bg-white rounded-xl shadow-xl p-8 max-w-md w-full text-center">
          <AlertTriangle size={48} className="mx-auto text-red-500 mb-4" />
          <h1 className="text-xl font-semibold text-gray-900 mb-2">결과를 표시할 수 없습니다</h1>
          <p className="text-sm text-gray-600">{error}</p>
        </div>
      </div>
    );
  }

  const session = data.session;
  const checklist = data.checklist_results ?? [];

  return (
    <div className="min-h-screen bg-gray-50">
      {/* 공유 헤더 */}
      <header className="bg-white border-b border-gray-200 sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="text-blue-600" size={22} />
            <div>
              <h1 className="text-lg font-semibold text-gray-900">Readyz-T 공유 진단 결과</h1>
              <p className="text-xs text-gray-500">
                {session.org} · {session.date}
                {data.shared?.expires_at && (
                  <span className="ml-2">· 만료 {new Date(data.shared.expires_at).toLocaleDateString("ko-KR")}</span>
                )}
              </p>
            </div>
          </div>
          <span className="px-3 py-1 rounded-full text-xs font-medium bg-blue-50 text-blue-700 border border-blue-200">
            읽기 전용 공유 보기
          </span>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8 space-y-6">
        {/* 종합 등급 배너 */}
        <div className="bg-gradient-to-r from-blue-600 to-blue-700 text-white rounded-xl p-8">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="text-blue-200 text-sm mb-1">종합 성숙도 등급</p>
              <h2 className="text-5xl font-bold mb-2">
                {data.overall_score ?? "-"}
                <span className="ml-2 text-2xl font-semibold text-blue-200">/ 4.0</span>
              </h2>
              <p className="text-blue-200">
                종합 점수 · {maturityLabel(data.overall_level)} 단계
              </p>
            </div>
          </div>
        </div>

        {/* 레이더 */}
        <div className="bg-white rounded-xl border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">필러별 성숙도</h3>
          <ResponsiveContainer width="100%" height={360}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#e5e7eb" />
              <PolarAngleAxis dataKey="pillar" stroke="#6b7280" tick={{ fontSize: 12 }} />
              <PolarRadiusAxis domain={[0, 4]} stroke="#d1d5db" tick={{ fontSize: 10 }} />
              <Radar name="현재(AS-IS)" dataKey="현재(AS-IS)" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.5} strokeWidth={2} />
              <Radar name="목표(TO-BE)" dataKey="목표(TO-BE)" stroke="#10b981" fill="#10b981" fillOpacity={0.2} strokeWidth={2} strokeDasharray="5 3" />
              <Legend wrapperStyle={{ fontSize: 12 }} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        {/* 필러별 점수 카드 */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {PILLARS.map((p, i) => {
            const score = currentScores[i];
            const colors = getScoreColor(score);
            const pct = (score / 4) * 100;
            return (
              <div key={p.key} className="bg-white rounded-xl border border-gray-200 p-5">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-semibold text-gray-700">{p.label}</h4>
                  <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${colors.badge}`}>
                    {maturityLabel(getMaturityLevel(score))}
                  </span>
                </div>
                <div className="flex items-baseline gap-1 mb-2">
                  <span className={`text-3xl font-bold ${colors.text}`}>{score.toFixed(2)}</span>
                  <span className="text-gray-400 text-sm">/ 4.0</span>
                </div>
                <div className="w-full bg-gray-100 rounded-full h-2">
                  <div className={`${colors.bar} h-2 rounded-full`} style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
        </div>

        {/* 체크리스트 요약 */}
        {checklist.length > 0 && (
          <div className="bg-white rounded-xl border border-gray-200 p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              체크리스트 결과 <span className="text-sm font-normal text-gray-400">({checklist.length}개)</span>
            </h3>
            <div className="space-y-2 max-h-[600px] overflow-y-auto pr-2">
              {checklist.map((item) => (
                <details key={item.id} className="border border-gray-200 rounded-lg">
                  <summary className="flex items-center justify-between gap-3 px-4 py-3 cursor-pointer hover:bg-gray-50">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-gray-800 truncate">{item.item}</p>
                      <p className="text-xs text-gray-500 mt-0.5">
                        {item.pillar} · {item.tool}
                      </p>
                    </div>
                    <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${
                      item.result === "충족"   ? "bg-green-100 text-green-700" :
                      item.result === "부분충족" ? "bg-amber-100 text-amber-700" :
                      item.result === "미충족"   ? "bg-red-100 text-red-700" :
                                                  "bg-gray-100 text-gray-500"
                    }`}>
                      {item.result}
                    </span>
                    <ChevronDown size={16} className="text-gray-400" />
                  </summary>
                  <div className="px-4 py-3 border-t border-gray-100 text-xs text-gray-600 space-y-1.5">
                    <p><strong className="text-gray-700">증적: </strong>{item.evidence}</p>
                    <p><strong className="text-gray-700">판정 기준: </strong>{item.criteria}</p>
                    <p><strong className="text-gray-700">개선 권고: </strong>{item.recommendation}</p>
                  </div>
                </details>
              ))}
            </div>
          </div>
        )}

        <footer className="text-center text-xs text-gray-400 py-6">
          본 페이지는 Readyz-T의 공유 링크로 발급된 읽기 전용 진단 결과입니다.
        </footer>
      </main>
    </div>
  );
}
