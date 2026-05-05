import { useState } from "react";
import { Link, useParams } from "react-router";
import { FileText, Download, TrendingUp, AlertTriangle, AlertCircle, ArrowRight, CheckCircle2, ChevronDown } from "lucide-react";
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ResponsiveContainer, Legend,
} from "recharts";
import { useAuth } from "../context/AuthContext";
import { sessions, improvements } from "../data/mockData";
import { PILLARS } from "../data/constants";
import { getMaturityLevel, getScoreColor } from "../lib/maturity";

const CURRENT_SCORES = [2.5, 3.0, 2.0, 2.8, 1.5, 2.2];
const TARGET_SCORES  = [3.5, 3.5, 3.0, 3.5, 3.0, 3.5];

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

  const session = sessions.find((s) => s.id === Number(sessionId)) || sessions[0];
  const normalizedQuestionQuery = detailQuestionQuery.trim().toLowerCase();
  const filteredChecklistDetails = session.checklistDetails.filter((detail) => {
    const matchesPillar = detailPillarFilter === "all" || detail.pillar === detailPillarFilter;
    const searchable = `${detail.item} ${detail.question} ${detail.tool} ${detail.evidence} ${detail.criteria}`.toLowerCase();
    const matchesQuestion = normalizedQuestionQuery.length === 0 || searchable.includes(normalizedQuestionQuery);
    return matchesPillar && matchesQuestion;
  });
  const checklistGroups = PILLARS.map((pillar) => ({
    pillar,
    items: filteredChecklistDetails.filter((detail) => detail.pillar === pillar.key),
  })).filter((group) => group.items.length > 0);

  const radarData = PILLARS.map((p, i) => ({
    pillar: p.shortLabel,
    "현재(AS-IS)": CURRENT_SCORES[i],
    "목표(TO-BE)": TARGET_SCORES[i],
  }));

  const pillarScores = PILLARS.map((p, i) => ({
    key: p.key,
    name: p.label,
    score: CURRENT_SCORES[i],
    target: TARGET_SCORES[i],
    level: getMaturityLevel(CURRENT_SCORES[i]),
    gap: parseFloat((TARGET_SCORES[i] - CURRENT_SCORES[i]).toFixed(1)),
  }));

  const byTerm = ["단기", "중기", "장기"].map((term) => ({
    term,
    tasks: improvements.filter((t) => t.term === term),
  }));

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1>진단 결과</h1>
          <p className="text-sm text-gray-600 mt-1">
            {session.org} — {session.manager} ({session.date})
          </p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
          <Download size={20} />
          PDF 다운로드
        </button>
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
          {/* 에러 코드 (관리자) */}
          {user?.role === "admin" && session.errors.length > 0 && (
            <div className="bg-red-50 border border-red-200 rounded-xl p-6">
              <div className="flex items-center gap-2 mb-4">
                <AlertCircle className="text-red-600" size={20} />
                <h2 className="text-red-900">진단 에러 코드</h2>
              </div>
              <div className="space-y-2">
                {session.errors.map((error, i) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-white rounded-lg border border-red-100">
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-sm font-bold text-red-700">{error.code}</span>
                      <span className="text-sm text-gray-700">{error.message}</span>
                    </div>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      error.severity === "Critical" ? "bg-red-100 text-red-700" :
                      error.severity === "High"     ? "bg-orange-100 text-orange-700" :
                                                      "bg-yellow-100 text-yellow-700"
                    }`}>
                      {error.severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 종합 등급 배너 */}
          <div className="bg-gradient-to-r from-blue-600 to-blue-700 text-white rounded-xl p-8">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-blue-200 text-sm mb-1">종합 성숙도 등급</p>
                <h1 className="text-5xl font-bold mb-2">{session.level} 단계</h1>
                <p className="text-blue-200">
                  평균 점수: {session.score !== null ? `${session.score} / 4.0` : "진행 중"}
                </p>
              </div>
              {/* 단계 진행 표시 */}
              <div className="flex items-center gap-2">
                {["기존", "초기", "향상", "최적화"].map((step, i, arr) => (
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
                        {step}
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
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${colors.badge}`}>{pillar.level}</span>
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
                    <span className="text-emerald-600">목표 {pillar.target} (+{pillar.gap})</span>
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
            <span>총 {session.checklistDetails.length}개 중 {filteredChecklistDetails.length}개 표시</span>
            {(detailPillarFilter !== "all" || detailQuestionQuery) && (
              <button
                onClick={() => {
                  setDetailPillarFilter("all");
                  setDetailQuestionQuery("");
                }}
                className="text-blue-600 hover:underline"
              >
                검색 초기화
              </button>
            )}
          </div>

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

                    return (
                      <details
                        key={detail.id}
                        className="group rounded-xl border border-gray-200 bg-white p-4 transition-colors open:border-blue-200 open:bg-blue-50/30"
                      >
                        <summary className="flex cursor-pointer list-none items-center justify-between gap-4">
                          <div className="min-w-0">
                            <div className="mb-2 flex flex-wrap items-center gap-2">
                              <span className="rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-600">
                                {detail.category}
                              </span>
                              <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${
                                detail.result === "충족"
                                  ? "bg-green-100 text-green-700"
                                  : detail.result === "미흡"
                                  ? "bg-red-100 text-red-700"
                                  : "bg-gray-100 text-gray-500"
                              }`}>
                                {detail.result}
                              </span>
                              <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${scoreColors.badge}`}>
                                {getMaturityLevel(detail.score)}
                              </span>
                              <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600">
                                {detail.diagnosisType} / {detail.tool}
                              </span>
                            </div>
                            <p className="mb-1 text-xs font-semibold text-gray-500">{detail.item} · {detail.maturity}</p>
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
              현재 평균 성숙도 <strong>2.33</strong>에서 목표 <strong>3.33</strong>으로 향상하기 위한
              {" "}<strong>{improvements.length}개</strong>의 개선 과제가 있습니다.
              Critical {improvements.filter(t => t.priority === "Critical").length}건,
              High {improvements.filter(t => t.priority === "High").length}건,
              Medium {improvements.filter(t => t.priority === "Medium").length}건.
            </p>
          </div>

          {/* 칸반 보드 */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {byTerm.map(({ term, tasks }) => (
              <div key={term} className={`rounded-xl border p-4 ${TERM_COLORS[term]}`}>
                <h3 className={`text-sm font-bold mb-3 ${TERM_HEADER[term]}`}>{TERM_LABELS[term]}</h3>
                <div className="space-y-3">
                  {tasks.length === 0 ? (
                    <p className="text-xs text-gray-400 text-center py-4">과제 없음</p>
                  ) : tasks.map((task, i) => (
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
                    </div>
                  ))}
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
            <p className="text-gray-500 mb-8">진단 결과 전체를 PDF 문서로 다운로드할 수 있습니다</p>
            <div className="flex justify-center gap-4">
              <button className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2 font-medium">
                <Download size={18} />
                PDF 다운로드
              </button>
              <Link
                to="/new-assessment"
                className="px-6 py-3 border border-blue-600 text-blue-600 rounded-lg hover:bg-blue-50 inline-flex items-center gap-2 font-medium"
              >
                재진단 시작
              </Link>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
