import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";
import {
  ArrowDown, ArrowUp, ArrowLeft, Loader2, AlertTriangle, GitCompare, TrendingUp, TrendingDown, Minus,
} from "lucide-react";
import {
  Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { toast } from "sonner";
import { getAssessmentCompare, ApiError } from "../../config/api";
import { PILLARS } from "../data/constants";
import { pillarKeyOf } from "../lib/pillar";
import { maturityLabel } from "../lib/maturity";
import type { AssessmentCompareResponse } from "../../types/api";

function deltaBadge(delta: number) {
  if (delta > 0) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-green-100 text-green-700">
        <ArrowUp size={12} />
        +{delta.toFixed(2)}
      </span>
    );
  }
  if (delta < 0) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-700">
        <ArrowDown size={12} />
        {delta.toFixed(2)}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-gray-100 text-gray-600">
      <Minus size={12} />
      0.00
    </span>
  );
}

export function Compare() {
  const [searchParams] = useSearchParams();
  const fromId = searchParams.get("from") ?? "";
  const toId = searchParams.get("to") ?? "";

  const [data, setData] = useState<AssessmentCompareResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!fromId || !toId) {
      setError("비교 대상 세션이 지정되지 않았습니다.");
      setLoading(false);
      return;
    }
    setLoading(true);
    getAssessmentCompare(fromId, toId)
      .then((res) => {
        setData(res);
        setError(null);
      })
      .catch((err) => {
        console.warn("[compare] fetch failed:", err);
        if (err instanceof ApiError && err.status === 404) {
          setError("비교할 세션을 찾을 수 없습니다.");
        } else {
          setError("비교 결과를 불러오지 못했습니다.");
        }
        toast.error("진단 비교를 불러오지 못했습니다.");
      })
      .finally(() => setLoading(false));
  }, [fromId, toId]);

  const pillarBarData = useMemo(() => {
    if (!data) return [];
    return data.pillar_deltas.map((d) => {
      const key = pillarKeyOf(d.pillar);
      const meta = PILLARS.find((p) => p.key === key);
      return {
        pillar: meta?.shortLabel ?? d.pillar,
        delta: Number(d.delta.toFixed(2)),
        from: d.from_score,
        to: d.to_score,
      };
    });
  }, [data]);

  if (loading) {
    return (
      <div className="max-w-5xl mx-auto py-16 text-center">
        <Loader2 size={36} className="mx-auto animate-spin text-blue-500 mb-3" />
        <p className="text-sm text-gray-500">진단 비교 결과를 불러오는 중...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="max-w-5xl mx-auto py-12">
        <div className="rounded-xl border border-red-200 bg-red-50 p-6 text-center">
          <AlertTriangle size={32} className="mx-auto text-red-600 mb-3" />
          <p className="font-semibold text-red-700 mb-2">{error ?? "비교 결과를 불러올 수 없습니다."}</p>
          <Link to="/history" className="text-sm text-red-600 hover:underline">
            이력 페이지로 돌아가기
          </Link>
        </div>
      </div>
    );
  }

  const { from, to, overall_delta, improved, regressed, new_in_to, unchanged_count } = data;

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <GitCompare size={22} className="text-blue-600" />
          <h1>진단 비교</h1>
        </div>
        <Link
          to="/history"
          className="inline-flex items-center gap-1.5 text-sm text-gray-600 hover:text-gray-900"
        >
          <ArrowLeft size={16} />
          이력으로 돌아가기
        </Link>
      </div>

      {/* 세션 메타 비교 */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <SessionMetaCard label="이전 진단 (FROM)" meta={from} color="blue" />
        <SessionMetaCard label="이후 진단 (TO)" meta={to} color="emerald" />
      </div>

      {/* 종합 점수 변화 */}
      <div className="bg-white rounded-xl border border-gray-200 p-6">
        <div className="flex items-center gap-2 mb-4">
          <TrendingUp className="text-blue-600" size={20} />
          <h2>종합 점수 변화</h2>
        </div>
        <div className="flex flex-wrap items-center gap-6">
          <div>
            <p className="text-xs text-gray-500 mb-1">이전</p>
            <p className="text-3xl font-bold text-blue-600">
              {from.score?.toFixed(2) ?? "-"}
              <span className="text-sm font-normal text-gray-400"> / 4.0</span>
            </p>
          </div>
          <div className="text-3xl text-gray-300">→</div>
          <div>
            <p className="text-xs text-gray-500 mb-1">이후</p>
            <p className="text-3xl font-bold text-emerald-600">
              {to.score?.toFixed(2) ?? "-"}
              <span className="text-sm font-normal text-gray-400"> / 4.0</span>
            </p>
          </div>
          <div className="ml-auto">
            <p className="text-xs text-gray-500 mb-1 text-right">전체 변화</p>
            <div className="text-right">{deltaBadge(overall_delta)}</div>
          </div>
        </div>
      </div>

      {/* 필러별 점수 차이 */}
      <div className="bg-white rounded-xl border border-gray-200 p-6">
        <h2 className="mb-4">필러별 점수 변화</h2>
        {pillarBarData.length > 0 ? (
          <>
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={pillarBarData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
                <XAxis dataKey="pillar" tick={{ fontSize: 12 }} stroke="#9ca3af" />
                <YAxis tick={{ fontSize: 11 }} stroke="#9ca3af" domain={[-4, 4]} />
                <Tooltip
                  formatter={(v: number) => [`${v > 0 ? "+" : ""}${v.toFixed(2)}`, "변화"]}
                  contentStyle={{ borderRadius: 8, border: "1px solid #e5e7eb" }}
                />
                <Bar dataKey="delta" radius={[4, 4, 0, 0]}>
                  {pillarBarData.map((entry, i) => (
                    <Cell key={i} fill={entry.delta >= 0 ? "#10b981" : "#ef4444"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
            <div className="mt-4 grid grid-cols-2 md:grid-cols-3 gap-3">
              {pillarBarData.map((d) => (
                <div key={d.pillar} className="px-3 py-2 rounded-lg border border-gray-200 bg-gray-50">
                  <p className="text-xs font-semibold text-gray-700">{d.pillar}</p>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {d.from.toFixed(2)} → {d.to.toFixed(2)}
                  </p>
                  <div className="mt-1">{deltaBadge(d.delta)}</div>
                </div>
              ))}
            </div>
          </>
        ) : (
          <p className="text-sm text-gray-500">필러별 비교 데이터가 없습니다.</p>
        )}
      </div>

      {/* 항목별 변경사항 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <ItemListCard
          title="개선된 항목 (충족 추가)"
          items={improved}
          icon={<TrendingUp className="text-green-600" size={18} />}
          color="green"
        />
        <ItemListCard
          title="역행된 항목 (충족 해제)"
          items={regressed}
          icon={<TrendingDown className="text-red-600" size={18} />}
          color="red"
        />
        <ItemListCard
          title="새로 추가된 항목"
          items={new_in_to}
          icon={<GitCompare className="text-blue-600" size={18} />}
          color="blue"
        />
      </div>

      <div className="bg-gray-50 rounded-xl border border-gray-200 p-4 text-sm text-gray-600">
        변경 없음: <strong className="text-gray-800">{unchanged_count}건</strong>
      </div>
    </div>
  );
}

function SessionMetaCard({
  label,
  meta,
  color,
}: {
  label: string;
  meta: AssessmentCompareResponse["from"];
  color: "blue" | "emerald";
}) {
  const colorClass =
    color === "blue"
      ? "border-blue-200 bg-blue-50/40"
      : "border-emerald-200 bg-emerald-50/40";
  return (
    <div className={`rounded-xl border-2 p-5 ${colorClass}`}>
      <p className="text-xs font-semibold text-gray-500 mb-2">{label}</p>
      <h3 className="text-lg font-semibold text-gray-900 mb-1">{meta.org}</h3>
      <p className="text-xs text-gray-500 mb-3">{meta.date} · {meta.manager}</p>
      <div className="flex items-baseline gap-2">
        <p className="text-3xl font-bold text-gray-900">{meta.score?.toFixed(2) ?? "-"}</p>
        <span className="text-sm text-gray-400">/ 4.0</span>
        <span className={`ml-2 inline-block px-2 py-0.5 rounded-full text-xs font-medium ${
          meta.level === "최적화" ? "bg-green-100 text-green-700" :
          meta.level === "향상"   ? "bg-blue-100 text-blue-700"   :
          meta.level === "초기"   ? "bg-yellow-100 text-yellow-700" :
                                    "bg-red-100 text-red-700"
        }`}>
          {maturityLabel(meta.level)}
        </span>
      </div>
    </div>
  );
}

function ItemListCard({
  title,
  items,
  icon,
  color,
}: {
  title: string;
  items: AssessmentCompareResponse["improved"];
  icon: React.ReactNode;
  color: "green" | "red" | "blue";
}) {
  const headerClass =
    color === "green" ? "text-green-700" :
    color === "red"   ? "text-red-700"   :
                        "text-blue-700";
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5">
      <div className="flex items-center gap-2 mb-3">
        {icon}
        <h3 className={`text-sm font-semibold ${headerClass}`}>
          {title} <span className="text-xs text-gray-400">({items.length}건)</span>
        </h3>
      </div>
      {items.length === 0 ? (
        <p className="text-xs text-gray-400 py-4 text-center">항목이 없습니다.</p>
      ) : (
        <ul className="space-y-2 max-h-72 overflow-y-auto pr-1">
          {items.map((it) => (
            <li
              key={it.id}
              className="rounded-lg border border-gray-200 px-3 py-2 text-xs"
            >
              <p className="font-mono text-[10px] text-gray-400 mb-0.5">{it.id}</p>
              <p className="text-sm text-gray-800 leading-snug">{it.item}</p>
              <p className="text-[11px] text-gray-500 mt-1">
                {it.from_result ?? "-"} → {it.to_result ?? "-"}
              </p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
