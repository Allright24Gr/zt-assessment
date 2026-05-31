import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  Activity, ShieldCheck, Database, Clock, RefreshCw, Save, Plus, Trash2,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import {
  getSystemMetrics, getRuntimeConfig, setRuntimeConfig, getAuditLogs, verifyAuditChain,
  createBackup, listBackups, listSchedules, createSchedule, updateSchedule, deleteSchedule,
  type SystemMetrics, type ConfigItem, type AuditLogItem, type ScheduleItem,
} from "../../config/api";

// 운영 콘솔 — admin 전용. MAR-009(모니터링)/MAR-010(동적설정)/MAR-014(백업)/
// SER-006·SER-009(감사 로그·체인 검증)/MAR-004(주기 평가 스케줄)을 한 화면에 노출.
export function AdminConsole() {
  const { user } = useAuth();
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [config, setConfig] = useState<ConfigItem[]>([]);
  const [audit, setAudit] = useState<AuditLogItem[]>([]);
  const [auditVerify, setAuditVerify] = useState<{ verified: number; checked: number; ok: boolean } | null>(null);
  const [backups, setBackups] = useState<Array<{ filename: string; size_bytes: number; modified_at: string }>>([]);
  const [schedules, setSchedules] = useState<ScheduleItem[]>([]);
  const [newSched, setNewSched] = useState({ name: "", interval_hours: 24 });
  const [busy, setBusy] = useState(false);

  const loadAll = async () => {
    try {
      const [m, c, a, b, s] = await Promise.all([
        getSystemMetrics(), getRuntimeConfig(), getAuditLogs({ limit: 30 }),
        listBackups(), listSchedules(),
      ]);
      setMetrics(m);
      setConfig(c.config);
      setAudit(a.items);
      setBackups(b.backups);
      setSchedules(s.schedules);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "운영 데이터 로드 실패");
    }
  };

  useEffect(() => { loadAll(); }, []);

  if (user?.role !== "admin") {
    return <div className="p-6 text-gray-500">관리자 전용 화면입니다.</div>;
  }

  const saveConfig = async (key: string, value: string | number | boolean) => {
    try {
      await setRuntimeConfig(key, value);
      toast.success(`${key} 변경됨 (즉시 반영)`);
      const c = await getRuntimeConfig();
      setConfig(c.config);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "설정 저장 실패");
    }
  };

  const runVerify = async () => {
    try {
      const r = await verifyAuditChain();
      setAuditVerify(r);
      toast[r.ok ? "success" : "error"](
        r.ok ? `감사 로그 무결성 OK (${r.verified}/${r.checked})` : `위변조 의심 ${r.broken_count}건`,
      );
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "검증 실패");
    }
  };

  const runBackup = async () => {
    setBusy(true);
    try {
      const r = await createBackup();
      toast.success(`백업 완료: ${r.rows}행 / ${r.tables}테이블`);
      setBackups((await listBackups()).backups);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "백업 실패");
    } finally { setBusy(false); }
  };

  const addSchedule = async () => {
    if (!newSched.name.trim()) { toast.error("스케줄 이름을 입력하세요."); return; }
    try {
      await createSchedule({
        name: newSched.name.trim(), interval_hours: newSched.interval_hours,
        config: { tool_scope: { keycloak: true, wazuh: true, nmap: true, trivy: true } },
      });
      toast.success("스케줄 생성됨");
      setNewSched({ name: "", interval_hours: 24 });
      setSchedules((await listSchedules()).schedules);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "스케줄 생성 실패");
    }
  };

  const toggleSched = async (s: ScheduleItem) => {
    try {
      await updateSchedule(s.schedule_id, { enabled: !s.enabled });
      setSchedules((await listSchedules()).schedules);
    } catch (e) { toast.error(e instanceof Error ? e.message : "변경 실패"); }
  };

  const removeSched = async (id: number) => {
    try {
      await deleteSchedule(id);
      setSchedules((prev) => prev.filter((x) => x.schedule_id !== id));
    } catch (e) { toast.error(e instanceof Error ? e.message : "삭제 실패"); }
  };

  const card = "bg-white rounded-xl border border-gray-200 p-6";

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <ShieldCheck className="text-blue-600" size={24} />
        <h1 className="text-xl font-semibold">운영 콘솔</h1>
        <button onClick={loadAll} className="ml-auto inline-flex items-center gap-1.5 px-3 py-1.5 text-sm border rounded-md hover:bg-gray-50">
          <RefreshCw size={14} /> 새로고침
        </button>
      </div>

      {/* MAR-009 시스템 상태 */}
      <div className={card}>
        <div className="flex items-center gap-2 mb-4"><Activity className="text-blue-600" size={20} /><h2>시스템 상태</h2></div>
        {metrics ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              ["가동 시간", `${Math.floor(metrics.uptime_seconds / 60)}분`],
              ["DB", metrics.db_ok ? "정상" : "오류"],
              ["완료 진단", `${metrics.counts.sessions_done ?? 0}`],
              ["결과 행", `${metrics.counts.results ?? 0}`],
              ["감사 로그", `${metrics.counts.audit_logs ?? 0}`],
              ["캐시 적중률", `${(metrics.cache.hit_rate * 100).toFixed(0)}%`],
              ["at-rest 암호화", metrics.encryption_enabled ? "ON" : "OFF"],
              ["스케줄(활성)", `${metrics.counts.schedules_enabled ?? 0}`],
            ].map(([label, val]) => (
              <div key={label} className="border border-gray-100 rounded-lg p-3">
                <div className="text-xs text-gray-500">{label}</div>
                <div className="text-lg font-semibold text-gray-800">{val}</div>
              </div>
            ))}
          </div>
        ) : <div className="text-sm text-gray-400">불러오는 중…</div>}
      </div>

      {/* MAR-010 동적 설정 */}
      <div className={card}>
        <div className="flex items-center gap-2 mb-4"><Save className="text-blue-600" size={20} /><h2>동적 운영 설정 (재시작 없이 반영)</h2></div>
        <div className="space-y-2">
          {config.map((c) => (
            <div key={c.key} className="flex items-center gap-3 text-sm border-b border-gray-50 py-1.5">
              <span className="w-56 text-gray-700">{c.label}</span>
              <code className="text-xs text-gray-400 w-48">{c.key}</code>
              {c.type === "bool" ? (
                <select
                  defaultValue={String(c.value)}
                  onChange={(e) => saveConfig(c.key, e.target.value === "true")}
                  className="border rounded px-2 py-1 text-sm"
                >
                  <option value="true">true</option>
                  <option value="false">false</option>
                </select>
              ) : (
                <ConfigNumberInput item={c} onSave={saveConfig} />
              )}
            </div>
          ))}
        </div>
      </div>

      {/* SER-006 / SER-009 감사 로그 */}
      <div className={card}>
        <div className="flex items-center gap-2 mb-4">
          <ShieldCheck className="text-blue-600" size={20} /><h2>감사 로그</h2>
          <button onClick={runVerify} className="ml-auto inline-flex items-center gap-1.5 px-3 py-1.5 text-sm border rounded-md hover:bg-gray-50">
            해시 체인 검증
          </button>
        </div>
        {auditVerify && (
          <div className={`mb-3 text-sm px-3 py-2 rounded-md ${auditVerify.ok ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-700"}`}>
            {auditVerify.ok ? `무결성 정상 — ${auditVerify.verified}/${auditVerify.checked} 검증됨` : "위변조 의심 — 체인 불일치"}
          </div>
        )}
        <div className="overflow-x-auto max-h-72 overflow-y-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-gray-50 text-gray-500">
              <tr><th className="text-left px-2 py-1.5">시각</th><th className="text-left px-2 py-1.5">이벤트</th><th className="text-left px-2 py-1.5">계정</th><th className="text-left px-2 py-1.5">IP</th><th className="text-center px-2 py-1.5">성공</th></tr>
            </thead>
            <tbody>
              {audit.map((a) => (
                <tr key={a.audit_id} className="border-t border-gray-100">
                  <td className="px-2 py-1.5 text-gray-500">{a.created_at?.slice(0, 19).replace("T", " ")}</td>
                  <td className="px-2 py-1.5">{a.event_type}</td>
                  <td className="px-2 py-1.5">{a.login_id ?? "-"}</td>
                  <td className="px-2 py-1.5 text-gray-400">{a.source_ip ?? "-"}</td>
                  <td className="px-2 py-1.5 text-center">{a.success ? "✓" : "✗"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* MAR-014 백업 */}
      <div className={card}>
        <div className="flex items-center gap-2 mb-4">
          <Database className="text-blue-600" size={20} /><h2>DB 백업/복구</h2>
          <button onClick={runBackup} disabled={busy} className="ml-auto inline-flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50">
            <Plus size={14} /> 백업 생성
          </button>
        </div>
        <ul className="text-xs text-gray-600 space-y-1 max-h-40 overflow-y-auto">
          {backups.length === 0 && <li className="text-gray-400">백업 없음</li>}
          {backups.map((b) => (
            <li key={b.filename} className="flex justify-between border-b border-gray-50 py-1">
              <span>{b.filename}</span>
              <span className="text-gray-400">{(b.size_bytes / 1024).toFixed(0)} KB · {b.modified_at.slice(0, 19).replace("T", " ")}</span>
            </li>
          ))}
        </ul>
        <p className="text-[11px] text-gray-400 mt-2">복구: <code>python scripts/backup_db.py restore &lt;파일&gt;</code></p>
      </div>

      {/* MAR-004 / SFR-AUTO-005 주기 평가 스케줄 */}
      <div className={card}>
        <div className="flex items-center gap-2 mb-4"><Clock className="text-blue-600" size={20} /><h2>주기 평가 스케줄 (데모 모드)</h2></div>
        <div className="flex items-center gap-2 mb-4">
          <input value={newSched.name} onChange={(e) => setNewSched((p) => ({ ...p, name: e.target.value }))}
            placeholder="스케줄 이름" className="border rounded px-3 py-1.5 text-sm flex-1" />
          <input type="number" min={1} value={newSched.interval_hours}
            onChange={(e) => setNewSched((p) => ({ ...p, interval_hours: Number(e.target.value) }))}
            className="border rounded px-3 py-1.5 text-sm w-24" /><span className="text-sm text-gray-500">시간마다</span>
          <button onClick={addSchedule} className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700">
            <Plus size={14} /> 추가
          </button>
        </div>
        <ul className="text-sm space-y-1">
          {schedules.length === 0 && <li className="text-gray-400 text-xs">등록된 스케줄 없음</li>}
          {schedules.map((s) => (
            <li key={s.schedule_id} className="flex items-center gap-3 border-b border-gray-50 py-1.5">
              <span className="font-medium">{s.name}</span>
              <span className="text-xs text-gray-500">{s.interval_hours}시간 주기</span>
              <span className="text-xs text-gray-400">다음: {s.next_run_at?.slice(0, 16).replace("T", " ") ?? "-"}</span>
              <button onClick={() => toggleSched(s)}
                className={`ml-auto px-2 py-0.5 rounded text-xs ${s.enabled ? "bg-emerald-50 text-emerald-700" : "bg-gray-100 text-gray-500"}`}>
                {s.enabled ? "활성" : "비활성"}
              </button>
              <button onClick={() => removeSched(s.schedule_id)} className="p-1 text-gray-400 hover:text-red-600"><Trash2 size={14} /></button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function ConfigNumberInput({ item, onSave }: { item: ConfigItem; onSave: (k: string, v: number) => void }) {
  const [val, setVal] = useState(String(item.value));
  return (
    <div className="flex items-center gap-2">
      <input value={val} onChange={(e) => setVal(e.target.value)} className="border rounded px-2 py-1 text-sm w-28" />
      <button onClick={() => onSave(item.key, Number(val))} className="px-2 py-1 text-xs border rounded hover:bg-gray-50">저장</button>
      <span className="text-[11px] text-gray-400">기본 {String(item.default)}</span>
    </div>
  );
}
