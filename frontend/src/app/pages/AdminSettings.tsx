import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import {
  ShieldCheck, User, Lock, Bell, Database, Save, RefreshCw, ExternalLink,
  CheckCircle2, AlertTriangle,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { useNotifications } from "../context/NotificationContext";
import {
  updateAuthProfile, changePassword, getSystemMetrics, getRuntimeConfig,
  getOperationalAlerts, ApiError,
  type SystemMetrics, type ConfigItem, type OperationalAlerts,
} from "../../config/api";

// 관리자 전용 설정 — 진단 신청자용 항목(목표 성숙도·판정 임계값·진단 프로필·회원 탈퇴)은 제외하고
// 운영자 관점(계정·비밀번호·운영 알림·보관/보안 정책 요약)으로 재구성.
const ALERT_PREFS_KEY = "zt_admin_alert_prefs";
const LAST_COMPLETED_KEY = "zt_admin_last_completed";

interface AlertPrefs {
  newAssessment: boolean; toolFailure: boolean; backupFailure: boolean; auditAnomaly: boolean;
}
const DEFAULT_PREFS: AlertPrefs = {
  newAssessment: true, toolFailure: true, backupFailure: true, auditAnomaly: true,
};
function loadPrefs(): AlertPrefs {
  try {
    const raw = localStorage.getItem(ALERT_PREFS_KEY);
    if (raw) return { ...DEFAULT_PREFS, ...JSON.parse(raw) };
  } catch { /* ignore */ }
  return DEFAULT_PREFS;
}

export function AdminSettings() {
  const { user, refresh } = useAuth();
  const { addNotification } = useNotifications();
  const navigate = useNavigate();

  // ── 계정 정보 ──
  const [name, setName] = useState(user?.username ?? "");
  const [department, setDepartment] = useState(user?.profile?.department ?? "");
  const [contact, setContact] = useState(user?.profile?.contact ?? "");
  const [acctPw, setAcctPw] = useState("");
  const [savingAcct, setSavingAcct] = useState(false);

  // ── 비밀번호 변경 ──
  const [pwCur, setPwCur] = useState("");
  const [pwNew, setPwNew] = useState("");
  const [pwConf, setPwConf] = useState("");
  const [pwSaving, setPwSaving] = useState(false);

  // ── 운영 알림 ──
  const [prefs, setPrefs] = useState<AlertPrefs>(loadPrefs());
  const [alerts, setAlerts] = useState<OperationalAlerts | null>(null);
  const [checking, setChecking] = useState(false);

  // ── 정책 요약 ──
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [config, setConfig] = useState<ConfigItem[]>([]);

  const runCheck = async (notify: boolean) => {
    setChecking(true);
    try {
      const a = await getOperationalAlerts();
      setAlerts(a);
      if (notify) fireAlertNotifications(a, true);
    } catch (e) {
      if (notify) toast.error(e instanceof Error ? e.message : "점검 실패");
    } finally {
      setChecking(false);
    }
  };

  // 활성 + 토글 ON 인 알림만 알림센터로 발송. dedup=세션당 1회(자동), 강제(버튼)는 항상.
  const fireAlertNotifications = (a: OperationalAlerts, force: boolean) => {
    const p = loadPrefs();
    const fired: string[] = [];
    const once = (key: string, cond: boolean, msg: string, type: "warning" | "error" | "info") => {
      if (!cond) return;
      const sKey = `zt_admin_alert_seen_${key}`;
      if (!force && sessionStorage.getItem(sKey)) return;
      addNotification(msg, type);
      sessionStorage.setItem(sKey, "1");
      fired.push(msg);
    };
    if (p.auditAnomaly) once("audit", !a.audit.ok, `감사 로그 무결성 경고 — 위변조 의심 ${a.audit.broken_count}건`, "error");
    if (p.backupFailure) once("backup", a.backup.overdue, "DB 백업 경과/누락 — 최근 백업이 없거나 7일 초과", "warning");
    if (p.toolFailure) once("tools", a.tools.recent_failures > 0, `도구 연결 실패 의심 — 최근 24h 수집 오류 ${a.tools.recent_failures}건`, "warning");
    if (p.newAssessment) {
      const last = Number(localStorage.getItem(LAST_COMPLETED_KEY) ?? "0");
      const cur = a.assessments.completed_total;
      if (cur > last) {
        once("new", true, `신규 진단 등록 — 완료 진단 ${cur - last}건 추가`, "info");
        localStorage.setItem(LAST_COMPLETED_KEY, String(cur));
      }
    }
    if (force && fired.length === 0) toast.success("활성 운영 알림 없음 — 정상");
  };

  useEffect(() => {
    (async () => {
      try {
        const [m, c] = await Promise.all([getSystemMetrics(), getRuntimeConfig()]);
        setMetrics(m); setConfig(c.config);
      } catch { /* ignore */ }
      runCheck(false).then(() => {
        // 마운트 시 자동 알림(세션당 1회 dedup)
        getOperationalAlerts().then((a) => fireAlertNotifications(a, false)).catch(() => {});
      });
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (user?.role !== "admin") {
    return <div className="p-6 text-gray-500">관리자 전용 화면입니다.</div>;
  }

  const togglePref = (k: keyof AlertPrefs) => {
    const next = { ...prefs, [k]: !prefs[k] };
    setPrefs(next);
    localStorage.setItem(ALERT_PREFS_KEY, JSON.stringify(next));
  };

  const saveAccount = async () => {
    if (!acctPw) { toast.error("변경을 저장하려면 현재 비밀번호를 입력하세요."); return; }
    if (!user) return;
    setSavingAcct(true);
    try {
      const mergedProfile = { ...(user.profile ?? {}), department, contact };
      await updateAuthProfile(user.id, mergedProfile, acctPw, name.trim() || undefined);
      await refresh();
      setAcctPw("");
      toast.success("계정 정보가 저장되었습니다.");
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "저장 실패");
    } finally { setSavingAcct(false); }
  };

  const savePassword = async () => {
    if (pwNew !== pwConf) { toast.error("새 비밀번호가 일치하지 않습니다."); return; }
    if (pwNew.length < 8 || !/[A-Za-z]/.test(pwNew) || !/\d/.test(pwNew)) {
      toast.error("8자 이상 + 영문·숫자 조합이어야 합니다."); return;
    }
    if (!user) return;
    setPwSaving(true);
    try {
      await changePassword(user.id, pwCur, pwNew);
      setPwCur(""); setPwNew(""); setPwConf("");
      toast.success("비밀번호가 변경되었습니다.");
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "변경 실패");
    } finally { setPwSaving(false); }
  };

  const cfg = (k: string) => config.find((c) => c.key === k)?.value;
  const card = "bg-white rounded-xl border border-gray-200 p-6";
  const ro = "px-3 py-2 bg-gray-50 border border-gray-100 rounded-lg text-sm text-gray-600";
  const inp = "px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-200 w-full";

  // 운영 알림 항목 정의 (라벨 + 현재 활성 여부 + 상세)
  const alertRows: { key: keyof AlertPrefs; label: string; active: boolean; detail: string }[] = [
    { key: "newAssessment", label: "신규 진단 등록", active: false,
      detail: alerts ? `완료 진단 누계 ${alerts.assessments.completed_total}건` : "—" },
    { key: "toolFailure", label: "도구 연결 실패", active: !!alerts && alerts.tools.recent_failures > 0,
      detail: alerts ? `최근 24h 수집 오류 ${alerts.tools.recent_failures}건` : "—" },
    { key: "backupFailure", label: "DB 백업 실패/경과", active: !!alerts && alerts.backup.overdue,
      detail: alerts ? (alerts.backup.last_at ? `최근 백업 ${alerts.backup.last_at.slice(0, 10)} · ${alerts.backup.count}개` : "백업 없음") : "—" },
    { key: "auditAnomaly", label: "감사 로그 이상", active: !!alerts && !alerts.audit.ok,
      detail: alerts ? (alerts.audit.ok ? "무결성 정상" : `위변조 의심 ${alerts.audit.broken_count}건`) : "—" },
  ];

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <ShieldCheck className="text-blue-600" size={24} />
        <h1 className="text-xl font-semibold">관리자 설정</h1>
        <span className="text-xs text-gray-400">운영자 계정 · 알림 · 정책</span>
      </div>

      {/* ① 시스템 계정 정보 */}
      <div className={card}>
        <div className="flex items-center gap-2 mb-4"><User className="text-blue-600" size={20} /><h2>시스템 계정 정보</h2></div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div><label className="block text-xs text-gray-500 mb-1">이름</label>
            <input className={inp} value={name} onChange={(e) => setName(e.target.value)} /></div>
          <div><label className="block text-xs text-gray-500 mb-1">로그인 ID</label>
            <div className={ro}>{user.id}</div></div>
          <div><label className="block text-xs text-gray-500 mb-1">이메일 (변경 불가)</label>
            <div className={ro}>{user.email || "-"}</div></div>
          <div><label className="block text-xs text-gray-500 mb-1">역할 / 소속</label>
            <div className={ro}>{user.role} · {user.orgName || "-"}</div></div>
          <div><label className="block text-xs text-gray-500 mb-1">부서</label>
            <input className={inp} value={department} onChange={(e) => setDepartment(e.target.value)} placeholder="예: 보안운영팀" /></div>
          <div><label className="block text-xs text-gray-500 mb-1">연락처</label>
            <input className={inp} value={contact} onChange={(e) => setContact(e.target.value)} placeholder="예: 010-0000-0000" /></div>
        </div>
        <div className="flex items-center gap-2 mt-4">
          <input type="password" className={`${inp} max-w-xs`} value={acctPw} onChange={(e) => setAcctPw(e.target.value)} placeholder="현재 비밀번호 (저장 확인용)" />
          <button onClick={saveAccount} disabled={savingAcct}
            className="inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700 disabled:opacity-50">
            <Save size={15} /> 저장
          </button>
        </div>
      </div>

      {/* ② 비밀번호 변경 */}
      <div className={card}>
        <div className="flex items-center gap-2 mb-4"><Lock className="text-blue-600" size={20} /><h2>비밀번호 변경</h2></div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input type="password" className={inp} value={pwCur} onChange={(e) => setPwCur(e.target.value)} placeholder="현재 비밀번호" />
          <input type="password" className={inp} value={pwNew} onChange={(e) => setPwNew(e.target.value)} placeholder="새 비밀번호 (8자+영문숫자)" />
          <input type="password" className={inp} value={pwConf} onChange={(e) => setPwConf(e.target.value)} placeholder="새 비밀번호 확인" />
        </div>
        <button onClick={savePassword} disabled={pwSaving || !pwCur || !pwNew}
          className="mt-4 inline-flex items-center gap-1.5 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700 disabled:opacity-50">
          <Save size={15} /> 비밀번호 변경
        </button>
      </div>

      {/* ③ 운영 알림 설정 */}
      <div className={card}>
        <div className="flex items-center gap-2 mb-1">
          <Bell className="text-blue-600" size={20} /><h2>운영 알림 설정</h2>
          <button onClick={() => runCheck(true)} disabled={checking}
            className="ml-auto inline-flex items-center gap-1.5 px-3 py-1.5 text-sm border rounded-md hover:bg-gray-50 disabled:opacity-50">
            <RefreshCw size={14} className={checking ? "animate-spin" : ""} /> 지금 점검
          </button>
        </div>
        <p className="text-xs text-gray-500 mb-4">관리자 관점 운영 이벤트를 서버가 실시간 계산해 알림센터로 전달합니다. (토글 ON 인 항목만)</p>
        <div className="space-y-2">
          {alertRows.map((r) => (
            <div key={r.key} className="flex items-center gap-3 py-2 border-b border-gray-50 text-sm">
              <span className={`w-2 h-2 rounded-full ${r.active ? "bg-red-500" : "bg-emerald-400"}`} />
              <span className="w-40 text-gray-700">{r.label}</span>
              <span className="flex-1 text-xs text-gray-400">{r.detail}</span>
              {r.active && <span className="text-[11px] text-red-600 font-medium">● 활성</span>}
              <button onClick={() => togglePref(r.key)}
                className={`px-3 py-1 rounded-full text-xs font-medium ${prefs[r.key] ? "bg-blue-50 text-blue-600" : "bg-gray-100 text-gray-400"}`}>
                {prefs[r.key] ? "ON" : "OFF"}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* ④ 데이터 보관·보안 정책 요약 (read-only) */}
      <div className={card}>
        <div className="flex items-center gap-2 mb-4">
          <Database className="text-blue-600" size={20} /><h2>데이터 보관·보안 정책 요약</h2>
          <button onClick={() => navigate("/admin")} className="ml-auto inline-flex items-center gap-1 text-sm text-blue-600 hover:underline">
            운영 콘솔에서 변경 <ExternalLink size={13} />
          </button>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
          {[
            ["세션 보관", `${cfg("session_retention_days") ?? 90}일 후 자동 삭제`],
            ["증적 at-rest 암호화", metrics?.encryption_enabled ? `ON (${metrics.encryption_key_source})` : "OFF"],
            ["감사 로그", `${metrics?.counts.audit_logs ?? "-"}건 (해시 체인)`],
            ["자동 백업 주기", `${cfg("backup_interval_hours") ?? 0}시간 (0=수동)`],
            ["주기 평가 스케줄러", String(cfg("scheduler_enable") ?? "true") === "true" ? "활성" : "비활성"],
            ["전송 보안", "HTTPS + HSTS (운영 nginx)"],
          ].map(([k, v]) => (
            <div key={k} className="border border-gray-100 rounded-lg p-3">
              <div className="text-xs text-gray-500">{k}</div>
              <div className="text-gray-800 font-medium mt-0.5 flex items-center gap-1">
                {String(v).startsWith("ON") || v === "활성" ? <CheckCircle2 size={14} className="text-emerald-500" /> : null}
                {String(v) === "OFF" ? <AlertTriangle size={14} className="text-amber-500" /> : null}
                <span className="text-[13px]">{v}</span>
              </div>
            </div>
          ))}
        </div>
        <p className="text-[11px] text-gray-400 mt-3">* 상세 변경(보관 일수·백업 주기·스케줄러 등)은 운영 콘솔의 동적 설정에서 수행합니다.</p>
      </div>
    </div>
  );
}
