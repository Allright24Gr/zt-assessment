import { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router";
import { Settings as SettingsIcon, Bell, Target, User, Save, Lock, X, Loader2, KeyRound } from "lucide-react";
import { toast } from "sonner";
import { PILLARS } from "../data/constants";
import { useAuth } from "../context/AuthContext";
import { updateAuthProfile, changePassword, ApiError, type ProfileFields } from "../../config/api";

const STORAGE_KEY = "zt_settings";

interface PersistedSettings {
  targetScores: number[];
  wazuhThreshold: number;
  trivyCritical: boolean;
  trivyHigh: boolean;
  trivyMedium: boolean;
  coverageThreshold: number;
  completeNotification: boolean;
  errorNotification: boolean;
  name: string;
  email: string;
  organization: string;
}

const DEFAULT_SETTINGS: PersistedSettings = {
  targetScores: PILLARS.map(() => 3.5),
  wazuhThreshold: 75,
  trivyCritical: true,
  trivyHigh: true,
  trivyMedium: false,
  coverageThreshold: 90,
  completeNotification: true,
  errorNotification: true,
  name: "관리자",
  email: "admin@example.com",
  organization: "보안팀",
};

interface ProfileFormState {
  department: string;
  contact: string;
  org_type: string;
  infra_type: string;
  employees: string;
  servers: string;
  applications: string;
  note: string;
}

function profileFromUser(p?: ProfileFields | null): ProfileFormState {
  return {
    department:   p?.department    ?? "",
    contact:      p?.contact       ?? "",
    org_type:     p?.org_type      ?? "기업",
    infra_type:   p?.infra_type    ?? "온프레미스",
    employees:    p?.employees    != null ? String(p.employees)    : "",
    servers:      p?.servers      != null ? String(p.servers)      : "",
    applications: p?.applications != null ? String(p.applications) : "",
    note:         p?.note          ?? "",
  };
}

export function Settings() {
  const { user, setUser } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [targetScores, setTargetScores] = useState(DEFAULT_SETTINGS.targetScores);
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);

  // 진단 프로필 (백엔드 동기화)
  const [profileForm, setProfileForm] = useState<ProfileFormState>(profileFromUser(user?.profile));
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmPassword, setConfirmPassword] = useState("");
  const [savingProfile, setSavingProfile] = useState(false);
  const confirmInputRef = useRef<HTMLInputElement>(null);

  // 비밀번호 변경 모달 (작업 H-fe)
  const [pwModalOpen, setPwModalOpen] = useState(false);
  const [pwCurrent, setPwCurrent] = useState("");
  const [pwNew, setPwNew] = useState("");
  const [pwConfirm, setPwConfirm] = useState("");
  const [pwError, setPwError] = useState("");
  const [pwSaving, setPwSaving] = useState(false);
  const pwFirstInputRef = useRef<HTMLInputElement>(null);
  const pwLastButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setProfileForm(profileFromUser(user?.profile));
  }, [user?.profile]);

  // 비밀번호 확인 모달 — ESC 닫기 + autoFocus
  useEffect(() => {
    if (!confirmOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setConfirmOpen(false);
        setConfirmPassword("");
      }
    };
    window.addEventListener("keydown", onKeyDown);
    const t = window.setTimeout(() => confirmInputRef.current?.focus(), 0);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.clearTimeout(t);
    };
  }, [confirmOpen]);

  // 비밀번호 변경 모달 — ESC 닫기 + autoFocus + focus trap
  useEffect(() => {
    if (!pwModalOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !pwSaving) {
        closePwModal();
      }
      // 간단한 focus trap: Tab/Shift+Tab만 다룬다.
      if (e.key === "Tab") {
        const first = pwFirstInputRef.current;
        const last = pwLastButtonRef.current;
        if (!first || !last) return;
        const active = document.activeElement;
        if (e.shiftKey && active === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && active === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener("keydown", onKeyDown);
    const t = window.setTimeout(() => pwFirstInputRef.current?.focus(), 0);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.clearTimeout(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pwModalOpen, pwSaving]);

  // Dashboard "지금 변경" 진입 시 자동 오픈 (작업 N)
  useEffect(() => {
    const state = location.state as { openPasswordModal?: boolean } | null;
    if (state?.openPasswordModal) {
      setPwModalOpen(true);
      // 뒤로가기 시 다시 모달이 열리지 않도록 state 제거
      navigate(location.pathname, { replace: true, state: null });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const closePwModal = () => {
    setPwModalOpen(false);
    setPwCurrent("");
    setPwNew("");
    setPwConfirm("");
    setPwError("");
  };

  // 비밀번호 정책: 8자 이상 + 영문+숫자 혼합
  const validateNewPassword = (next: string, confirm: string): string => {
    if (next.length < 8) return "새 비밀번호는 8자 이상이어야 합니다.";
    if (!/[A-Za-z]/.test(next) || !/[0-9]/.test(next)) {
      return "새 비밀번호는 영문과 숫자를 모두 포함해야 합니다.";
    }
    if (next !== confirm) return "새 비밀번호 확인 값이 일치하지 않습니다.";
    return "";
  };

  const submitPasswordChange = async () => {
    if (!user?.id) {
      toast.error("로그인 정보를 확인할 수 없습니다.");
      return;
    }
    if (!pwCurrent) {
      setPwError("현재 비밀번호를 입력해주세요.");
      return;
    }
    const v = validateNewPassword(pwNew, pwConfirm);
    if (v) {
      setPwError(v);
      return;
    }
    setPwError("");
    setPwSaving(true);
    try {
      await changePassword(user.id, pwCurrent, pwNew);
      toast.success("비밀번호가 변경되었습니다.");
      try {
        sessionStorage.removeItem("zt_seed_password_warning");
      } catch { /* ignore */ }
      closePwModal();
    } catch (err) {
      console.warn("[settings] change password:", err);
      if (err instanceof ApiError) {
        if (err.status === 401) {
          setPwError("현재 비밀번호가 일치하지 않습니다.");
        } else if (err.status === 400) {
          setPwError("비밀번호 정책: 8자 이상 + 영문+숫자");
        } else if (err.status === 423 || err.status === 429) {
          setPwError("로그인 잠금 상태입니다. 잠시 후 다시 시도하세요.");
        } else {
          setPwError("비밀번호 변경 중 오류가 발생했습니다.");
        }
      } else {
        setPwError("비밀번호 변경 중 오류가 발생했습니다.");
      }
    } finally {
      setPwSaving(false);
    }
  };

  const openProfileConfirm = () => {
    if (!user?.id) {
      toast.error("로그인 정보를 확인할 수 없습니다.");
      return;
    }
    setConfirmPassword("");
    setConfirmOpen(true);
  };

  const submitProfile = async () => {
    if (!user?.id) return;
    if (!confirmPassword) {
      toast.error("비밀번호를 입력해주세요.");
      return;
    }
    const payload: ProfileFields = {
      org_name:     user.orgName,
      department:   profileForm.department.trim() || undefined,
      contact:      profileForm.contact.trim()    || undefined,
      org_type:     profileForm.org_type          || undefined,
      infra_type:   profileForm.infra_type        || undefined,
      employees:    profileForm.employees    ? Number(profileForm.employees)    : undefined,
      servers:      profileForm.servers      ? Number(profileForm.servers)      : undefined,
      applications: profileForm.applications ? Number(profileForm.applications) : undefined,
      note:         profileForm.note.trim()       || undefined,
    };
    setSavingProfile(true);
    try {
      const updated = await updateAuthProfile(user.id, payload, confirmPassword);
      setUser({
        id: updated.login_id,
        user_id: updated.user_id,
        username: updated.name,
        role: updated.role === "admin" ? "admin" : "user",
        orgName: updated.org_name,
        org_id: updated.org_id,
        email: updated.email,
        profile: updated.profile,
      });
      toast.success("진단 프로필이 저장되었습니다.");
      setConfirmOpen(false);
      setConfirmPassword("");
    } catch (err) {
      console.warn("[settings] profile save:", err);
      if (err instanceof ApiError && err.status === 401) {
        toast.error("비밀번호가 일치하지 않습니다.");
      } else {
        toast.error("프로필 저장 중 오류가 발생했습니다.");
      }
    } finally {
      setSavingProfile(false);
    }
  };

  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (!stored) return;
      const parsed = JSON.parse(stored) as Partial<PersistedSettings>;
      setSettings({ ...DEFAULT_SETTINGS, ...parsed });
      if (Array.isArray(parsed.targetScores) && parsed.targetScores.length === PILLARS.length) {
        setTargetScores(parsed.targetScores);
      }
    } catch (err) {
      console.warn("[settings] load failed:", err);
    }
  }, []);

  const handleSave = () => {
    try {
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({ ...settings, targetScores }),
      );
      toast.success("설정이 저장되었습니다. (브라우저 로컬에 보관)");
    } catch (err) {
      console.warn("[settings] save failed:", err);
      toast.error("설정 저장에 실패했습니다.");
    }
  };

  const updateTarget = (index: number, value: number) => {
    setTargetScores((prev) => prev.map((score, i) => (i === index ? value : score)));
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <h1>설정</h1>
        <span className="px-2.5 py-0.5 text-xs font-medium rounded bg-yellow-100 text-yellow-800 border border-yellow-200">
          베타 · 브라우저 로컬 저장
        </span>
      </div>
      <p className="text-sm text-gray-500">
        현재 설정은 백엔드와 연동되지 않고 브라우저에만 저장됩니다. 진단 임계값은 백엔드 정책 파일을 직접 수정해주세요.
      </p>

      {/* Threshold Settings */}
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="flex items-center gap-2 mb-6">
          <SettingsIcon className="text-blue-600" size={20} />
          <h2>판정 임계값 설정</h2>
        </div>

        <div className="space-y-6">
          <div>
            <label className="block mb-2">Wazuh SCA 점수 기준값 (%)</label>
            <div className="flex items-center gap-4">
              <input
                type="range"
                min="0"
                max="100"
                value={settings.wazuhThreshold}
                onChange={(e) =>
                  setSettings({ ...settings, wazuhThreshold: parseInt(e.target.value) })
                }
                className="flex-1"
              />
              <span className="text-lg font-semibold text-blue-600 w-16 text-center">
                {settings.wazuhThreshold}%
              </span>
            </div>
            <p className="text-sm text-gray-600 mt-2">
              이 값 이상일 때 해당 항목을 통과로 판정합니다
            </p>
          </div>

          <div>
            <label className="block mb-3">Trivy CVE Severity 기준</label>
            <div className="space-y-2">
              <label className="flex items-center gap-3 p-3 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.trivyCritical}
                  onChange={(e) =>
                    setSettings({ ...settings, trivyCritical: e.target.checked })
                  }
                  className="w-4 h-4"
                />
                <span className="flex-1">Critical</span>
                <span className="px-2 py-1 bg-red-100 text-red-700 rounded text-sm">위험</span>
              </label>
              <label className="flex items-center gap-3 p-3 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.trivyHigh}
                  onChange={(e) =>
                    setSettings({ ...settings, trivyHigh: e.target.checked })
                  }
                  className="w-4 h-4"
                />
                <span className="flex-1">High</span>
                <span className="px-2 py-1 bg-orange-100 text-orange-700 rounded text-sm">높음</span>
              </label>
              <label className="flex items-center gap-3 p-3 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.trivyMedium}
                  onChange={(e) =>
                    setSettings({ ...settings, trivyMedium: e.target.checked })
                  }
                  className="w-4 h-4"
                />
                <span className="flex-1">Medium</span>
                <span className="px-2 py-1 bg-yellow-100 text-yellow-700 rounded text-sm">보통</span>
              </label>
            </div>
          </div>

          <div>
            <label className="block mb-2">커버리지 비율 기준값 (%)</label>
            <div className="flex items-center gap-4">
              <input
                type="range"
                min="50"
                max="100"
                value={settings.coverageThreshold}
                onChange={(e) =>
                  setSettings({ ...settings, coverageThreshold: parseInt(e.target.value) })
                }
                className="flex-1"
              />
              <span className="text-lg font-semibold text-blue-600 w-16 text-center">
                {settings.coverageThreshold}%
              </span>
            </div>
            <p className="text-sm text-gray-600 mt-2">
              전체 항목 중 이 비율 이상 확인되어야 진단이 유효합니다
            </p>
          </div>
        </div>
      </div>

      {/* Target Maturity Settings */}
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="flex items-center gap-2 mb-6">
          <Target className="text-emerald-600" size={20} />
          <h2>목표 성숙도 설정</h2>
        </div>

        <div className="space-y-4">
          {PILLARS.map((pillar, index) => (
            <div key={pillar.key}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-medium text-gray-700">{pillar.label}</span>
                <span className="text-sm font-semibold text-emerald-600">{targetScores[index].toFixed(1)} / 4.0</span>
              </div>
              <input
                type="range"
                min="0.5"
                max="4"
                step="0.1"
                value={targetScores[index]}
                onChange={(event) => updateTarget(index, Number(event.target.value))}
                className="w-full accent-emerald-600"
              />
              <div className="flex justify-between text-[11px] text-gray-400">
                <span>0.5</span>
                <span>4.0</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Notification Settings */}
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="flex items-center gap-2 mb-6">
          <Bell className="text-blue-600" size={20} />
          <h2>알림 설정</h2>
        </div>

        <div className="space-y-3">
          <label className="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
            <div>
              <h3>진단 완료 알림</h3>
              <p className="text-sm text-gray-600">진단이 완료되면 알림을 받습니다</p>
            </div>
            <input
              type="checkbox"
              checked={settings.completeNotification}
              onChange={(e) =>
                setSettings({ ...settings, completeNotification: e.target.checked })
              }
              className="w-5 h-5"
            />
          </label>
          <label className="flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
            <div>
              <h3>오류 발생 시 알림</h3>
              <p className="text-sm text-gray-600">진단 중 오류가 발생하면 즉시 알림을 받습니다</p>
            </div>
            <input
              type="checkbox"
              checked={settings.errorNotification}
              onChange={(e) =>
                setSettings({ ...settings, errorNotification: e.target.checked })
              }
              className="w-5 h-5"
            />
          </label>
        </div>
      </div>

      {/* 진단 프로필 (백엔드 동기화) */}
      {user && (
        <div className="bg-white rounded-lg border border-gray-200 p-6">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <User className="text-blue-600" size={20} />
              <h2>진단 프로필</h2>
            </div>
            <span className="px-2 py-0.5 text-[11px] font-medium rounded bg-blue-50 text-blue-700 border border-blue-100">
              백엔드 동기화 · {user.orgName ?? "-"}
            </span>
          </div>
          <p className="text-sm text-gray-500 mb-4">
            새 진단 시작 시 이 정보가 자동으로 입력됩니다. 저장 시 비밀번호 재확인이 필요합니다.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block mb-2 text-sm text-gray-700">부서 / 직책</label>
              <input
                type="text"
                value={profileForm.department}
                onChange={(e) => setProfileForm({ ...profileForm, department: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                placeholder="예: 정보보안팀 / 팀장"
              />
            </div>
            <div>
              <label className="block mb-2 text-sm text-gray-700">연락처</label>
              <input
                type="tel"
                value={profileForm.contact}
                onChange={(e) => setProfileForm({ ...profileForm, contact: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                placeholder="010-0000-0000"
              />
            </div>
            <div>
              <label className="block mb-2 text-sm text-gray-700">기관 유형</label>
              <select
                value={profileForm.org_type}
                onChange={(e) => setProfileForm({ ...profileForm, org_type: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg"
              >
                {["기업", "공공기관", "금융기관", "의료기관"].map((t) => <option key={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label className="block mb-2 text-sm text-gray-700">인프라 유형</label>
              <select
                value={profileForm.infra_type}
                onChange={(e) => setProfileForm({ ...profileForm, infra_type: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg"
              >
                {["온프레미스", "클라우드 (AWS)", "클라우드 (Azure)", "클라우드 (GCP)", "하이브리드"].map((t) => <option key={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label className="block mb-2 text-sm text-gray-700">전체 임직원 수</label>
              <input
                type="number"
                min={0}
                value={profileForm.employees}
                onChange={(e) => setProfileForm({ ...profileForm, employees: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                placeholder="예: 500"
              />
            </div>
            <div>
              <label className="block mb-2 text-sm text-gray-700">전체 서버 수</label>
              <input
                type="number"
                min={0}
                value={profileForm.servers}
                onChange={(e) => setProfileForm({ ...profileForm, servers: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                placeholder="예: 50"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block mb-2 text-sm text-gray-700">운영 중 애플리케이션 수</label>
              <input
                type="number"
                min={0}
                value={profileForm.applications}
                onChange={(e) => setProfileForm({ ...profileForm, applications: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg"
                placeholder="예: 30"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block mb-2 text-sm text-gray-700">비고 / 진단 목적</label>
              <textarea
                rows={3}
                value={profileForm.note}
                onChange={(e) => setProfileForm({ ...profileForm, note: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg resize-none"
                placeholder="진단 배경, 중점 검토 영역, 기타 참고 사항"
              />
            </div>
          </div>
          <div className="mt-5 flex justify-end">
            <button
              onClick={openProfileConfirm}
              className="flex items-center gap-2 px-5 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              <Lock size={16} />
              비밀번호 확인 후 저장
            </button>
          </div>
        </div>
      )}

      {/* User Account Settings */}
      <div className="bg-white rounded-lg border border-gray-200 p-6">
        <div className="flex items-center gap-2 mb-6">
          <User className="text-blue-600" size={20} />
          <h2>사용자 계정 정보</h2>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block mb-2">이름</label>
            <input
              type="text"
              value={settings.name}
              onChange={(e) => setSettings({ ...settings, name: e.target.value })}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg"
            />
          </div>
          <div>
            <label className="block mb-2">이메일</label>
            <input
              type="email"
              value={settings.email}
              onChange={(e) => setSettings({ ...settings, email: e.target.value })}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg"
            />
          </div>
          <div>
            <label className="block mb-2">소속</label>
            <input
              type="text"
              value={settings.organization}
              onChange={(e) => setSettings({ ...settings, organization: e.target.value })}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg"
            />
          </div>
          <div>
            <label className="block mb-2">비밀번호 변경</label>
            <button
              type="button"
              onClick={() => setPwModalOpen(true)}
              className="inline-flex items-center gap-1.5 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              <KeyRound size={14} />
              비밀번호 변경하기
            </button>
          </div>
        </div>
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          <Save size={20} />
          설정 저장
        </button>
      </div>

      {/* 비밀번호 재확인 모달 */}
      {confirmOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4"
          onClick={() => !savingProfile && setConfirmOpen(false)}
          aria-hidden="true"
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="profile-confirm-title"
            className="relative bg-white rounded-xl shadow-2xl w-full max-w-sm p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              type="button"
              onClick={() => !savingProfile && setConfirmOpen(false)}
              className="absolute top-3 right-3 text-gray-400 hover:text-gray-600"
              aria-label="닫기"
            >
              <X size={18} />
            </button>
            <div className="flex items-center gap-2 mb-3">
              <Lock size={18} className="text-blue-600" aria-hidden="true" />
              <h2 id="profile-confirm-title" className="text-base font-semibold text-gray-900">
                비밀번호 확인
              </h2>
            </div>
            <p className="text-sm text-gray-600 mb-4">
              진단 프로필 정보를 저장하려면 현재 비밀번호를 입력해주세요.
            </p>
            <form
              onSubmit={(e) => { e.preventDefault(); submitProfile(); }}
              className="space-y-3"
            >
              <input
                ref={confirmInputRef}
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="현재 비밀번호"
                aria-label="현재 비밀번호"
                disabled={savingProfile}
                required
              />
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => !savingProfile && setConfirmOpen(false)}
                  className="flex-1 bg-gray-100 text-gray-700 py-2 rounded-lg hover:bg-gray-200 text-sm font-medium"
                  disabled={savingProfile}
                >
                  취소
                </button>
                <button
                  type="submit"
                  className={`flex-1 flex items-center justify-center gap-1.5 py-2 rounded-lg text-sm font-medium text-white ${
                    savingProfile ? "bg-blue-400 cursor-not-allowed" : "bg-blue-600 hover:bg-blue-700"
                  }`}
                  disabled={savingProfile}
                >
                  {savingProfile ? <><Loader2 size={14} className="animate-spin" /> 저장 중...</> : "확인 후 저장"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* 비밀번호 변경 모달 (작업 H-fe) */}
      {pwModalOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4"
          onClick={() => !pwSaving && closePwModal()}
          aria-hidden="true"
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="pw-change-title"
            className="relative bg-white rounded-xl shadow-2xl w-full max-w-sm p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              type="button"
              onClick={() => !pwSaving && closePwModal()}
              className="absolute top-3 right-3 text-gray-400 hover:text-gray-600"
              aria-label="닫기"
            >
              <X size={18} />
            </button>
            <div className="flex items-center gap-2 mb-3">
              <KeyRound size={18} className="text-blue-600" aria-hidden="true" />
              <h2 id="pw-change-title" className="text-base font-semibold text-gray-900">
                비밀번호 변경
              </h2>
            </div>
            <p className="text-xs text-gray-500 mb-4">
              새 비밀번호는 8자 이상, 영문과 숫자를 모두 포함해야 합니다.
            </p>
            <form
              onSubmit={(e) => { e.preventDefault(); submitPasswordChange(); }}
              className="space-y-3"
            >
              <div>
                <label htmlFor="pw-current" className="block text-xs text-gray-700 mb-1">현재 비밀번호</label>
                <input
                  ref={pwFirstInputRef}
                  id="pw-current"
                  type="password"
                  autoComplete="current-password"
                  value={pwCurrent}
                  onChange={(e) => setPwCurrent(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="현재 비밀번호"
                  disabled={pwSaving}
                  required
                />
              </div>
              <div>
                <label htmlFor="pw-new" className="block text-xs text-gray-700 mb-1">새 비밀번호</label>
                <input
                  id="pw-new"
                  type="password"
                  autoComplete="new-password"
                  value={pwNew}
                  onChange={(e) => setPwNew(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="새 비밀번호"
                  disabled={pwSaving}
                  required
                />
              </div>
              <div>
                <label htmlFor="pw-confirm" className="block text-xs text-gray-700 mb-1">새 비밀번호 확인</label>
                <input
                  id="pw-confirm"
                  type="password"
                  autoComplete="new-password"
                  value={pwConfirm}
                  onChange={(e) => setPwConfirm(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="새 비밀번호 확인"
                  disabled={pwSaving}
                  required
                />
              </div>
              {pwError && (
                <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded px-3 py-2">
                  {pwError}
                </p>
              )}
              <div className="flex gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => !pwSaving && closePwModal()}
                  className="flex-1 bg-gray-100 text-gray-700 py-2 rounded-lg hover:bg-gray-200 text-sm font-medium"
                  disabled={pwSaving}
                >
                  취소
                </button>
                <button
                  ref={pwLastButtonRef}
                  type="submit"
                  className={`flex-1 flex items-center justify-center gap-1.5 py-2 rounded-lg text-sm font-medium text-white ${
                    pwSaving ? "bg-blue-400 cursor-not-allowed" : "bg-blue-600 hover:bg-blue-700"
                  }`}
                  disabled={pwSaving}
                >
                  {pwSaving ? <><Loader2 size={14} className="animate-spin" /> 변경 중...</> : "변경"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
