import { useState, useEffect, useRef } from "react";
import { useNavigate, Link } from "react-router";
import { useAuth } from "../context/AuthContext";
import { useNotifications } from "../context/NotificationContext";
import { Shield, AlertCircle, X, Mail, KeyRound } from "lucide-react";
import { requestPasswordReset, ApiError } from "../../config/api";

const DEMO_ACCOUNTS = [
  { label: "관리자", id: "admin", role: "관리자" },
  { label: "박기웅 (세종대학교)", id: "user1", role: "일반 사용자" },
  { label: "서진우 (T-Markov Framework)", id: "user2", role: "일반 사용자" },
];

type RecoveryMode = null | "id" | "password";

export function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [recovery, setRecovery] = useState<RecoveryMode>(null);
  const [recoveryEmail, setRecoveryEmail] = useState("");
  const [recoverySent, setRecoverySent] = useState(false);
  const recoveryEmailInputRef = useRef<HTMLInputElement>(null);
  const recoveryCloseButtonRef = useRef<HTMLButtonElement>(null);
  const { user, login } = useAuth();
  const { addNotification } = useNotifications();
  const navigate = useNavigate();

  useEffect(() => {
    if (user) {
      navigate("/");
    }
  }, [user, navigate]);

  // ESC 키로 모달 닫기 + 첫 입력 필드 자동 포커스 + Tab focus trap
  useEffect(() => {
    if (!recovery) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setRecovery(null);
        setRecoveryEmail("");
        setRecoverySent(false);
        return;
      }
      // Tab focus trap — 모달 내부 포커스 가능 요소만 순환
      if (e.key !== "Tab") return;
      const dialog = document.querySelector('[aria-labelledby="recovery-modal-title"]');
      if (!dialog) return;
      const focusables = dialog.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])',
      );
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const active = document.activeElement as HTMLElement | null;
      if (e.shiftKey && active === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    // 다음 tick에 첫 인터랙티브 요소에 포커스
    const t = window.setTimeout(() => {
      if (recoverySent) recoveryCloseButtonRef.current?.focus();
      else recoveryEmailInputRef.current?.focus();
    }, 0);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.clearTimeout(t);
    };
  }, [recovery, recoverySent]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    const ok = await login(username, password);
    if (ok) {
      // 시드 계정(password === login_id) 감지 → Dashboard 배너 + 알림 트리거.
      try {
        if (username && username === password) {
          sessionStorage.setItem("zt_seed_password_warning", "true");
          addNotification("기본 비밀번호를 사용 중입니다. Settings에서 변경해주세요.", "warning");
        } else {
          sessionStorage.removeItem("zt_seed_password_warning");
        }
      } catch { /* ignore */ }
      navigate("/");
    } else {
      setError("아이디 또는 비밀번호가 올바르지 않습니다.");
    }
  };

  const handleDemoLogin = (id: string) => {
    setUsername(id);
    setPassword(id);
  };

  const openRecovery = (mode: RecoveryMode) => {
    setRecovery(mode);
    setRecoveryEmail("");
    setRecoverySent(false);
  };

  const closeRecovery = () => {
    setRecovery(null);
    setRecoveryEmail("");
    setRecoverySent(false);
  };

  const submitRecovery = async (e: React.FormEvent) => {
    e.preventDefault();
    if (recovery === "id") {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(recoveryEmail.trim())) return;
      setRecoverySent(true);
      return;
    }
    // password — backend requestPasswordReset 호출. 보안 정책상 결과는 항상 성공 표시.
    if (!recoveryEmail.trim()) return;
    try {
      await requestPasswordReset(recoveryEmail.trim());
    } catch (err) {
      if (err instanceof ApiError && err.status >= 500) {
        // 5xx만 사용자에게 알림 — 그 외 계정 존재 여부 노출 차단
        console.warn("[recovery:password] failed:", err);
      }
    }
    setRecoverySent(true);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-blue-100">
      <div className="bg-white rounded-lg shadow-xl p-8 w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-100 rounded-full mb-4">
            <Shield className="text-blue-600" size={32} />
          </div>
          <h1 className="text-3xl font-semibold text-gray-900 mb-2">Readyz-T</h1>
          <p className="text-gray-600">Zero Trust 성숙도 진단 시스템</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm mb-2 text-gray-700">아이디</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="아이디를 입력하세요"
              required
            />
          </div>

          <div>
            <label className="block text-sm mb-2 text-gray-700">비밀번호</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="비밀번호를 입력하세요"
              required
            />
          </div>

          {error && (
            <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
              <AlertCircle size={16} />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            className="w-full bg-blue-600 text-white py-3 rounded-lg hover:bg-blue-700 transition-colors font-medium"
          >
            로그인
          </button>

          <div className="flex items-center justify-center gap-4 text-xs text-gray-500">
            <button
              type="button"
              onClick={() => openRecovery("id")}
              className="hover:text-blue-600 hover:underline"
            >
              아이디 찾기
            </button>
            <span className="text-gray-300">|</span>
            <button
              type="button"
              onClick={() => openRecovery("password")}
              className="hover:text-blue-600 hover:underline"
            >
              비밀번호 찾기
            </button>
          </div>
        </form>

        <div className="mt-8 pt-6 border-t border-gray-200">
          <p className="text-xs text-gray-400 text-center mb-3">데모 로그인 — 계정을 클릭하면 자동 입력됩니다</p>
          <div className="grid grid-cols-2 gap-2">
            {DEMO_ACCOUNTS.map((account) => (
              <button
                key={account.id}
                type="button"
                onClick={() => handleDemoLogin(account.id)}
                className="text-left px-3 py-2 rounded-lg border border-gray-200 hover:border-blue-300 hover:bg-blue-50 transition-colors"
              >
                <p className="text-xs font-medium text-gray-700 truncate">{account.label}</p>
                <p className="text-xs text-gray-400">{account.role}</p>
              </button>
            ))}
          </div>
          <p className="text-center mt-4 text-sm text-gray-500">
            계정이 없으신가요?{" "}
            <Link to="/signup" className="text-blue-600 hover:underline">
              회원가입
            </Link>
          </p>
        </div>
      </div>

      {recovery && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4"
          onClick={closeRecovery}
          aria-hidden="true"
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="recovery-modal-title"
            className="relative bg-white rounded-xl shadow-2xl w-full max-w-sm p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              type="button"
              onClick={closeRecovery}
              className="absolute top-3 right-3 text-gray-400 hover:text-gray-600"
              aria-label="닫기"
            >
              <X size={18} />
            </button>
            <div className="flex items-center gap-2 mb-3">
              {recovery === "password" ? (
                <KeyRound size={18} className="text-blue-600" aria-hidden="true" />
              ) : (
                <Mail size={18} className="text-blue-600" aria-hidden="true" />
              )}
              <h2 id="recovery-modal-title" className="text-base font-semibold text-gray-900">
                {recovery === "password" ? "비밀번호 찾기" : "아이디 찾기"}
              </h2>
            </div>
            {!recoverySent ? (
              <>
                <p className="text-sm text-gray-600 mb-4">
                  {recovery === "password"
                    ? "가입 시 사용한 아이디를 입력해주세요. 등록된 이메일로 재설정 링크를 발송합니다."
                    : "가입 시 등록한 이메일을 입력해주세요. 아이디 안내 메일을 발송합니다."}
                </p>
                <form onSubmit={submitRecovery} className="space-y-3">
                  <input
                    ref={recoveryEmailInputRef}
                    type={recovery === "password" ? "text" : "email"}
                    value={recoveryEmail}
                    onChange={(e) => setRecoveryEmail(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder={recovery === "password" ? "아이디" : "user@example.com"}
                    aria-label={recovery === "password" ? "가입 아이디" : "가입 이메일"}
                    autoComplete={recovery === "password" ? "username" : "email"}
                    required
                  />
                  <button
                    type="submit"
                    className="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700 transition-colors text-sm font-medium"
                  >
                    {recovery === "password" ? "재설정 메일 발송" : "인증 메일 발송"}
                  </button>
                </form>
                <p className="text-[11px] text-gray-400 mt-3 leading-relaxed">
                  * 데모 빌드입니다. SMTP 미연결 환경에서는 실제 메일이 발송되지 않으며,
                  발송 흐름만 시뮬레이션됩니다.
                </p>
              </>
            ) : (
              <>
                <p className="text-sm text-gray-700 mb-2">
                  {recovery === "password" ? (
                    <>입력하신 아이디가 등록된 계정이면 이메일로 <span className="font-semibold">재설정 링크</span>가 발송됩니다.</>
                  ) : (
                    <><span className="font-semibold">{recoveryEmail}</span> 으로 안내 메일을 발송했습니다.</>
                  )}
                </p>
                <p className="text-xs text-gray-500 mb-4">
                  메일이 도착하지 않으면 스팸함을 확인하거나 시스템 관리자에게 문의해주세요.
                </p>
                <button
                  ref={recoveryCloseButtonRef}
                  type="button"
                  onClick={closeRecovery}
                  className="w-full bg-gray-100 text-gray-700 py-2 rounded-lg hover:bg-gray-200 text-sm font-medium"
                >
                  닫기
                </button>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
