import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { Shield, AlertCircle, CheckCircle2, Loader2, KeyRound } from "lucide-react";
import { toast } from "sonner";
import { resetPassword, ApiError } from "../../config/api";

function validatePassword(next: string, confirm: string): string {
  if (next.length < 8) return "새 비밀번호는 8자 이상이어야 합니다.";
  if (!/[A-Za-z]/.test(next) || !/[0-9]/.test(next)) {
    return "새 비밀번호는 영문과 숫자를 모두 포함해야 합니다.";
  }
  if (next !== confirm) return "새 비밀번호 확인 값이 일치하지 않습니다.";
  return "";
}

export function PasswordResetConfirm() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const token = searchParams.get("token") ?? "";
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (!token) {
      setError("유효한 재설정 토큰이 없습니다. 다시 시도해주세요.");
    }
  }, [token]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (!token) {
      setError("유효한 재설정 토큰이 없습니다.");
      return;
    }
    const v = validatePassword(newPassword, confirmPassword);
    if (v) {
      setError(v);
      return;
    }
    setSubmitting(true);
    try {
      await resetPassword(token, newPassword);
      setDone(true);
      toast.success("비밀번호가 재설정되었습니다. 새 비밀번호로 로그인해주세요.");
      window.setTimeout(() => navigate("/login"), 1500);
    } catch (err) {
      console.warn("[password-reset-confirm] failed:", err);
      if (err instanceof ApiError) {
        if (err.status === 400 || err.status === 404) {
          setError("재설정 토큰이 만료되었거나 유효하지 않습니다. 다시 요청해주세요.");
        } else if (err.status === 422) {
          setError("비밀번호 정책: 8자 이상 + 영문+숫자");
        } else {
          setError("재설정에 실패했습니다. 잠시 후 다시 시도해주세요.");
        }
      } else {
        setError("재설정에 실패했습니다.");
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-blue-100">
      <div className="bg-white rounded-lg shadow-xl p-8 w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-100 rounded-full mb-4">
            <Shield className="text-blue-600" size={32} />
          </div>
          <h1 className="text-2xl font-semibold text-gray-900 mb-2">새 비밀번호 설정</h1>
          <p className="text-gray-600 text-sm">
            새 비밀번호는 8자 이상, 영문과 숫자를 모두 포함해야 합니다.
          </p>
        </div>

        {!done ? (
          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label htmlFor="new-password" className="block text-sm mb-2 text-gray-700">
                새 비밀번호
              </label>
              <input
                id="new-password"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="8자 이상 영문+숫자"
                autoComplete="new-password"
                disabled={submitting || !token}
                required
              />
            </div>
            <div>
              <label htmlFor="confirm-password" className="block text-sm mb-2 text-gray-700">
                새 비밀번호 확인
              </label>
              <input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="새 비밀번호 다시 입력"
                autoComplete="new-password"
                disabled={submitting || !token}
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
              disabled={submitting || !token}
              className="w-full bg-blue-600 text-white py-3 rounded-lg hover:bg-blue-700 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {submitting ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  변경 중...
                </>
              ) : (
                <>
                  <KeyRound size={16} />
                  비밀번호 재설정
                </>
              )}
            </button>
          </form>
        ) : (
          <div className="flex items-start gap-2 p-4 bg-green-50 border border-green-200 rounded-lg">
            <CheckCircle2 size={18} className="text-green-600 mt-0.5 shrink-0" />
            <div className="text-sm text-green-900">
              <p className="font-semibold mb-1">비밀번호가 재설정되었습니다.</p>
              <p className="text-xs text-green-800 leading-relaxed">
                잠시 후 로그인 화면으로 이동합니다.
              </p>
            </div>
          </div>
        )}

        <div className="mt-6 pt-5 border-t border-gray-200 text-center">
          <Link to="/login" className="text-sm text-blue-600 hover:underline">
            로그인 화면으로 돌아가기
          </Link>
        </div>
      </div>
    </div>
  );
}
