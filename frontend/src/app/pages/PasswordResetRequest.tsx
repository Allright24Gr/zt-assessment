import { useState } from "react";
import { Link } from "react-router";
import { Shield, AlertCircle, CheckCircle2, Loader2, KeyRound } from "lucide-react";
import { requestPasswordReset, ApiError } from "../../config/api";

export function PasswordResetRequest() {
  const [loginId, setLoginId] = useState("");
  const [error, setError] = useState("");
  const [sent, setSent] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (!loginId.trim()) {
      setError("아이디를 입력해주세요.");
      return;
    }
    setSubmitting(true);
    try {
      await requestPasswordReset(loginId.trim());
      // 보안상 응답은 항상 성공 — 계정 존재 여부 노출 금지
      setSent(true);
    } catch (err) {
      console.warn("[password-reset-request] failed:", err);
      // 백엔드는 항상 200을 반환해야 하지만, 5xx 등 인프라 오류는 표시
      if (err instanceof ApiError && err.status >= 500) {
        setError("일시적인 오류가 발생했습니다. 잠시 후 다시 시도해주세요.");
      } else {
        // 그 외에는 보안 정책상 성공으로 표시
        setSent(true);
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
          <h1 className="text-2xl font-semibold text-gray-900 mb-2">비밀번호 찾기</h1>
          <p className="text-gray-600 text-sm">
            가입 시 등록한 아이디를 입력해주세요. 이메일로 재설정 링크를 발송합니다.
          </p>
        </div>

        {!sent ? (
          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label htmlFor="login-id" className="block text-sm mb-2 text-gray-700">
                아이디
              </label>
              <input
                id="login-id"
                type="text"
                value={loginId}
                onChange={(e) => setLoginId(e.target.value)}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="가입 시 사용한 아이디"
                autoComplete="username"
                disabled={submitting}
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
              disabled={submitting}
              className="w-full bg-blue-600 text-white py-3 rounded-lg hover:bg-blue-700 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {submitting ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  발송 중...
                </>
              ) : (
                <>
                  <KeyRound size={16} />
                  재설정 메일 발송
                </>
              )}
            </button>
          </form>
        ) : (
          <div className="space-y-4">
            <div className="flex items-start gap-2 p-4 bg-green-50 border border-green-200 rounded-lg">
              <CheckCircle2 size={18} className="text-green-600 mt-0.5 shrink-0" />
              <div className="text-sm text-green-900">
                <p className="font-semibold mb-1">재설정 메일을 발송했습니다.</p>
                <p className="text-xs text-green-800 leading-relaxed">
                  계정이 존재하는 경우, 등록된 이메일로 비밀번호 재설정 링크가 발송됩니다.
                  메일을 확인하지 못한 경우 스팸함을 확인하거나 시스템 관리자에게 문의해주세요.
                </p>
              </div>
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
