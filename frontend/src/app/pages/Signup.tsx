import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router";
import { useAuth } from "../context/AuthContext";
import { Shield, AlertCircle, CheckCircle2 } from "lucide-react";
import type { ProfileFields } from "../../config/api";

const ORG_TYPES = ["IT/SW", "금융", "의료", "공공", "교육", "제조", "유통/서비스", "기타"];
const INFRA_TYPES = ["온프레미스", "퍼블릭 클라우드", "프라이빗 클라우드", "하이브리드"];

export function Signup() {
  const { user, register, loading } = useAuth();
  const navigate = useNavigate();

  const [loginId, setLoginId] = useState("");
  const [password, setPassword] = useState("");
  const [passwordConfirm, setPasswordConfirm] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");

  // 진단 시 자동 prefill될 프로필 (모두 선택)
  const [profile, setProfile] = useState<ProfileFields>({});

  const [error, setError] = useState("");

  useEffect(() => {
    if (user) navigate("/");
  }, [user, navigate]);

  const setProf = <K extends keyof ProfileFields>(key: K, val: ProfileFields[K]) =>
    setProfile((p) => ({ ...p, [key]: val }));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (loginId.length < 2) return setError("아이디는 2자 이상이어야 합니다.");
    if (password.length < 4) return setError("비밀번호는 4자 이상이어야 합니다.");
    if (password !== passwordConfirm) return setError("비밀번호 확인이 일치하지 않습니다.");
    if (!name.trim()) return setError("이름을 입력해주세요.");

    const cleanedProfile: ProfileFields = {};
    (Object.entries(profile) as [keyof ProfileFields, unknown][]).forEach(([k, v]) => {
      if (v === undefined || v === null) return;
      if (typeof v === "string" && v.trim() === "") return;
      (cleanedProfile as Record<string, unknown>)[k] = v;
    });

    const ok = await register({
      login_id: loginId.trim(),
      password,
      name: name.trim(),
      email: email.trim() || undefined,
      profile: Object.keys(cleanedProfile).length > 0 ? cleanedProfile : undefined,
    });

    if (ok) {
      navigate("/");
    } else {
      setError("이미 사용 중인 아이디이거나 가입에 실패했습니다.");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-blue-100 py-10">
      <div className="bg-white rounded-lg shadow-xl p-8 w-full max-w-2xl">
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-14 h-14 bg-blue-100 rounded-full mb-3">
            <Shield className="text-blue-600" size={26} />
          </div>
          <h1 className="text-2xl font-semibold text-gray-900 mb-1">회원가입</h1>
          <p className="text-sm text-gray-600">Zero Trust 성숙도 진단 시스템</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* ── 필수: 계정 정보 ─────────────────────────────────────── */}
          <section>
            <h2 className="text-sm font-semibold text-gray-700 mb-3">계정 정보</h2>
            <div className="grid grid-cols-2 gap-3">
              <Field label="아이디 *" value={loginId} onChange={setLoginId} placeholder="2자 이상" />
              <Field label="이름 *" value={name} onChange={setName} placeholder="홍길동" />
              <Field label="비밀번호 *" type="password" value={password} onChange={setPassword} placeholder="4자 이상" />
              <Field label="비밀번호 확인 *" type="password" value={passwordConfirm} onChange={setPasswordConfirm} />
              <div className="col-span-2">
                <Field label="이메일 (선택)" type="email" value={email} onChange={setEmail} placeholder="user@example.com" />
              </div>
            </div>
          </section>

          {/* ── 선택: 진단 프로필 ───────────────────────────────────── */}
          <section className="border-t border-gray-100 pt-5">
            <div className="flex items-center gap-2 mb-3">
              <CheckCircle2 size={16} className="text-green-600" />
              <h2 className="text-sm font-semibold text-gray-700">
                진단 프로필 (선택) — 입력하면 신규 진단 시작 시 자동 입력됩니다
              </h2>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="기관/조직명" value={profile.org_name ?? ""} onChange={(v) => setProf("org_name", v)} />
              <Field label="부서" value={profile.department ?? ""} onChange={(v) => setProf("department", v)} />
              <Field label="연락처" value={profile.contact ?? ""} onChange={(v) => setProf("contact", v)} placeholder="02-0000-0000" />
              <SelectField label="산업군" value={profile.org_type ?? ""} options={ORG_TYPES} onChange={(v) => setProf("org_type", v)} />
              <SelectField label="인프라 유형" value={profile.infra_type ?? ""} options={INFRA_TYPES} onChange={(v) => setProf("infra_type", v)} />
              <NumberField label="임직원 수" value={profile.employees} onChange={(v) => setProf("employees", v)} />
              <NumberField label="서버 대수" value={profile.servers} onChange={(v) => setProf("servers", v)} />
              <NumberField label="애플리케이션 수" value={profile.applications} onChange={(v) => setProf("applications", v)} />
              <div className="col-span-2">
                <label className="block text-xs text-gray-600 mb-1">메모</label>
                <textarea
                  value={profile.note ?? ""}
                  onChange={(e) => setProf("note", e.target.value)}
                  rows={2}
                  className="w-full px-3 py-2 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>
          </section>

          {error && (
            <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-sm">
              <AlertCircle size={16} />
              <span>{error}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-600 text-white py-3 rounded-lg hover:bg-blue-700 transition-colors font-medium disabled:opacity-50"
          >
            {loading ? "가입 중..." : "가입하기"}
          </button>

          <p className="text-center text-sm text-gray-500">
            이미 계정이 있나요?{" "}
            <Link to="/login" className="text-blue-600 hover:underline">
              로그인
            </Link>
          </p>
        </form>
      </div>
    </div>
  );
}

// ─── Inline form helpers ──────────────────────────────────────────────────

function Field({
  label, value, onChange, type = "text", placeholder,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
  placeholder?: string;
}) {
  return (
    <div>
      <label className="block text-xs text-gray-600 mb-1">{label}</label>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full px-3 py-2 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
      />
    </div>
  );
}

function NumberField({
  label, value, onChange,
}: {
  label: string;
  value: number | undefined;
  onChange: (v: number | undefined) => void;
}) {
  return (
    <div>
      <label className="block text-xs text-gray-600 mb-1">{label}</label>
      <input
        type="number"
        min={0}
        value={value ?? ""}
        onChange={(e) => {
          const v = e.target.value;
          onChange(v === "" ? undefined : Number(v));
        }}
        className="w-full px-3 py-2 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
      />
    </div>
  );
}

function SelectField({
  label, value, options, onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (v: string) => void;
}) {
  return (
    <div>
      <label className="block text-xs text-gray-600 mb-1">{label}</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full px-3 py-2 border border-gray-300 rounded text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 bg-white"
      >
        <option value="">선택...</option>
        {options.map((o) => (
          <option key={o} value={o}>{o}</option>
        ))}
      </select>
    </div>
  );
}
