import { createContext, useContext, useState, ReactNode, useEffect } from "react";
import {
  loginUser,
  registerUser,
  fetchAuthMe,
  setStoredTokens,
  getStoredAccessToken,
  getStoredRefreshToken,
  type AuthUser,
  type RegisterPayload,
} from "../../config/api";
import type { AuthEnvelope } from "../../types/api";

export interface User {
  id: string;            // login_id
  user_id: number;
  username: string;
  role: "admin" | "user";
  orgName?: string;
  org_id?: number;
  email?: string | null;
  profile?: AuthUser["profile"];
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  accessToken: string | null;
  refreshToken: string | null;
  login: (login_id: string, password: string) => Promise<boolean>;
  register: (payload: RegisterPayload) => Promise<boolean>;
  logout: () => void;
  refresh: () => Promise<void>;
  setUser: (u: User | null) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);
const STORAGE_KEY = "zt_user";

function _toUser(u: AuthUser | AuthEnvelope["user"]): User {
  return {
    id: u.login_id,
    user_id: u.user_id,
    username: u.name,
    role: u.role === "admin" ? "admin" : "user",
    orgName: u.org_name,
    org_id: u.org_id,
    email: u.email,
    // profile은 AuthUser와 AuthEnvelope.user 형식이 다를 수 있으므로 보수적으로 캐스팅
    profile: (u as AuthUser).profile as AuthUser["profile"] | undefined,
  };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUserState] = useState<User | null>(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      return stored ? (JSON.parse(stored) as User) : null;
    } catch {
      // 손상된 데이터는 제거해 다음 로드에서 catch가 반복되지 않도록 한다.
      try {
        localStorage.removeItem(STORAGE_KEY);
      } catch {
        /* ignore */
      }
      return null;
    }
  });
  const [loading, setLoading] = useState(false);

  // 토큰은 localStorage("zt_tokens")에 영속 (시연 우선 — 별도 키 분리는 추후)
  const [tokens, setTokensState] = useState<{ access: string | null; refresh: string | null }>(
    () => ({
      access: getStoredAccessToken(),
      refresh: getStoredRefreshToken(),
    }),
  );

  // 페이지 새로고침 시 백엔드에서 최신 프로필 재조회
  useEffect(() => {
    if (!user?.id) return;
    fetchAuthMe(user.id)
      .then((latest) => {
        const u = _toUser(latest);
        setUserState(u);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(u));
      })
      .catch(() => {
        // 백엔드에 없으면 로그아웃 처리
        setUserState(null);
        setStoredTokens(null);
        setTokensState({ access: null, refresh: null });
        localStorage.removeItem(STORAGE_KEY);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const setUser = (u: User | null) => {
    setUserState(u);
    if (u) localStorage.setItem(STORAGE_KEY, JSON.stringify(u));
    else localStorage.removeItem(STORAGE_KEY);
  };

  const _persistEnvelope = (env: AuthEnvelope) => {
    const u = _toUser(env.user);
    setUser(u);
    setStoredTokens(env.tokens);
    setTokensState({ access: env.tokens.access_token, refresh: env.tokens.refresh_token });
  };

  const login = async (login_id: string, password: string) => {
    setLoading(true);
    try {
      const res = await loginUser(login_id, password);
      _persistEnvelope(res);
      return true;
    } catch {
      return false;
    } finally {
      setLoading(false);
    }
  };

  const register = async (payload: RegisterPayload) => {
    setLoading(true);
    try {
      const res = await registerUser(payload);
      _persistEnvelope(res);
      return true;
    } catch {
      return false;
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    setUser(null);
    setStoredTokens(null);
    setTokensState({ access: null, refresh: null });
  };

  const refresh = async () => {
    if (!user?.id) return;
    try {
      const latest = await fetchAuthMe(user.id);
      setUser(_toUser(latest));
    } catch {
      // ignore
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        accessToken: tokens.access,
        refreshToken: tokens.refresh,
        login,
        register,
        logout,
        refresh,
        setUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}
