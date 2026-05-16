import { createContext, useContext, useState, ReactNode, useEffect } from "react";
import { loginUser, registerUser, fetchAuthMe, type AuthUser, type RegisterPayload } from "../../config/api";

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
  login: (login_id: string, password: string) => Promise<boolean>;
  register: (payload: RegisterPayload) => Promise<boolean>;
  logout: () => void;
  refresh: () => Promise<void>;
  setUser: (u: User | null) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);
const STORAGE_KEY = "zt_user";

function _toUser(u: AuthUser): User {
  return {
    id: u.login_id,
    user_id: u.user_id,
    username: u.name,
    role: u.role === "admin" ? "admin" : "user",
    orgName: u.org_name,
    org_id: u.org_id,
    email: u.email,
    profile: u.profile,
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
        localStorage.removeItem(STORAGE_KEY);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const setUser = (u: User | null) => {
    setUserState(u);
    if (u) localStorage.setItem(STORAGE_KEY, JSON.stringify(u));
    else localStorage.removeItem(STORAGE_KEY);
  };

  const login = async (login_id: string, password: string) => {
    setLoading(true);
    try {
      const res = await loginUser(login_id, password);
      setUser(_toUser(res));
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
      setUser(_toUser(res));
      return true;
    } catch {
      return false;
    } finally {
      setLoading(false);
    }
  };

  const logout = () => setUser(null);

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
    <AuthContext.Provider value={{ user, loading, login, register, logout, refresh, setUser }}>
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
