import { createContext, useContext, useState, ReactNode } from "react";

interface User {
  id: string;
  username: string;
  role: "admin" | "user";
  orgName?: string;
}

interface AuthContextType {
  user: User | null;
  login: (username: string, password: string) => boolean;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);
const STORAGE_KEY = "zt_user";

const users = [
  { id: "admin", password: "admin", role: "admin" as const, username: "관리자" },
  { id: "user1", password: "user1", role: "user" as const, username: "박기웅", orgName: "세종대학교" },
];

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      return stored ? (JSON.parse(stored) as User) : null;
    } catch {
      return null;
    }
  });

  const login = (username: string, password: string) => {
    const foundUser = users.find((u) => u.id === username && u.password === password);
    if (foundUser) {
      const userObj: User = {
        id: foundUser.id,
        username: foundUser.username,
        role: foundUser.role,
        orgName: foundUser.orgName,
      };
      setUser(userObj);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(userObj));
      return true;
    }
    return false;
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem(STORAGE_KEY);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
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
