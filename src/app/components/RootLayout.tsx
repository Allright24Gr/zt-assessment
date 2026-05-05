import { useEffect } from "react";
import { Link, Navigate, Outlet, useLocation, useNavigate } from "react-router";
import { Bell, FileText, History, LayoutDashboard, LogOut, Settings, User } from "lucide-react";
import { useAuth } from "../context/AuthContext";

export function RootLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  // React Hook 규칙을 지키기 위해 로그인 분기 전에 항상 호출합니다.
  useEffect(() => {
    if (user?.role === "admin" && location.pathname === "/") {
      navigate("/history", { replace: true });
    }
  }, [user?.role, location.pathname, navigate]);

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  const navItems = user.role === "admin"
    ? [
        { path: "/history", label: "History", icon: History },
        { path: "/settings", label: "Settings", icon: Settings },
      ]
    : [
        { path: "/", label: "Dashboard", icon: LayoutDashboard },
        { path: "/new-assessment", label: "New Assessment", icon: FileText },
        { path: "/history", label: "History", icon: History },
        { path: "/settings", label: "Settings", icon: Settings },
      ];

  const isActive = (path: string) => {
    if (path === "/") return location.pathname === "/";
    return location.pathname.startsWith(path);
  };

  return (
    <div className="flex h-screen bg-gray-50">
      <aside className="w-64 bg-white border-r border-gray-200 flex flex-col">
        <div className="p-6 border-b border-gray-200">
          <h1 className="text-xl font-semibold text-blue-600">Readyz-T</h1>
          <p className="text-sm text-gray-500 mt-1">Zero Trust 성숙도 진단</p>
        </div>
        <nav className="flex-1 p-4">
          <ul className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <li key={item.path}>
                  <Link
                    to={item.path}
                    className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                      isActive(item.path)
                        ? "bg-blue-50 text-blue-600"
                        : "text-gray-700 hover:bg-gray-100"
                    }`}
                  >
                    <Icon size={20} />
                    <span>{item.label}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>
      </aside>

      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="bg-white border-b border-gray-200 px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <h2 className="text-lg text-gray-600">현재 세션: -</h2>
            </div>
            <div className="flex items-center gap-4">
              <button className="p-2 hover:bg-gray-100 rounded-lg relative">
                <Bell size={20} className="text-gray-600" />
                <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full" />
              </button>
              <div className="flex items-center gap-2 px-3 py-2 bg-gray-100 rounded-lg">
                <User size={20} className="text-gray-600" />
                <span className="text-sm">{user.username}</span>
              </div>
              <button
                onClick={logout}
                className="p-2 hover:bg-red-50 rounded-lg text-red-600"
                title="로그아웃"
              >
                <LogOut size={20} />
              </button>
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
