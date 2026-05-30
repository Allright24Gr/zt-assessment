import { useEffect, useRef, useState } from "react";
import { Link, Navigate, Outlet, useLocation, useNavigate } from "react-router";
import { Bell, CheckCheck, FileText, History, LayoutDashboard, LogOut, Settings, ShieldCheck, Trash2, User, X } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { useNotifications } from "../context/NotificationContext";

export function RootLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { notifications, unreadCount, markAsRead, markAllAsRead, clearAll } = useNotifications();
  const [notifOpen, setNotifOpen] = useState(false);
  const notifPanelRef = useRef<HTMLDivElement>(null);

  // React Hook 규칙을 지키기 위해 로그인 분기 전에 항상 호출합니다.
  useEffect(() => {
    if (user?.role === "admin" && location.pathname === "/") {
      navigate("/history", { replace: true });
    }
  }, [user?.role, location.pathname, navigate]);

  // 패널 외부 클릭 시 닫기
  useEffect(() => {
    if (!notifOpen) return;
    const onClick = (e: MouseEvent) => {
      const el = notifPanelRef.current;
      if (el && !el.contains(e.target as Node)) setNotifOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setNotifOpen(false);
    };
    window.addEventListener("mousedown", onClick);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onClick);
      window.removeEventListener("keydown", onKey);
    };
  }, [notifOpen]);

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  const navItems = user.role === "admin"
    ? [
        { path: "/history", label: "History", icon: History },
        { path: "/admin", label: "운영 콘솔", icon: ShieldCheck },
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
              <div className="relative" ref={notifPanelRef}>
                <button
                  type="button"
                  onClick={() => setNotifOpen((v) => !v)}
                  className="p-2 hover:bg-gray-100 rounded-lg relative"
                  aria-label={`알림 ${unreadCount > 0 ? `(${unreadCount}개 새 알림)` : "(없음)"}`}
                  title={unreadCount > 0 ? `읽지 않은 알림 ${unreadCount}개` : "알림 없음"}
                >
                  <Bell size={20} className="text-gray-600" />
                  {unreadCount > 0 && (
                    <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full" />
                  )}
                </button>
                {notifOpen && (
                  <div className="absolute right-0 top-full mt-2 w-80 bg-white border border-gray-200 rounded-lg shadow-xl z-50 max-h-[70vh] flex flex-col">
                    <div className="px-4 py-3 border-b border-gray-100 flex items-center justify-between bg-gray-50 rounded-t-lg">
                      <span className="text-sm font-semibold text-gray-800">
                        알림 {notifications.length > 0 && `(${notifications.length})`}
                      </span>
                      <div className="flex items-center gap-1">
                        {unreadCount > 0 && (
                          <button
                            type="button"
                            onClick={markAllAsRead}
                            className="p-1 text-gray-500 hover:text-blue-600 hover:bg-blue-50 rounded"
                            title="모두 읽음 처리"
                          >
                            <CheckCheck size={14} />
                          </button>
                        )}
                        {notifications.length > 0 && (
                          <button
                            type="button"
                            onClick={clearAll}
                            className="p-1 text-gray-500 hover:text-red-600 hover:bg-red-50 rounded"
                            title="모두 지우기"
                          >
                            <Trash2 size={14} />
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => setNotifOpen(false)}
                          className="p-1 text-gray-400 hover:text-gray-600"
                          title="닫기"
                        >
                          <X size={14} />
                        </button>
                      </div>
                    </div>
                    <div className="overflow-y-auto flex-1">
                      {notifications.length === 0 ? (
                        <div className="px-4 py-10 text-center text-xs text-gray-400">
                          새로운 알림이 없습니다.
                        </div>
                      ) : (
                        notifications.map((n) => {
                          const typeColor = {
                            info:    "border-blue-300 bg-blue-50/40",
                            success: "border-green-300 bg-green-50/40",
                            warning: "border-amber-300 bg-amber-50/40",
                            error:   "border-red-300 bg-red-50/40",
                          }[n.type];
                          const ts = new Date(n.createdAt);
                          const tsLabel = ts.toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
                          return (
                            <button
                              key={n.id}
                              type="button"
                              onClick={() => markAsRead(n.id)}
                              className={`w-full text-left px-3 py-2.5 border-l-4 ${typeColor} ${n.read ? "opacity-60" : ""} hover:bg-gray-50 border-b border-gray-100`}
                            >
                              <p className={`text-xs leading-snug ${n.read ? "text-gray-600" : "text-gray-900 font-medium"}`}>
                                {n.message}
                              </p>
                              <p className="text-[10px] text-gray-400 mt-0.5">{tsLabel}</p>
                            </button>
                          );
                        })
                      )}
                    </div>
                  </div>
                )}
              </div>
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
