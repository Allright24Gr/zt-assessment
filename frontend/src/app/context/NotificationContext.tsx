import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

export interface Notification {
  id: string;
  message: string;
  type: "info" | "success" | "warning" | "error";
  createdAt: number;
  read: boolean;
}

interface NotificationContextValue {
  notifications: Notification[];
  unreadCount: number;
  addNotification: (msg: string, type?: Notification["type"]) => void;
  markAsRead: (id: string) => void;
  markAllAsRead: () => void;
  clearAll: () => void;
}

const NotificationContext = createContext<NotificationContextValue | null>(null);

const STORAGE_KEY = "zt_notifications";
const MAX_KEEP = 50; // 최근 50개만 유지

function loadStored(): Notification[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((n): n is Notification =>
      n && typeof n.id === "string" && typeof n.message === "string"
    );
  } catch {
    return [];
  }
}

function persist(items: Notification[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(items.slice(0, MAX_KEEP)));
  } catch { /* ignore */ }
}

export function NotificationProvider({ children }: { children: React.ReactNode }) {
  const [notifications, setNotifications] = useState<Notification[]>(() => loadStored());

  useEffect(() => {
    persist(notifications);
  }, [notifications]);

  const addNotification = useCallback((message: string, type: Notification["type"] = "info") => {
    const n: Notification = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      message,
      type,
      createdAt: Date.now(),
      read: false,
    };
    setNotifications((prev) => [n, ...prev].slice(0, MAX_KEEP));
  }, []);

  const markAsRead = useCallback((id: string) => {
    setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, read: true } : n)));
  }, []);

  const markAllAsRead = useCallback(() => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  }, []);

  const clearAll = useCallback(() => {
    setNotifications([]);
  }, []);

  const unreadCount = useMemo(() => notifications.filter((n) => !n.read).length, [notifications]);

  const value = useMemo<NotificationContextValue>(() => ({
    notifications, unreadCount, addNotification, markAsRead, markAllAsRead, clearAll,
  }), [notifications, unreadCount, addNotification, markAsRead, markAllAsRead, clearAll]);

  return (
    <NotificationContext.Provider value={value}>
      {children}
    </NotificationContext.Provider>
  );
}

export function useNotifications(): NotificationContextValue {
  const ctx = useContext(NotificationContext);
  if (!ctx) {
    // 안전 fallback — provider 밖에서 호출되어도 앱이 깨지지 않음
    return {
      notifications: [],
      unreadCount: 0,
      addNotification: () => { /* noop */ },
      markAsRead: () => { /* noop */ },
      markAllAsRead: () => { /* noop */ },
      clearAll: () => { /* noop */ },
    };
  }
  return ctx;
}
