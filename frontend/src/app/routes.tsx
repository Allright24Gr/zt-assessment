import { createBrowserRouter } from "react-router";
import { RootLayout } from "./components/RootLayout";
import { Login } from "./pages/Login";
import { Signup } from "./pages/Signup";
import { PasswordResetRequest } from "./pages/PasswordResetRequest";
import { PasswordResetConfirm } from "./pages/PasswordResetConfirm";
import { SharedResult } from "./pages/SharedResult";
import { Dashboard } from "./pages/Dashboard";
import { NewAssessment } from "./pages/NewAssessment";
import { InProgress } from "./pages/InProgress";
import { Reporting } from "./pages/Reporting";
import { History } from "./pages/History";
import { Compare } from "./pages/Compare";
import { Settings } from "./pages/Settings";

export const router = createBrowserRouter([
  // 공개 라우트 (인증 불필요)
  {
    path: "/login",
    Component: Login,
  },
  {
    path: "/signup",
    Component: Signup,
  },
  {
    path: "/auth/request-password-reset",
    Component: PasswordResetRequest,
  },
  {
    path: "/auth/reset-password",
    Component: PasswordResetConfirm,
  },
  {
    path: "/shared/:token",
    Component: SharedResult,
  },
  // 인증 필요한 일반 라우트
  {
    path: "/",
    Component: RootLayout,
    children: [
      { index: true, Component: Dashboard },
      { path: "new-assessment", Component: NewAssessment },
      { path: "in-progress/:sessionId?", Component: InProgress },
      { path: "reporting/:sessionId?", Component: Reporting },
      { path: "history", Component: History },
      { path: "compare", Component: Compare },
      { path: "settings", Component: Settings },
    ],
  },
]);
