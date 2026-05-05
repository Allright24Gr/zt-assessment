import { createBrowserRouter, Navigate } from "react-router";
import { RootLayout } from "./components/RootLayout";
import { Login } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard";
import { NewAssessment } from "./pages/NewAssessment";
import { InProgress } from "./pages/InProgress";
import { Reporting } from "./pages/Reporting";
import { History } from "./pages/History";
import { Settings } from "./pages/Settings";

export const router = createBrowserRouter([
  {
    path: "/login",
    Component: Login,
  },
  {
    path: "/",
    Component: RootLayout,
    children: [
      { index: true, Component: Dashboard },
      { path: "new-assessment", Component: NewAssessment },
      { path: "in-progress/:sessionId?", Component: InProgress },
      { path: "reporting/:sessionId?", Component: Reporting },
      { path: "history", Component: History },
      { path: "settings", Component: Settings },
    ],
  },
]);
