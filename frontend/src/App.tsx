import { Suspense, lazy } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Layout } from "./components/layout/Layout";
import { EmptyState, Spinner } from "./components/ui";
import { useAuth } from "./lib/auth";
import Alerts from "./pages/Alerts";
import Approvals from "./pages/Approvals";
import Audit from "./pages/Audit";
import Automation from "./pages/Automation";
import Credentials from "./pages/Credentials";
import Dashboard from "./pages/Dashboard";
import DeviceDetail from "./pages/DeviceDetail";
import Devices from "./pages/Devices";
import Integrations from "./pages/Integrations";
import Inventory from "./pages/Inventory";
import JobDetail from "./pages/JobDetail";
import Jobs from "./pages/Jobs";
import Login from "./pages/Login";
import Onboarding from "./pages/Onboarding";
import Schedules from "./pages/Schedules";
import Scripts from "./pages/Scripts";
import SettingsPage from "./pages/Settings";
import SetupRequired from "./pages/AccountSecurity";
import UsersPage from "./pages/Users";

// 1.1 modules are loaded on demand to keep the first page load small
const GpoPage = lazy(() => import("./pages/gpo/GpoPage"));
const GpoDetail = lazy(() => import("./pages/gpo/GpoDetail"));
const AdPage = lazy(() => import("./pages/ad/AdPage"));
const CompliancePage = lazy(() => import("./pages/compliance/CompliancePage"));
const AssessmentDetail = lazy(() => import("./pages/compliance/AssessmentDetail"));
const FindingDetail = lazy(() => import("./pages/compliance/FindingDetail"));
const ReportCenter = lazy(() => import("./pages/ReportCenter"));
function ReportsRedirect() {
  const { search } = useLocation();
  return <Navigate to={new URLSearchParams(search).get("r") ? `/reports/operational${search}` : "/reports/center"} replace />;
}
const L = ({ children }: { children: JSX.Element }) => <Suspense fallback={<Spinner />}>{children}</Suspense>;

function Guard({ perm, children }: { perm?: string; children: JSX.Element }) {
  const { can } = useAuth();
  if (perm && !can(perm)) return <EmptyState title="You don't have access to this page" hint={`Required permission: ${perm}. Ask an administrator to assign a role that includes it.`} />;
  return children;
}

export default function App() {
  const { user, loading, restricted } = useAuth();
  if (loading) return <Spinner label="Starting InfraPilot…" />;
  if (!user) return <Login />;
  if (restricted) return <SetupRequired />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Guard perm="dashboard.read"><Dashboard /></Guard>} />
        <Route path="onboarding" element={<Onboarding />} />
        <Route path="devices" element={<Guard perm="devices.read"><Devices /></Guard>} />
        <Route path="devices/:id" element={<Guard perm="devices.read"><DeviceDetail /></Guard>} />
        <Route path="inventory" element={<Guard perm="devices.read"><Inventory /></Guard>} />
        <Route path="credentials" element={<Guard perm="credentials.read"><Credentials /></Guard>} />
        <Route path="jobs" element={<Jobs />} />
        <Route path="jobs/:id" element={<JobDetail />} />
        <Route path="automation" element={<Automation />} />
        <Route path="scripts" element={<Guard perm="scripts.read"><Scripts /></Guard>} />
        <Route path="schedules" element={<Guard perm="automation.read"><Schedules /></Guard>} />
        <Route path="reports" element={<ReportsRedirect />} />
        <Route path="reports/:tab" element={<Guard perm="reports.read"><L><ReportCenter /></L></Guard>} />
        <Route path="gpo" element={<Navigate to="/gpo/inventory" replace />} />
        <Route path="gpo/object/:guid" element={<Guard perm="gpo.read"><L><GpoDetail /></L></Guard>} />
        <Route path="gpo/:tab" element={<Guard perm="gpo.read"><L><GpoPage /></L></Guard>} />
        <Route path="ad" element={<Navigate to="/ad/overview" replace />} />
        <Route path="ad/:tab" element={<Guard perm="ad.read"><L><AdPage /></L></Guard>} />
        <Route path="compliance" element={<Navigate to="/compliance/dashboard" replace />} />
        <Route path="compliance/assessments/:id" element={<Guard perm="compliance.read"><L><AssessmentDetail /></L></Guard>} />
        <Route path="compliance/findings/:id" element={<Guard perm="compliance.read"><L><FindingDetail /></L></Guard>} />
        <Route path="compliance/:tab" element={<Guard perm="compliance.read"><L><CompliancePage /></L></Guard>} />
        <Route path="approvals" element={<Guard perm="approvals.read"><Approvals /></Guard>} />
        <Route path="alerts" element={<Guard perm="alerts.read"><Alerts /></Guard>} />
        <Route path="audit" element={<Guard perm="audit.read"><Audit /></Guard>} />
        <Route path="users" element={<Guard perm="users.manage"><UsersPage /></Guard>} />
        <Route path="integrations" element={<Guard perm="integrations.manage"><Integrations /></Guard>} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
