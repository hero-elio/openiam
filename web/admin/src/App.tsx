import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { ReactNode } from "react";
import { useAuthStore } from "@/stores/auth";
import { Login } from "@/pages/Login";
import { AdminLayout } from "@/layouts/AdminLayout";
import { Dashboard } from "@/pages/Dashboard";
import { TenantsPage } from "@/pages/Tenants";
import { ApplicationsPage } from "@/pages/Applications";
import { UsersPage } from "@/pages/Users";
import { RolesPage } from "@/pages/Roles";
import { PermissionsPage } from "@/pages/Permissions";
import { ResourcePermissionsPage } from "@/pages/ResourcePermissions";
import { PermissionTesterPage } from "@/pages/PermissionTester";
import { SessionsPage } from "@/pages/Sessions";

function RequireAuth({ children }: { children: ReactNode }) {
  const isAuthed = useAuthStore((s) => s.isAuthenticated());
  const location = useLocation();
  if (!isAuthed) {
    const next = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?next=${next}`} replace />;
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/*"
        element={
          <RequireAuth>
            <AdminLayout>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/tenants/*" element={<TenantsPage />} />
                <Route path="/applications/*" element={<ApplicationsPage />} />
                <Route path="/users/*" element={<UsersPage />} />
                <Route path="/roles/*" element={<RolesPage />} />
                <Route path="/permissions" element={<PermissionsPage />} />
                <Route path="/resource-permissions" element={<ResourcePermissionsPage />} />
                <Route path="/permission-tester" element={<PermissionTesterPage />} />
                <Route path="/sessions" element={<SessionsPage />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </AdminLayout>
          </RequireAuth>
        }
      />
    </Routes>
  );
}
