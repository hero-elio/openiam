import { useEffect, useState } from "react";
import { Alert, Card, Col, Row, Skeleton, Statistic, Typography } from "antd";
import {
  AppstoreOutlined,
  ClusterOutlined,
  KeyOutlined,
  SafetyCertificateOutlined,
} from "@ant-design/icons";
import { tenantApi } from "@/api/tenant";
import { authzApi } from "@/api/authz";
import { useAuthStore } from "@/stores/auth";

const { Title, Paragraph } = Typography;

interface DashboardStats {
  tenants: number | null;
  applications: number | null;
  roles: number | null;
  permissions: number | null;
}

export function Dashboard() {
  const claims = useAuthStore((s) => s.claims);
  const [stats, setStats] = useState<DashboardStats>({
    tenants: null,
    applications: null,
    roles: null,
    permissions: null,
  });
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    if (!claims?.tenant_id || !claims?.app_id) {
      setLoading(false);
      return;
    }
    setLoading(true);
    Promise.allSettled([
      tenantApi.list({ limit: 200 }),
      tenantApi.listApplications(claims.tenant_id),
      authzApi.listRoles(claims.app_id),
      authzApi.listPermissionDefinitions(claims.app_id),
    ])
      .then(([tenants, apps, roles, perms]) => {
        if (cancelled) return;
        setStats({
          tenants: tenants.status === "fulfilled" ? tenants.value.length : null,
          applications: apps.status === "fulfilled" ? apps.value.length : null,
          roles: roles.status === "fulfilled" ? roles.value.length : null,
          permissions: perms.status === "fulfilled" ? perms.value.length : null,
        });
        const failure = [tenants, apps, roles, perms].find(
          (r) => r.status === "rejected",
        );
        if (failure && failure.status === "rejected") {
          setError("部分聚合数据加载失败，请检查权限或后端可用性");
        } else {
          setError(null);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [claims?.tenant_id, claims?.app_id]);

  return (
    <div>
      <Title level={3}>仪表盘</Title>
      <Paragraph type="secondary">
        当前 tenant <code>{claims?.tenant_id}</code> / app <code>{claims?.app_id}</code> /
        user <code>{claims?.user_id}</code>
      </Paragraph>
      {error && (
        <Alert type="warning" message={error} showIcon style={{ marginBottom: 12 }} />
      )}
      {loading ? (
        <Skeleton active />
      ) : (
        <Row gutter={[16, 16]}>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="租户数"
                value={stats.tenants ?? "-"}
                prefix={<ClusterOutlined />}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="本租户应用数"
                value={stats.applications ?? "-"}
                prefix={<AppstoreOutlined />}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="本应用角色数"
                value={stats.roles ?? "-"}
                prefix={<SafetyCertificateOutlined />}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="本应用权限定义数"
                value={stats.permissions ?? "-"}
                prefix={<KeyOutlined />}
              />
            </Card>
          </Col>
        </Row>
      )}
    </div>
  );
}
