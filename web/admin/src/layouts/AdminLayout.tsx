import { ReactNode, useMemo } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Avatar, Button, Dropdown, Layout, Menu, Space, Tag, Typography } from "antd";
import {
  ApiOutlined,
  AppstoreOutlined,
  AuditOutlined,
  ClusterOutlined,
  DashboardOutlined,
  FileSearchOutlined,
  KeyOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  SafetyCertificateOutlined,
  TeamOutlined,
  UserOutlined,
} from "@ant-design/icons";
import { useAuthStore } from "@/stores/auth";
import { useUIStore } from "@/stores/ui";
import { AppSwitcher } from "@/components/AppSwitcher";
import { authnApi } from "@/api/authn";

const { Header, Sider, Content } = Layout;
const { Text } = Typography;

interface MenuItem {
  key: string;
  label: string;
  icon: ReactNode;
}

const items: MenuItem[] = [
  { key: "/", label: "仪表盘", icon: <DashboardOutlined /> },
  { key: "/tenants", label: "租户", icon: <ClusterOutlined /> },
  { key: "/applications", label: "应用", icon: <AppstoreOutlined /> },
  { key: "/users", label: "用户", icon: <TeamOutlined /> },
  { key: "/roles", label: "角色", icon: <SafetyCertificateOutlined /> },
  { key: "/permissions", label: "权限定义", icon: <KeyOutlined /> },
  { key: "/resource-permissions", label: "资源权限", icon: <AuditOutlined /> },
  { key: "/permission-tester", label: "权限自检", icon: <FileSearchOutlined /> },
  { key: "/sessions", label: "会话与凭证", icon: <ApiOutlined /> },
];

export function AdminLayout({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const location = useLocation();
  const claims = useAuthStore((s) => s.claims);
  const clear = useAuthStore((s) => s.clear);
  const collapsed = useUIStore((s) => s.collapsed);
  const toggle = useUIStore((s) => s.toggleCollapsed);

  const selectedKey = useMemo(() => {
    const path = location.pathname;
    if (path === "/") return "/";
    const match = items
      .map((i) => i.key)
      .filter((k) => k !== "/")
      .find((k) => path === k || path.startsWith(`${k}/`));
    return match ?? "/";
  }, [location.pathname]);

  const onLogout = async () => {
    try {
      await authnApi.logout();
    } catch {
      /* ignore */
    } finally {
      clear();
      navigate("/login", { replace: true });
    }
  };

  return (
    <Layout style={{ minHeight: "100vh" }}>
      <Sider
        collapsible
        collapsed={collapsed}
        trigger={null}
        theme="dark"
        width={220}
      >
        <div
          style={{
            color: "#fff",
            padding: 16,
            fontSize: collapsed ? 14 : 18,
            fontWeight: 600,
            textAlign: "center",
            transition: "all .2s",
          }}
        >
          {collapsed ? "IAM" : "OpenIAM"}
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[selectedKey]}
          items={items.map((i) => ({ key: i.key, icon: i.icon, label: i.label }))}
          onClick={({ key }) => navigate(key)}
        />
      </Sider>
      <Layout>
        <Header
          style={{
            background: "#fff",
            paddingLeft: 12,
            paddingRight: 16,
            display: "flex",
            alignItems: "center",
            gap: 12,
            boxShadow: "0 1px 4px rgba(0,21,41,0.08)",
          }}
        >
          <Button
            type="text"
            icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
            onClick={toggle}
          />
          <Space size="small">
            <Tag color="blue">tenant: {claims?.tenant_id ?? "-"}</Tag>
            <Tag color="geekblue">app: {claims?.app_id ?? "-"}</Tag>
            <AppSwitcher />
          </Space>
          <div style={{ flex: 1 }} />
          <Dropdown
            menu={{
              items: [
                { key: "logout", label: "退出登录", icon: <LogoutOutlined />, onClick: onLogout },
              ],
            }}
          >
            <Space style={{ cursor: "pointer" }}>
              <Avatar size="small" icon={<UserOutlined />} />
              <Text>{claims?.user_id?.slice(0, 8) ?? "user"}</Text>
            </Space>
          </Dropdown>
        </Header>
        <Content style={{ padding: 16 }}>
          <div className="openiam-content-card" style={{ minHeight: "calc(100vh - 96px)" }}>
            {children}
          </div>
        </Content>
      </Layout>
    </Layout>
  );
}
