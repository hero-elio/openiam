import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Button, Card, Form, Input, Tabs, Typography, message } from "antd";
import { authnApi } from "@/api/authn";
import { useAuthStore } from "@/stores/auth";

const { Title, Paragraph, Text } = Typography;

interface LoginFormValues {
  app_id: string;
  email: string;
  password: string;
  provider?: string;
}

interface RegisterFormValues {
  tenant_id: string;
  app_id: string;
  email: string;
  password: string;
}

export function Login() {
  const navigate = useNavigate();
  const [search] = useSearchParams();
  const next = search.get("next") || "/";
  const setTokens = useAuthStore((s) => s.setTokens);
  const isAuthed = useAuthStore((s) => s.isAuthenticated());
  const [submitting, setSubmitting] = useState(false);
  const [registering, setRegistering] = useState(false);

  useEffect(() => {
    if (isAuthed) {
      navigate(next, { replace: true });
    }
  }, [isAuthed, navigate, next]);

  const onLogin = async (values: LoginFormValues) => {
    setSubmitting(true);
    try {
      const res = await authnApi.login({
        app_id: values.app_id,
        email: values.email,
        password: values.password,
        provider: values.provider || "password",
      });
      setTokens(res.access_token, res.refresh_token);
      message.success("登录成功");
      navigate(next, { replace: true });
    } finally {
      setSubmitting(false);
    }
  };

  const onRegister = async (values: RegisterFormValues) => {
    setRegistering(true);
    try {
      const res = await authnApi.register({
        tenant_id: values.tenant_id,
        app_id: values.app_id,
        email: values.email,
        password: values.password,
      });
      setTokens(res.access_token, res.refresh_token);
      message.success("注册成功并已登录");
      navigate(next, { replace: true });
    } finally {
      setRegistering(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#f0f2f5",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 24,
      }}
    >
      <Card style={{ width: 420 }}>
        <Title level={3} style={{ marginBottom: 0 }}>
          OpenIAM 管理后台
        </Title>
        <Paragraph type="secondary" style={{ marginTop: 4 }}>
          需要 <Text code>super_admin</Text> 角色登录目标 app
        </Paragraph>
        <Tabs
          defaultActiveKey="login"
          items={[
            {
              key: "login",
              label: "登录",
              children: (
                <Form<LoginFormValues>
                  layout="vertical"
                  onFinish={onLogin}
                  initialValues={{ provider: "password" }}
                  autoComplete="on"
                >
                  <Form.Item
                    name="app_id"
                    label="App ID"
                    rules={[{ required: true }]}
                    extra="bootstrap 输出的 app_id（UUID）；tenant 由后端从 app 反查"
                  >
                    <Input placeholder="应用 ID" autoComplete="organization" />
                  </Form.Item>
                  <Form.Item
                    name="email"
                    label="邮箱"
                    rules={[{ required: true, type: "email" }]}
                  >
                    <Input autoComplete="email" />
                  </Form.Item>
                  <Form.Item
                    name="password"
                    label="密码"
                    rules={[{ required: true, min: 8 }]}
                  >
                    <Input.Password autoComplete="current-password" />
                  </Form.Item>
                  <Form.Item name="provider" label="Provider">
                    <Input placeholder="password" />
                  </Form.Item>
                  <Button type="primary" htmlType="submit" block loading={submitting}>
                    登录
                  </Button>
                </Form>
              ),
            },
            {
              key: "register",
              label: "首次部署注册",
              children: (
                <>
                  <Paragraph type="secondary">
                    仅在 bootstrap 第一个用户时使用；权限校验由后端的注册策略决定。
                  </Paragraph>
                  <Form<RegisterFormValues> layout="vertical" onFinish={onRegister}>
                    <Form.Item
                      name="tenant_id"
                      label="Tenant ID"
                      rules={[{ required: true }]}
                    >
                      <Input />
                    </Form.Item>
                    <Form.Item
                      name="app_id"
                      label="App ID"
                      rules={[{ required: true }]}
                    >
                      <Input />
                    </Form.Item>
                    <Form.Item
                      name="email"
                      label="邮箱"
                      rules={[{ required: true, type: "email" }]}
                    >
                      <Input />
                    </Form.Item>
                    <Form.Item
                      name="password"
                      label="密码"
                      rules={[{ required: true, min: 8 }]}
                    >
                      <Input.Password />
                    </Form.Item>
                    <Button type="primary" htmlType="submit" block loading={registering}>
                      注册并登录
                    </Button>
                  </Form>
                </>
              ),
            },
          ]}
        />
      </Card>
    </div>
  );
}
