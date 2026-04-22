import { useEffect, useState } from "react";
import {
  Alert,
  Button,
  Form,
  Input,
  Popconfirm,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  Typography,
  message,
} from "antd";
import { ReloadOutlined, ThunderboltOutlined } from "@ant-design/icons";
import { authnApi } from "@/api/authn";
import { useAuthStore } from "@/stores/auth";
import { JsonPreview } from "@/components/JsonPreview";
import type { ChallengeResponse, SessionResponse } from "@/types/api";

const { Title, Paragraph, Text } = Typography;

export function SessionsPage() {
  return (
    <div>
      <Title level={3}>会话与凭证</Title>
      <Paragraph type="secondary">
        当前 token 持有者的所有活跃会话；以及绑定额外凭证（SIWE / WebAuthn）。
      </Paragraph>
      <Tabs
        defaultActiveKey="sessions"
        items={[
          { key: "sessions", label: "会话列表", children: <SessionsTab /> },
          { key: "bind", label: "凭证绑定", children: <BindCredentialTab /> },
        ]}
      />
    </div>
  );
}

function SessionsTab() {
  const [data, setData] = useState<SessionResponse[]>([]);
  const [loading, setLoading] = useState(false);

  const reload = async () => {
    setLoading(true);
    try {
      const list = await authnApi.listSessions();
      setData(list);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    reload();
  }, []);

  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      <div className="openiam-toolbar">
        <Button icon={<ReloadOutlined />} onClick={reload}>
          刷新
        </Button>
      </div>
      <Table<SessionResponse>
        rowKey="id"
        loading={loading}
        dataSource={data}
        pagination={{ pageSize: 20 }}
        columns={[
          {
            title: "Session ID",
            dataIndex: "id",
            render: (v) => <Text className="openiam-monospace">{v}</Text>,
            width: 320,
          },
          {
            title: "Provider",
            dataIndex: "provider",
            render: (v) => <Tag>{v}</Tag>,
            width: 110,
          },
          { title: "User-Agent", dataIndex: "user_agent", ellipsis: true },
          { title: "IP", dataIndex: "ip_address", width: 160 },
          { title: "创建时间", dataIndex: "created_at", width: 220 },
          { title: "过期时间", dataIndex: "expires_at", width: 220 },
          {
            title: "操作",
            width: 100,
            render: (_, row) => (
              <Popconfirm
                title="确认撤销此会话?"
                onConfirm={async () => {
                  await authnApi.revokeSession(row.id);
                  message.success("已撤销");
                  reload();
                }}
              >
                <Button danger size="small" type="link">
                  撤销
                </Button>
              </Popconfirm>
            ),
          },
        ]}
      />
    </Space>
  );
}

function BindCredentialTab() {
  const claims = useAuthStore((s) => s.claims);
  const [form] = Form.useForm<{
    provider: string;
    identifier: string;
    signature: string;
    public_key: string;
  }>();
  const [challenge, setChallenge] = useState<ChallengeResponse | null>(null);
  const [loadingChallenge, setLoadingChallenge] = useState(false);
  const [binding, setBinding] = useState(false);
  const [bindResult, setBindResult] = useState<{ id: string } | null>(null);

  const onChallenge = async () => {
    if (!claims) return;
    const provider = form.getFieldValue("provider") ?? "siwe";
    const identifier = form.getFieldValue("identifier");
    if (!identifier) {
      message.warning("请输入 identifier (例如 钱包地址或 webauthn handle)");
      return;
    }
    setLoadingChallenge(true);
    try {
      const c = await authnApi.challenge({
        app_id: claims.app_id,
        tenant_id: claims.tenant_id,
        provider,
        identifier,
      });
      setChallenge(c);
      message.success("已获取 challenge，请离线签名后填回 signature");
    } finally {
      setLoadingChallenge(false);
    }
  };

  const onBind = async (values: {
    provider: string;
    signature: string;
    public_key?: string;
  }) => {
    if (!claims || !challenge) {
      message.warning("请先获取 challenge");
      return;
    }
    setBinding(true);
    try {
      const res = await authnApi.bind({
        user_id: claims.user_id,
        app_id: claims.app_id,
        tenant_id: claims.tenant_id,
        provider: values.provider,
        challenge: challenge.challenge,
        signature: values.signature,
        public_key: values.public_key,
      });
      setBindResult(res);
      message.success("绑定成功");
    } finally {
      setBinding(false);
    }
  };

  return (
    <Space direction="vertical" style={{ width: "100%", maxWidth: 720 }}>
      <Alert
        type="info"
        showIcon
        message="本面板用于诊断/手动绑定流程"
        description="完整 dApp 体验（弹钱包、调浏览器 webauthn API）不在管理后台范畴；这里仅做协议字段级的人工录入。"
      />
      <Form
        form={form}
        layout="vertical"
        initialValues={{ provider: "siwe" }}
        onFinish={onBind}
      >
        <Form.Item name="provider" label="Provider" rules={[{ required: true }]}>
          <Select
            options={[
              { value: "siwe", label: "siwe" },
              { value: "webauthn", label: "webauthn" },
            ]}
          />
        </Form.Item>
        <Form.Item name="identifier" label="Identifier (用于 challenge)">
          <Input placeholder="例如 0x...（SIWE 钱包地址）" />
        </Form.Item>
        <Button
          icon={<ThunderboltOutlined />}
          loading={loadingChallenge}
          onClick={onChallenge}
        >
          1. 获取 Challenge
        </Button>
        {challenge && (
          <Alert
            style={{ marginTop: 12 }}
            type="success"
            message="Challenge"
            description={
              <pre className="openiam-monospace" style={{ margin: 0 }}>
                {JSON.stringify(challenge, null, 2)}
              </pre>
            }
          />
        )}
        <Form.Item name="signature" label="Signature" rules={[{ required: true }]}>
          <Input.TextArea rows={3} placeholder="离线对 challenge 的签名" />
        </Form.Item>
        <Form.Item name="public_key" label="Public Key (WebAuthn 用)">
          <Input.TextArea rows={2} />
        </Form.Item>
        <Button type="primary" htmlType="submit" loading={binding} disabled={!challenge}>
          2. 提交绑定
        </Button>
      </Form>
      {bindResult && <JsonPreview data={bindResult} collapsedByDefault={false} />}
    </Space>
  );
}
