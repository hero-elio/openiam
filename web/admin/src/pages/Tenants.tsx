import { useEffect, useState } from "react";
import {
  Button,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import { PlusOutlined, ReloadOutlined } from "@ant-design/icons";
import { tenantApi } from "@/api/tenant";
import { PermissionGate } from "@/components/PermissionGate";
import { JsonPreview } from "@/components/JsonPreview";
import type { TenantResponse } from "@/types/api";

const { Title, Paragraph, Text } = Typography;

export function TenantsPage() {
  const [data, setData] = useState<TenantResponse[]>([]);
  const [loading, setLoading] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [detail, setDetail] = useState<TenantResponse | null>(null);
  const [form] = Form.useForm<{ name: string }>();
  const [creating, setCreating] = useState(false);

  const reload = async () => {
    setLoading(true);
    try {
      const list = await tenantApi.list({ limit: 200 });
      setData(list);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    reload();
  }, []);

  const onCreate = async ({ name }: { name: string }) => {
    setCreating(true);
    try {
      const res = await tenantApi.create(name);
      message.success(`已创建租户 ${res.id}`);
      setDrawerOpen(false);
      form.resetFields();
      reload();
    } finally {
      setCreating(false);
    }
  };

  return (
    <div>
      <Title level={3}>租户管理</Title>
      <Paragraph type="secondary">租户是顶层隔离单元；JWT 中的 tenant_id 决定大多数操作的可见范围。</Paragraph>
      <div className="openiam-toolbar">
        <PermissionGate resource="tenants" action="create">
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setDrawerOpen(true)}>
            新建租户
          </Button>
        </PermissionGate>
        <Button icon={<ReloadOutlined />} onClick={reload}>
          刷新
        </Button>
      </div>
      <Table<TenantResponse>
        rowKey="id"
        loading={loading}
        dataSource={data}
        pagination={{ pageSize: 20 }}
        columns={[
          {
            title: "ID",
            dataIndex: "id",
            render: (v) => <Text className="openiam-monospace">{v}</Text>,
            width: 320,
          },
          { title: "名称", dataIndex: "name" },
          {
            title: "状态",
            dataIndex: "status",
            render: (v) => <Tag color={v === "active" ? "green" : "default"}>{v}</Tag>,
            width: 100,
          },
          {
            title: "创建时间",
            dataIndex: "created_at",
            width: 220,
          },
          {
            title: "操作",
            width: 120,
            render: (_, row) => (
              <Button size="small" type="link" onClick={() => setDetail(row)}>
                详情
              </Button>
            ),
          },
        ]}
      />

      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title="新建租户"
        width={400}
      >
        <Form form={form} layout="vertical" onFinish={onCreate}>
          <Form.Item
            name="name"
            label="租户名称"
            rules={[{ required: true, max: 120 }]}
          >
            <Input placeholder="例如 acme" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={creating} block>
            提交
          </Button>
        </Form>
      </Drawer>

      <Modal
        open={!!detail}
        onCancel={() => setDetail(null)}
        footer={null}
        title="租户详情"
        width={640}
      >
        {detail && (
          <Space direction="vertical" style={{ width: "100%" }}>
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="ID">{detail.id}</Descriptions.Item>
              <Descriptions.Item label="名称">{detail.name}</Descriptions.Item>
              <Descriptions.Item label="状态">{detail.status}</Descriptions.Item>
              <Descriptions.Item label="创建时间">{detail.created_at}</Descriptions.Item>
            </Descriptions>
            <JsonPreview data={detail} />
          </Space>
        )}
      </Modal>
    </div>
  );
}
