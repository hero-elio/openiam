import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Button,
  Drawer,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  Typography,
  message,
} from "antd";
import { CopyOutlined, PlusOutlined, ReloadOutlined } from "@ant-design/icons";
import { tenantApi } from "@/api/tenant";
import { useAuthStore } from "@/stores/auth";
import { PermissionGate } from "@/components/PermissionGate";
import { JsonPreview } from "@/components/JsonPreview";
import type { ApplicationResponse, CreateApplicationResponse, TenantResponse } from "@/types/api";

const { Title, Paragraph, Text } = Typography;

export function ApplicationsPage() {
  const claims = useAuthStore((s) => s.claims);
  const [tenants, setTenants] = useState<TenantResponse[]>([]);
  const [tenantID, setTenantID] = useState<string | undefined>(claims?.tenant_id);
  const [data, setData] = useState<ApplicationResponse[]>([]);
  const [loading, setLoading] = useState(false);

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [createForm] = Form.useForm<{ name: string }>();
  const [creating, setCreating] = useState(false);
  const [createResult, setCreateResult] = useState<CreateApplicationResponse | null>(null);

  const [detail, setDetail] = useState<ApplicationResponse | null>(null);
  const [editing, setEditing] = useState<ApplicationResponse | null>(null);
  const [editForm] = Form.useForm<{ name: string; redirect_uris: string; scopes: string }>();
  const [savingEdit, setSavingEdit] = useState(false);

  useEffect(() => {
    tenantApi.list({ limit: 200 }).then(setTenants).catch(() => undefined);
  }, []);

  const reload = useMemo(
    () => async () => {
      if (!tenantID) return;
      setLoading(true);
      try {
        const list = await tenantApi.listApplications(tenantID);
        setData(list);
      } finally {
        setLoading(false);
      }
    },
    [tenantID],
  );

  useEffect(() => {
    reload();
  }, [reload]);

  const onCreate = async ({ name }: { name: string }) => {
    if (!tenantID) return;
    setCreating(true);
    try {
      const res = await tenantApi.createApplication(tenantID, name);
      setCreateResult(res);
      message.success(`已创建应用 ${res.id}`);
      createForm.resetFields();
      reload();
    } finally {
      setCreating(false);
    }
  };

  const onEdit = async (values: { name: string; redirect_uris: string; scopes: string }) => {
    if (!editing) return;
    setSavingEdit(true);
    try {
      await tenantApi.updateApplication(editing.id, {
        name: values.name,
        redirect_uris: values.redirect_uris
          ? values.redirect_uris.split("\n").map((s) => s.trim()).filter(Boolean)
          : [],
        scopes: values.scopes
          ? values.scopes.split(",").map((s) => s.trim()).filter(Boolean)
          : [],
      });
      message.success("已更新");
      setEditing(null);
      reload();
    } finally {
      setSavingEdit(false);
    }
  };

  return (
    <div>
      <Title level={3}>应用管理</Title>
      <Paragraph type="secondary">
        应用属于某个租户；客户端密钥仅在创建时返回一次，请妥善保存。
      </Paragraph>
      <div className="openiam-toolbar">
        <Select
          style={{ width: 320 }}
          showSearch
          placeholder="选择租户"
          optionFilterProp="label"
          value={tenantID}
          onChange={setTenantID}
          options={tenants.map((t) => ({ value: t.id, label: `${t.name} (${t.id})` }))}
        />
        <PermissionGate resource="applications" action="create">
          <Button
            type="primary"
            icon={<PlusOutlined />}
            disabled={!tenantID}
            onClick={() => setDrawerOpen(true)}
          >
            新建应用
          </Button>
        </PermissionGate>
        <Button icon={<ReloadOutlined />} onClick={reload}>
          刷新
        </Button>
      </div>

      <Table<ApplicationResponse>
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
            title: "Client ID",
            dataIndex: "client_id",
            render: (v) => <Text className="openiam-monospace">{v}</Text>,
          },
          {
            title: "状态",
            dataIndex: "status",
            render: (v) => <Tag color={v === "active" ? "green" : "default"}>{v}</Tag>,
            width: 100,
          },
          {
            title: "操作",
            width: 160,
            render: (_, row) => (
              <Space size="small">
                <Button size="small" type="link" onClick={() => setDetail(row)}>
                  详情
                </Button>
                <PermissionGate resource="applications" action="update">
                  <Button
                    size="small"
                    type="link"
                    onClick={() => {
                      setEditing(row);
                      editForm.setFieldsValue({
                        name: row.name,
                        redirect_uris: (row.redirect_uris ?? []).join("\n"),
                        scopes: (row.scopes ?? []).join(","),
                      });
                    }}
                  >
                    编辑
                  </Button>
                </PermissionGate>
              </Space>
            ),
          },
        ]}
      />

      <Drawer
        open={drawerOpen}
        onClose={() => {
          setDrawerOpen(false);
          setCreateResult(null);
        }}
        title="新建应用"
        width={520}
      >
        <Form form={createForm} layout="vertical" onFinish={onCreate}>
          <Form.Item name="name" label="应用名称" rules={[{ required: true }]}>
            <Input placeholder="例如 portal" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={creating} block>
            提交
          </Button>
        </Form>
        {createResult && (
          <Alert
            type="warning"
            style={{ marginTop: 16 }}
            showIcon
            message="客户端凭证（仅显示一次）"
            description={
              <Tabs
                size="small"
                items={[
                  {
                    key: "client_id",
                    label: "Client ID",
                    children: <ClipboardLine value={createResult.client_id} />,
                  },
                  {
                    key: "client_secret",
                    label: "Client Secret",
                    children: <ClipboardLine value={createResult.client_secret} />,
                  },
                  {
                    key: "raw",
                    label: "原始响应",
                    children: <JsonPreview data={createResult} collapsedByDefault={false} />,
                  },
                ]}
              />
            }
          />
        )}
      </Drawer>

      <Modal
        open={!!detail}
        onCancel={() => setDetail(null)}
        footer={null}
        title="应用详情"
        width={640}
      >
        {detail && <JsonPreview data={detail} collapsedByDefault={false} />}
      </Modal>

      <Modal
        open={!!editing}
        onCancel={() => setEditing(null)}
        title={`编辑应用 ${editing?.id ?? ""}`}
        onOk={() => editForm.submit()}
        confirmLoading={savingEdit}
      >
        <Form form={editForm} layout="vertical" onFinish={onEdit}>
          <Form.Item name="name" label="名称">
            <Input />
          </Form.Item>
          <Form.Item name="redirect_uris" label="Redirect URIs（每行一个）">
            <Input.TextArea rows={4} />
          </Form.Item>
          <Form.Item name="scopes" label="Scopes（逗号分隔）">
            <Input />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}

function ClipboardLine({ value }: { value: string }) {
  return (
    <Space.Compact style={{ width: "100%" }}>
      <Input value={value} readOnly className="openiam-monospace" />
      <Button
        icon={<CopyOutlined />}
        onClick={() => {
          navigator.clipboard?.writeText(value);
          message.success("已复制");
        }}
      />
    </Space.Compact>
  );
}
