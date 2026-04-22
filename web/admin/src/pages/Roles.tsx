import { useEffect, useState } from "react";
import {
  Button,
  Drawer,
  Form,
  Input,
  Modal,
  Popconfirm,
  Space,
  Table,
  Tabs,
  Tag,
  Typography,
  message,
} from "antd";
import { PlusOutlined, ReloadOutlined } from "@ant-design/icons";
import { authzApi } from "@/api/authz";
import { useAuthStore } from "@/stores/auth";
import { PermissionGate } from "@/components/PermissionGate";
import { ResourceActionPicker } from "@/components/ResourceActionPicker";
import { JsonPreview } from "@/components/JsonPreview";
import type { RoleResponse, UserAppRoleResponse } from "@/types/api";

const { Title, Paragraph, Text } = Typography;

export function RolesPage() {
  const claims = useAuthStore((s) => s.claims);
  const appID = claims?.app_id ?? "";
  const tenantID = claims?.tenant_id ?? "";
  const [data, setData] = useState<RoleResponse[]>([]);
  const [loading, setLoading] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [createForm] = Form.useForm();
  const [creating, setCreating] = useState(false);
  const [detail, setDetail] = useState<RoleResponse | null>(null);

  const reload = async () => {
    if (!appID) return;
    setLoading(true);
    try {
      const list = await authzApi.listRoles(appID);
      setData(list);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appID]);

  const onCreate = async (values: { name: string; description: string }) => {
    setCreating(true);
    try {
      const res = await authzApi.createRole({
        app_id: appID,
        tenant_id: tenantID,
        name: values.name,
        description: values.description,
      });
      message.success(`已创建角色 ${res.id}`);
      createForm.resetFields();
      setDrawerOpen(false);
      reload();
    } finally {
      setCreating(false);
    }
  };

  return (
    <div>
      <Title level={3}>角色管理</Title>
      <Paragraph type="secondary">当前应用 <code>{appID}</code> 下的角色；含成员/权限两个 Tab。</Paragraph>
      <div className="openiam-toolbar">
        <PermissionGate resource="roles" action="create">
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setDrawerOpen(true)}>
            新建角色
          </Button>
        </PermissionGate>
        <Button icon={<ReloadOutlined />} onClick={reload}>
          刷新
        </Button>
      </div>

      <Table<RoleResponse>
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
          { title: "描述", dataIndex: "description" },
          {
            title: "类型",
            dataIndex: "is_system",
            width: 100,
            render: (v) => <Tag color={v ? "blue" : "default"}>{v ? "系统" : "自定义"}</Tag>,
          },
          {
            title: "操作",
            width: 200,
            render: (_, row) => (
              <Space size="small">
                <Button size="small" type="link" onClick={() => setDetail(row)}>
                  详情
                </Button>
                <PermissionGate resource="roles" action="delete">
                  <Popconfirm
                    title={`确认删除角色 ${row.name}?`}
                    onConfirm={async () => {
                      await authzApi.deleteRole(row.id);
                      message.success("已删除");
                      reload();
                    }}
                  >
                    <Button size="small" danger type="link" disabled={row.is_system}>
                      删除
                    </Button>
                  </Popconfirm>
                </PermissionGate>
              </Space>
            ),
          },
        ]}
      />

      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title="新建角色"
        width={420}
      >
        <Form form={createForm} layout="vertical" onFinish={onCreate}>
          <Form.Item name="name" label="角色名" rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="description" label="描述">
            <Input />
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
        title={detail ? `角色详情：${detail.name}` : ""}
        width={780}
        destroyOnClose
      >
        {detail && (
          <Tabs
            defaultActiveKey="members"
            items={[
              {
                key: "members",
                label: "成员",
                children: <MembersTab role={detail} />,
              },
              {
                key: "permissions",
                label: "权限",
                children: <PermissionsTab role={detail} onChanged={reload} />,
              },
              {
                key: "raw",
                label: "原始响应",
                children: <JsonPreview data={detail} collapsedByDefault={false} />,
              },
            ]}
          />
        )}
      </Modal>
    </div>
  );
}

function MembersTab({ role }: { role: RoleResponse }) {
  const [members, setMembers] = useState<UserAppRoleResponse[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    authzApi
      .listRoleMembers(role.id)
      .then(setMembers)
      .finally(() => setLoading(false));
  }, [role.id]);

  return (
    <Table<UserAppRoleResponse>
      rowKey={(r) => `${r.user_id}-${r.role_id}`}
      loading={loading}
      dataSource={members}
      pagination={false}
      size="small"
      columns={[
        {
          title: "用户 ID",
          dataIndex: "user_id",
          render: (v) => <Text className="openiam-monospace">{v}</Text>,
        },
        { title: "App ID", dataIndex: "app_id", width: 320 },
        { title: "分配时间", dataIndex: "assigned_at", width: 220 },
      ]}
    />
  );
}

function PermissionsTab({
  role,
  onChanged,
}: {
  role: RoleResponse;
  onChanged: () => void;
}) {
  const [perms, setPerms] = useState<string[]>(role.permissions ?? []);
  const [resource, setResource] = useState("");
  const [action, setAction] = useState("");
  const [adding, setAdding] = useState(false);

  useEffect(() => {
    setPerms(role.permissions ?? []);
  }, [role]);

  const onGrant = async () => {
    if (!resource || !action) {
      message.warning("请选择 resource 与 action");
      return;
    }
    setAdding(true);
    try {
      await authzApi.grantPermission(role.id, { resource, action });
      message.success("已授予");
      setResource("");
      setAction("");
      setPerms((p) => Array.from(new Set([...p, `${resource}:${action}`])));
      onChanged();
    } finally {
      setAdding(false);
    }
  };

  const onRevoke = async (key: string) => {
    const [r, a] = key.split(":");
    if (!r || !a) return;
    await authzApi.revokePermission(role.id, { resource: r, action: a });
    message.success("已撤销");
    setPerms((p) => p.filter((k) => k !== key));
    onChanged();
  };

  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      <div className="openiam-toolbar" style={{ width: "100%" }}>
        <div style={{ flex: 1 }}>
          <ResourceActionPicker
            appID={role.app_id}
            value={{ resource, action }}
            onChange={(v) => {
              setResource(v.resource);
              setAction(v.action);
            }}
          />
        </div>
        <PermissionGate resource="roles" action="grant_permission">
          <Button type="primary" loading={adding} onClick={onGrant}>
            授予权限
          </Button>
        </PermissionGate>
      </div>

      <Table
        rowKey={(r) => r}
        dataSource={perms}
        pagination={false}
        size="small"
        columns={[
          { title: "权限", render: (v) => <Text className="openiam-monospace">{v}</Text> },
          {
            title: "操作",
            width: 100,
            render: (_, key) => (
              <PermissionGate resource="roles" action="revoke_permission">
                <Popconfirm title="确认撤销?" onConfirm={() => onRevoke(key as string)}>
                  <Button danger size="small" type="link">
                    撤销
                  </Button>
                </Popconfirm>
              </PermissionGate>
            ),
          },
        ]}
      />
    </Space>
  );
}
