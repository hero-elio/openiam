import { useEffect, useMemo, useState } from "react";
import {
  Button,
  Drawer,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  Typography,
  message,
} from "antd";
import { PlusOutlined, ReloadOutlined } from "@ant-design/icons";
import { identityApi } from "@/api/identity";
import { authzApi } from "@/api/authz";
import { useAuthStore } from "@/stores/auth";
import { PermissionGate } from "@/components/PermissionGate";
import { JsonPreview } from "@/components/JsonPreview";
import type {
  RoleResponse,
  UserAppRoleResponse,
  UserResponse,
} from "@/types/api";

const { Title, Paragraph, Text } = Typography;

export function UsersPage() {
  const claims = useAuthStore((s) => s.claims);
  const [data, setData] = useState<UserResponse[]>([]);
  const [loading, setLoading] = useState(false);
  const [filterTenant, setFilterTenant] = useState<string>(claims?.tenant_id ?? "");
  const [filterEmail, setFilterEmail] = useState<string>("");

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [createForm] = Form.useForm();
  const [creating, setCreating] = useState(false);

  const [detailUser, setDetailUser] = useState<UserResponse | null>(null);

  const reload = useMemo(
    () => async () => {
      setLoading(true);
      try {
        const list = await identityApi.list({
          tenant_id: filterTenant || undefined,
          email_like: filterEmail ? `%${filterEmail}%` : undefined,
          limit: 200,
        });
        setData(list);
      } finally {
        setLoading(false);
      }
    },
    [filterTenant, filterEmail],
  );

  useEffect(() => {
    reload();
  }, [reload]);

  const onCreate = async (values: {
    tenant_id: string;
    app_id: string;
    email: string;
    password: string;
  }) => {
    setCreating(true);
    try {
      const res = await identityApi.register({ ...values });
      message.success(`已创建用户 ${res.id}`);
      createForm.resetFields();
      setDrawerOpen(false);
      reload();
    } finally {
      setCreating(false);
    }
  };

  return (
    <div>
      <Title level={3}>用户管理</Title>
      <Paragraph type="secondary">列出全部用户，可按租户和邮箱过滤；详情页提供改资料、改密、角色 Tab。</Paragraph>
      <div className="openiam-toolbar">
        <Input
          placeholder="按 tenant_id 过滤"
          allowClear
          style={{ width: 280 }}
          value={filterTenant}
          onChange={(e) => setFilterTenant(e.target.value)}
        />
        <Input.Search
          placeholder="按邮箱模糊过滤"
          allowClear
          style={{ width: 280 }}
          value={filterEmail}
          onChange={(e) => setFilterEmail(e.target.value)}
          onSearch={() => reload()}
        />
        <PermissionGate resource="users" action="create">
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setDrawerOpen(true)}>
            新建用户
          </Button>
        </PermissionGate>
        <Button icon={<ReloadOutlined />} onClick={reload}>
          刷新
        </Button>
      </div>

      <Table<UserResponse>
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
          { title: "邮箱", dataIndex: "email" },
          { title: "显示名", dataIndex: "display_name" },
          {
            title: "状态",
            dataIndex: "status",
            render: (v) => <Tag color={v === "active" ? "green" : "default"}>{v}</Tag>,
            width: 100,
          },
          { title: "Tenant", dataIndex: "tenant_id", width: 320 },
          {
            title: "操作",
            width: 120,
            render: (_, row) => (
              <Button size="small" type="link" onClick={() => setDetailUser(row)}>
                详情
              </Button>
            ),
          },
        ]}
      />

      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title="新建用户（管理员预配）"
        width={520}
      >
        <Form
          form={createForm}
          layout="vertical"
          onFinish={onCreate}
          initialValues={{
            tenant_id: claims?.tenant_id,
            app_id: claims?.app_id,
          }}
        >
          <Form.Item name="tenant_id" label="Tenant ID" rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="app_id" label="App ID" rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="email" label="邮箱" rules={[{ required: true, type: "email" }]}>
            <Input />
          </Form.Item>
          <Form.Item name="password" label="初始密码" rules={[{ required: true, min: 8 }]}>
            <Input.Password />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={creating} block>
            提交
          </Button>
        </Form>
      </Drawer>

      <UserDetailModal
        user={detailUser}
        onClose={() => setDetailUser(null)}
        onChanged={reload}
      />
    </div>
  );
}

function UserDetailModal({
  user,
  onClose,
  onChanged,
}: {
  user: UserResponse | null;
  onClose: () => void;
  onChanged: () => void;
}) {
  return (
    <Modal
      open={!!user}
      onCancel={onClose}
      footer={null}
      title={user ? `用户详情 ${user.id.slice(0, 8)}…` : ""}
      width={760}
      destroyOnClose
    >
      {user && (
        <Tabs
          defaultActiveKey="profile"
          items={[
            {
              key: "profile",
              label: "资料",
              children: <ProfileTab user={user} onChanged={onChanged} />,
            },
            {
              key: "password",
              label: "改密",
              children: <PasswordTab user={user} />,
            },
            {
              key: "roles",
              label: "角色",
              children: <RolesTab user={user} />,
            },
            {
              key: "raw",
              label: "原始响应",
              children: <JsonPreview data={user} collapsedByDefault={false} />,
            },
          ]}
        />
      )}
    </Modal>
  );
}

function ProfileTab({ user, onChanged }: { user: UserResponse; onChanged: () => void }) {
  const [form] = Form.useForm<{ display_name: string; avatar_url: string }>();
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    form.setFieldsValue({
      display_name: user.display_name,
      avatar_url: user.avatar_url,
    });
  }, [form, user]);

  const onSave = async (values: { display_name: string; avatar_url: string }) => {
    setSaving(true);
    try {
      await identityApi.updateProfile(user.id, values);
      message.success("已保存");
      onChanged();
    } finally {
      setSaving(false);
    }
  };

  return (
    <Form form={form} layout="vertical" onFinish={onSave}>
      <Form.Item name="display_name" label="显示名">
        <Input />
      </Form.Item>
      <Form.Item name="avatar_url" label="头像 URL">
        <Input />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={saving}>
        保存
      </Button>
    </Form>
  );
}

function PasswordTab({ user }: { user: UserResponse }) {
  const claims = useAuthStore((s) => s.claims);
  const [form] = Form.useForm<{ old_password: string; new_password: string }>();
  const [saving, setSaving] = useState(false);

  const isSelf = user.id === claims?.user_id;

  return (
    <Form
      form={form}
      layout="vertical"
      onFinish={async (values) => {
        setSaving(true);
        try {
          await identityApi.changePassword(user.id, values);
          message.success("密码已更新");
          form.resetFields();
        } finally {
          setSaving(false);
        }
      }}
    >
      {!isSelf && (
        <Paragraph type="warning">
          注意：只能为自己修改密码（owner-only），管理员重置密码当前未直接暴露 API。
        </Paragraph>
      )}
      <Form.Item name="old_password" label="旧密码" rules={[{ required: true, min: 8 }]}>
        <Input.Password />
      </Form.Item>
      <Form.Item name="new_password" label="新密码" rules={[{ required: true, min: 8 }]}>
        <Input.Password />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={saving}>
        修改密码
      </Button>
    </Form>
  );
}

function RolesTab({ user }: { user: UserResponse }) {
  const claims = useAuthStore((s) => s.claims);
  const appID = claims?.app_id ?? "";
  const [list, setList] = useState<UserAppRoleResponse[]>([]);
  const [roles, setRoles] = useState<RoleResponse[]>([]);
  const [loading, setLoading] = useState(false);
  const [picking, setPicking] = useState<string | undefined>(undefined);

  const reload = async () => {
    setLoading(true);
    try {
      const [u, r] = await Promise.all([
        authzApi.listUserRoles(user.id, appID),
        authzApi.listRoles(appID),
      ]);
      setList(u);
      setRoles(r);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (appID) reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user.id, appID]);

  const roleNameByID = (rid: string) => roles.find((r) => r.id === rid)?.name ?? rid;

  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      <div className="openiam-toolbar">
        <Select
          showSearch
          allowClear
          placeholder="选择要分配的角色"
          style={{ width: 320 }}
          options={roles.map((r) => ({ value: r.id, label: `${r.name} (${r.id.slice(0, 8)})` }))}
          value={picking}
          onChange={setPicking}
          filterOption={(input, opt) =>
            (opt?.label as string).toLowerCase().includes(input.toLowerCase())
          }
        />
        <PermissionGate resource="roles" action="assign">
          <Button
            type="primary"
            disabled={!picking}
            onClick={async () => {
              if (!picking || !claims) return;
              await authzApi.assignRole(user.id, {
                app_id: appID,
                role_id: picking,
                tenant_id: claims.tenant_id,
              });
              message.success("已分配");
              setPicking(undefined);
              reload();
            }}
          >
            分配
          </Button>
        </PermissionGate>
      </div>

      <Table<UserAppRoleResponse>
        rowKey={(r) => `${r.user_id}-${r.role_id}`}
        loading={loading}
        dataSource={list}
        pagination={false}
        size="small"
        columns={[
          {
            title: "Role",
            dataIndex: "role_id",
            render: (v) => (
              <span>
                {roleNameByID(v)} <Text type="secondary" className="openiam-monospace">({v})</Text>
              </span>
            ),
          },
          { title: "分配时间", dataIndex: "assigned_at", width: 220 },
          {
            title: "操作",
            width: 120,
            render: (_, row) => (
              <PermissionGate resource="roles" action="assign">
                <Popconfirm
                  title="确认解除分配？"
                  onConfirm={async () => {
                    await authzApi.unassignRole(user.id, row.role_id, appID);
                    message.success("已解除");
                    reload();
                  }}
                >
                  <Button danger size="small" type="link">
                    解除
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
