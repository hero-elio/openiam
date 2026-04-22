import { useEffect, useState } from "react";
import {
  Button,
  Drawer,
  Form,
  Input,
  Popconfirm,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import { PlusOutlined, ReloadOutlined } from "@ant-design/icons";
import { authzApi } from "@/api/authz";
import { useAuthStore } from "@/stores/auth";
import { PermissionGate } from "@/components/PermissionGate";
import type { PermissionDefinitionResponse } from "@/types/api";

const { Title, Paragraph, Text } = Typography;

export function PermissionsPage() {
  const claims = useAuthStore((s) => s.claims);
  const appID = claims?.app_id ?? "";
  const [data, setData] = useState<PermissionDefinitionResponse[]>([]);
  const [loading, setLoading] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [form] = Form.useForm<{ resource: string; action: string; description: string }>();
  const [creating, setCreating] = useState(false);

  const reload = async () => {
    if (!appID) return;
    setLoading(true);
    try {
      const list = await authzApi.listPermissionDefinitions(appID);
      setData(list);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appID]);

  const builtin = data.filter((d) => d.is_builtin);
  const custom = data.filter((d) => !d.is_builtin);

  const onCreate = async (values: {
    resource: string;
    action: string;
    description: string;
  }) => {
    setCreating(true);
    try {
      await authzApi.registerPermission({
        app_id: appID,
        resource: values.resource,
        action: values.action,
        description: values.description,
      });
      message.success("已注册自定义权限");
      form.resetFields();
      setDrawerOpen(false);
      reload();
    } finally {
      setCreating(false);
    }
  };

  const renderTable = (rows: PermissionDefinitionResponse[], allowDelete: boolean) => (
    <Table<PermissionDefinitionResponse>
      rowKey="id"
      loading={loading}
      dataSource={rows}
      pagination={{ pageSize: 50 }}
      size="small"
      columns={[
        {
          title: "Resource",
          dataIndex: "resource",
          render: (v) => <Text className="openiam-monospace">{v}</Text>,
        },
        {
          title: "Action",
          dataIndex: "action",
          render: (v) => <Text className="openiam-monospace">{v}</Text>,
        },
        { title: "描述", dataIndex: "description" },
        {
          title: "类型",
          dataIndex: "is_builtin",
          width: 100,
          render: (v) => <Tag color={v ? "blue" : "green"}>{v ? "内置" : "自定义"}</Tag>,
        },
        ...(allowDelete
          ? [
              {
                title: "操作",
                width: 100,
                render: (_: unknown, row: PermissionDefinitionResponse) => (
                  <PermissionGate resource="permissions" action="delete">
                    <Popconfirm
                      title="确认删除该权限定义?"
                      onConfirm={async () => {
                        await authzApi.deletePermission({
                          app_id: appID,
                          resource: row.resource,
                          action: row.action,
                        });
                        message.success("已删除");
                        reload();
                      }}
                    >
                      <Button danger size="small" type="link">
                        删除
                      </Button>
                    </Popconfirm>
                  </PermissionGate>
                ),
              },
            ]
          : []),
      ]}
    />
  );

  return (
    <div>
      <Title level={3}>权限定义</Title>
      <Paragraph type="secondary">
        内置权限由 SDK 在启动时注册（不可删除）；自定义权限按应用维度新增。
      </Paragraph>
      <div className="openiam-toolbar">
        <PermissionGate resource="permissions" action="create">
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setDrawerOpen(true)}>
            新建自定义权限
          </Button>
        </PermissionGate>
        <Button icon={<ReloadOutlined />} onClick={reload}>
          刷新
        </Button>
      </div>

      <Space direction="vertical" size="large" style={{ width: "100%" }}>
        <div>
          <Title level={5}>内置权限（{builtin.length}）</Title>
          {renderTable(builtin, false)}
        </div>
        <div>
          <Title level={5}>自定义权限（{custom.length}）</Title>
          {renderTable(custom, true)}
        </div>
      </Space>

      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title="新建自定义权限"
        width={420}
      >
        <Form form={form} layout="vertical" onFinish={onCreate}>
          <Form.Item name="resource" label="Resource" rules={[{ required: true }]}>
            <Input placeholder="例如 articles" />
          </Form.Item>
          <Form.Item name="action" label="Action" rules={[{ required: true }]}>
            <Input placeholder="例如 publish" />
          </Form.Item>
          <Form.Item name="description" label="描述">
            <Input />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={creating} block>
            提交
          </Button>
        </Form>
      </Drawer>
    </div>
  );
}
