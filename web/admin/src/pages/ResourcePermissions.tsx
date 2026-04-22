import { useState } from "react";
import {
  Button,
  Form,
  Input,
  Modal,
  Popconfirm,
  Table,
  Typography,
  message,
} from "antd";
import { PlusOutlined, ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { authzApi } from "@/api/authz";
import { useAuthStore } from "@/stores/auth";
import { PermissionGate } from "@/components/PermissionGate";
import type { ResourcePermissionResponse } from "@/types/api";

const { Title, Paragraph, Text } = Typography;

export function ResourcePermissionsPage() {
  const claims = useAuthStore((s) => s.claims);
  const appID = claims?.app_id ?? "";
  const tenantID = claims?.tenant_id ?? "";

  const [userID, setUserID] = useState("");
  const [data, setData] = useState<ResourcePermissionResponse[]>([]);
  const [loading, setLoading] = useState(false);
  const [grantOpen, setGrantOpen] = useState(false);
  const [grantForm] =
    Form.useForm<{ resource_type: string; resource_id: string; action: string }>();
  const [granting, setGranting] = useState(false);

  const reload = async () => {
    if (!userID) {
      message.warning("请先输入 user_id");
      return;
    }
    setLoading(true);
    try {
      const list = await authzApi.listResourcePermissions({
        user_id: userID,
        app_id: appID,
      });
      setData(list);
    } finally {
      setLoading(false);
    }
  };

  const onGrant = async (values: {
    resource_type: string;
    resource_id: string;
    action: string;
  }) => {
    if (!userID) return;
    setGranting(true);
    try {
      await authzApi.grantResourcePermission({
        user_id: userID,
        app_id: appID,
        tenant_id: tenantID,
        resource_type: values.resource_type,
        resource_id: values.resource_id,
        action: values.action,
      });
      message.success("已授予资源权限");
      grantForm.resetFields();
      setGrantOpen(false);
      reload();
    } finally {
      setGranting(false);
    }
  };

  const onRevoke = async (row: ResourcePermissionResponse) => {
    await authzApi.revokeResourcePermission({
      user_id: row.user_id,
      app_id: row.app_id,
      resource_type: row.resource_type,
      resource_id: row.resource_id,
      action: row.action,
    });
    message.success("已撤销");
    reload();
  };

  return (
    <div>
      <Title level={3}>资源级权限</Title>
      <Paragraph type="secondary">
        粒度更细的 ACL：给某用户在某条资源上单独授予/撤销动作。
      </Paragraph>

      <div className="openiam-toolbar">
        <Input
          style={{ width: 360 }}
          placeholder="user_id（必填）"
          value={userID}
          onChange={(e) => setUserID(e.target.value)}
        />
        <Button icon={<SearchOutlined />} type="primary" onClick={reload}>
          查询
        </Button>
        <PermissionGate resource="resource_permissions" action="grant">
          <Button
            icon={<PlusOutlined />}
            disabled={!userID}
            onClick={() => setGrantOpen(true)}
          >
            授予
          </Button>
        </PermissionGate>
        <Button icon={<ReloadOutlined />} onClick={reload}>
          刷新
        </Button>
      </div>

      <Table<ResourcePermissionResponse>
        rowKey="id"
        loading={loading}
        dataSource={data}
        pagination={{ pageSize: 20 }}
        columns={[
          {
            title: "Resource Type",
            dataIndex: "resource_type",
            render: (v) => <Text className="openiam-monospace">{v}</Text>,
          },
          {
            title: "Resource ID",
            dataIndex: "resource_id",
            render: (v) => <Text className="openiam-monospace">{v}</Text>,
          },
          {
            title: "Action",
            dataIndex: "action",
            render: (v) => <Text className="openiam-monospace">{v}</Text>,
          },
          { title: "授予时间", dataIndex: "granted_at", width: 220 },
          { title: "授予人", dataIndex: "granted_by", width: 280 },
          {
            title: "操作",
            width: 100,
            render: (_, row) => (
              <PermissionGate resource="resource_permissions" action="revoke">
                <Popconfirm title="确认撤销?" onConfirm={() => onRevoke(row)}>
                  <Button danger size="small" type="link">
                    撤销
                  </Button>
                </Popconfirm>
              </PermissionGate>
            ),
          },
        ]}
      />

      <Modal
        open={grantOpen}
        onCancel={() => setGrantOpen(false)}
        title={`为 ${userID || "?"} 授予资源权限`}
        onOk={() => grantForm.submit()}
        confirmLoading={granting}
      >
        <Form form={grantForm} layout="vertical" onFinish={onGrant}>
          <Form.Item name="resource_type" label="资源类型" rules={[{ required: true }]}>
            <Input placeholder="例如 articles" />
          </Form.Item>
          <Form.Item name="resource_id" label="资源 ID" rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="action" label="动作" rules={[{ required: true }]}>
            <Input placeholder="例如 read / write / delete" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
