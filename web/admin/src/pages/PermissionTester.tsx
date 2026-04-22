import { useState } from "react";
import {
  Alert,
  Button,
  Form,
  Input,
  Space,
  Tabs,
  Tag,
  Typography,
} from "antd";
import { ExperimentOutlined } from "@ant-design/icons";
import { authzApi } from "@/api/authz";
import { useAuthStore } from "@/stores/auth";
import { ResourceActionPicker } from "@/components/ResourceActionPicker";
import { JsonPreview } from "@/components/JsonPreview";
import type { CheckPermissionResponse } from "@/types/api";

const { Title, Paragraph } = Typography;

export function PermissionTesterPage() {
  const claims = useAuthStore((s) => s.claims);
  const appID = claims?.app_id ?? "";
  const userIDDefault = claims?.user_id ?? "";

  return (
    <div>
      <Title level={3}>权限自检</Title>
      <Paragraph type="secondary">
        开发与排障工具：可以为任意 user/app/resource/action 组合调用 <code>POST /authz/check</code>{" "}
        与 <code>POST /authz/resources/check</code>。
      </Paragraph>

      <Tabs
        defaultActiveKey="global"
        items={[
          {
            key: "global",
            label: "全局权限",
            children: (
              <GlobalCheckForm appID={appID} userIDDefault={userIDDefault} />
            ),
          },
          {
            key: "resource",
            label: "资源权限",
            children: (
              <ResourceCheckForm appID={appID} userIDDefault={userIDDefault} />
            ),
          },
        ]}
      />
    </div>
  );
}

function GlobalCheckForm({
  appID,
  userIDDefault,
}: {
  appID: string;
  userIDDefault: string;
}) {
  const [form] = Form.useForm<{
    user_id: string;
    app_id: string;
    resource: string;
    action: string;
  }>();
  const [result, setResult] = useState<CheckPermissionResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [picker, setPicker] = useState({ resource: "", action: "" });

  const onSubmit = async (values: {
    user_id: string;
    app_id: string;
    resource: string;
    action: string;
  }) => {
    setLoading(true);
    try {
      const res = await authzApi.checkPermission({
        user_id: values.user_id,
        app_id: values.app_id,
        resource: picker.resource || values.resource,
        action: picker.action || values.action,
      });
      setResult(res);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      <Form
        form={form}
        layout="vertical"
        onFinish={onSubmit}
        initialValues={{ user_id: userIDDefault, app_id: appID }}
      >
        <Form.Item name="user_id" label="user_id" rules={[{ required: true }]}>
          <Input />
        </Form.Item>
        <Form.Item name="app_id" label="app_id" rules={[{ required: true }]}>
          <Input />
        </Form.Item>
        <Form.Item label="resource / action">
          <ResourceActionPicker
            appID={appID}
            value={picker}
            onChange={(v) => setPicker({ resource: v.resource, action: v.action })}
          />
        </Form.Item>
        <Button
          type="primary"
          htmlType="submit"
          loading={loading}
          icon={<ExperimentOutlined />}
        >
          检查
        </Button>
      </Form>

      {result && (
        <>
          <Alert
            type={result.allowed ? "success" : "error"}
            showIcon
            message={
              <span>
                结果：<Tag color={result.allowed ? "green" : "red"}>
                  {result.allowed ? "ALLOWED" : "DENIED"}
                </Tag>
              </span>
            }
          />
          <JsonPreview data={result} collapsedByDefault={false} />
        </>
      )}
    </Space>
  );
}

function ResourceCheckForm({
  appID,
  userIDDefault,
}: {
  appID: string;
  userIDDefault: string;
}) {
  const [form] = Form.useForm<{
    user_id: string;
    app_id: string;
    resource_type: string;
    resource_id: string;
    action: string;
  }>();
  const [result, setResult] = useState<CheckPermissionResponse | null>(null);
  const [loading, setLoading] = useState(false);

  const onSubmit = async (values: {
    user_id: string;
    app_id: string;
    resource_type: string;
    resource_id: string;
    action: string;
  }) => {
    setLoading(true);
    try {
      const res = await authzApi.checkResourcePermission(values);
      setResult(res);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      <Form
        form={form}
        layout="vertical"
        onFinish={onSubmit}
        initialValues={{ user_id: userIDDefault, app_id: appID }}
      >
        <Form.Item name="user_id" label="user_id" rules={[{ required: true }]}>
          <Input />
        </Form.Item>
        <Form.Item name="app_id" label="app_id" rules={[{ required: true }]}>
          <Input />
        </Form.Item>
        <Form.Item name="resource_type" label="resource_type" rules={[{ required: true }]}>
          <Input placeholder="例如 articles" />
        </Form.Item>
        <Form.Item name="resource_id" label="resource_id" rules={[{ required: true }]}>
          <Input />
        </Form.Item>
        <Form.Item name="action" label="action" rules={[{ required: true }]}>
          <Input />
        </Form.Item>
        <Button
          type="primary"
          htmlType="submit"
          loading={loading}
          icon={<ExperimentOutlined />}
        >
          检查
        </Button>
      </Form>

      {result && (
        <>
          <Alert
            type={result.allowed ? "success" : "error"}
            showIcon
            message={
              <span>
                结果：<Tag color={result.allowed ? "green" : "red"}>
                  {result.allowed ? "ALLOWED" : "DENIED"}
                </Tag>
              </span>
            }
          />
          <JsonPreview data={result} collapsedByDefault={false} />
        </>
      )}
    </Space>
  );
}
