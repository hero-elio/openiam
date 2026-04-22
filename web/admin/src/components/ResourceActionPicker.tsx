import { useEffect, useState } from "react";
import { AutoComplete, Form, Input } from "antd";
import { authzApi } from "@/api/authz";
import type { PermissionDefinitionResponse } from "@/types/api";

interface Props {
  appID: string;
  value?: { resource?: string; action?: string };
  onChange?: (val: { resource: string; action: string }) => void;
}

export function ResourceActionPicker({ appID, value, onChange }: Props) {
  const [defs, setDefs] = useState<PermissionDefinitionResponse[]>([]);

  useEffect(() => {
    if (!appID) return;
    authzApi
      .listPermissionDefinitions(appID)
      .then(setDefs)
      .catch(() => setDefs([]));
  }, [appID]);

  const resources = Array.from(new Set(defs.map((d) => d.resource))).map((r) => ({ value: r }));
  const actions = Array.from(
    new Set(
      defs
        .filter((d) => !value?.resource || d.resource === value.resource)
        .map((d) => d.action),
    ),
  ).map((a) => ({ value: a }));

  return (
    <Input.Group compact>
      <Form.Item noStyle>
        <AutoComplete
          style={{ width: "50%" }}
          placeholder="资源 (resource)"
          options={resources}
          value={value?.resource}
          onChange={(v) =>
            onChange?.({ resource: v ?? "", action: value?.action ?? "" })
          }
          filterOption
        />
      </Form.Item>
      <Form.Item noStyle>
        <AutoComplete
          style={{ width: "50%" }}
          placeholder="动作 (action)"
          options={actions}
          value={value?.action}
          onChange={(v) =>
            onChange?.({ resource: value?.resource ?? "", action: v ?? "" })
          }
          filterOption
        />
      </Form.Item>
    </Input.Group>
  );
}
