import { useState } from "react";
import { Button } from "antd";

interface Props {
  data: unknown;
  title?: string;
  collapsedByDefault?: boolean;
}

export function JsonPreview({ data, title = "原始响应", collapsedByDefault = true }: Props) {
  const [collapsed, setCollapsed] = useState(collapsedByDefault);
  const text = JSON.stringify(data, null, 2);
  return (
    <div>
      <Button type="link" size="small" onClick={() => setCollapsed((v) => !v)}>
        {collapsed ? `展开 ${title}` : `折叠 ${title}`}
      </Button>
      {!collapsed && (
        <pre
          style={{
            background: "#fafafa",
            border: "1px solid #f0f0f0",
            borderRadius: 4,
            padding: 12,
            fontSize: 12,
            overflowX: "auto",
            margin: 0,
          }}
        >
          {text}
        </pre>
      )}
    </div>
  );
}
