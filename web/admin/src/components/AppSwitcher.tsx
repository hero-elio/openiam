import { Button, Tooltip } from "antd";
import { SwapOutlined } from "@ant-design/icons";
import { useAuthStore } from "@/stores/auth";
import { useNavigate } from "react-router-dom";

export function AppSwitcher() {
  const claims = useAuthStore((s) => s.claims);
  const clear = useAuthStore((s) => s.clear);
  const navigate = useNavigate();

  if (!claims) return null;

  return (
    <Tooltip title="JWT 一次只能携带一个 app/tenant 上下文，切换需重新登录">
      <Button
        size="small"
        icon={<SwapOutlined />}
        onClick={() => {
          clear();
          navigate("/login", { replace: true });
        }}
      >
        切换
      </Button>
    </Tooltip>
  );
}
