import { ReactElement, cloneElement, useEffect, useMemo, useState } from "react";
import { Tooltip } from "antd";
import { authzApi } from "@/api/authz";
import { useAuthStore } from "@/stores/auth";

interface Props {
  resource: string;
  action: string;
  children: ReactElement;
  fallbackMessage?: string;
}

const cache = new Map<string, { allowed: boolean; expiresAt: number }>();
const TTL_MS = 30_000;

export function PermissionGate({ resource, action, children, fallbackMessage }: Props) {
  const claims = useAuthStore((s) => s.claims);
  const [state, setState] = useState<{ allowed: boolean; loading: boolean }>(
    () => ({ allowed: false, loading: true }),
  );

  const cacheKey = useMemo(
    () => `${claims?.user_id ?? ""}|${claims?.app_id ?? ""}|${resource}|${action}`,
    [claims?.user_id, claims?.app_id, resource, action],
  );

  useEffect(() => {
    if (!claims?.user_id || !claims?.app_id) {
      setState({ allowed: false, loading: false });
      return;
    }
    const cached = cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      setState({ allowed: cached.allowed, loading: false });
      return;
    }
    let cancelled = false;
    setState((s) => ({ ...s, loading: true }));
    authzApi
      .checkPermission({
        user_id: claims.user_id,
        app_id: claims.app_id,
        resource,
        action,
      })
      .then((res) => {
        if (cancelled) return;
        cache.set(cacheKey, {
          allowed: res.allowed,
          expiresAt: Date.now() + TTL_MS,
        });
        setState({ allowed: res.allowed, loading: false });
      })
      .catch(() => {
        if (cancelled) return;
        setState({ allowed: false, loading: false });
      });
    return () => {
      cancelled = true;
    };
  }, [cacheKey, claims?.user_id, claims?.app_id, resource, action]);

  if (state.loading) {
    return cloneElement(children, { disabled: true });
  }
  if (state.allowed) {
    return children;
  }
  return (
    <Tooltip title={fallbackMessage ?? `缺少权限 ${resource}:${action}`}>
      <span>{cloneElement(children, { disabled: true })}</span>
    </Tooltip>
  );
}
