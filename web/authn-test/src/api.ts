export interface APIResult {
  status: number;
  ok: boolean;
  data: Record<string, unknown>;
}

export async function callAPI(
  path: string,
  method: string,
  body?: unknown,
  accessToken?: string,
): Promise<APIResult> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (accessToken) headers["Authorization"] = `Bearer ${accessToken}`;

  const resp = await fetch(path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await resp.text();
  let data: Record<string, unknown>;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }
  return { status: resp.status, ok: resp.ok, data };
}
