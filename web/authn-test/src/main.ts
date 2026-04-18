import { callAPI, type APIResult } from "./api";
import { val, setVal, toBase64URL, fromBase64URL, buildSiweMessage } from "./utils";
import "./style.css";

declare global {
  interface Window {
    ethereum?: {
      request(args: { method: string; params?: unknown[] }): Promise<unknown>;
    };
  }
}

// --- UI helpers ---

const output = document.getElementById("output")!;

function setOutput(title: string, data: unknown) {
  output.textContent = title + "\n\n" + JSON.stringify(data, null, 2);
}

function setTokens(data: Record<string, unknown>) {
  if (data?.access_token) setVal("accessToken", data.access_token as string);
  if (data?.refresh_token) setVal("refreshToken", data.refresh_token as string);
}

// --- Password ---

document.getElementById("btnRegister")!.addEventListener("click", async () => {
  const result = await callAPI("/api/v1/auth/register", "POST", {
    app_id: val("appId"),
    provider: val("provider"),
    email: val("email"),
    password: val("password"),
    tenant_id: val("tenantId"),
  });
  setTokens(result.data);
  setOutput("POST /api/v1/auth/register", result);
});

document.getElementById("btnLogin")!.addEventListener("click", async () => {
  const result = await callAPI("/api/v1/auth/login", "POST", {
    app_id: val("appId"),
    provider: val("provider"),
    params: { email: val("email"), password: val("password") },
  });
  setTokens(result.data);
  setOutput("POST /api/v1/auth/login", result);
});

document.getElementById("btnRefresh")!.addEventListener("click", async () => {
  const result = await callAPI("/api/v1/auth/token/refresh", "POST", {
    refresh_token: val("refreshToken"),
  });
  setTokens(result.data);
  setOutput("POST /api/v1/auth/token/refresh", result);
});

document.getElementById("btnSessions")!.addEventListener("click", async () => {
  const result = await callAPI("/api/v1/auth/sessions", "GET", undefined, val("accessToken"));
  setOutput("GET /api/v1/auth/sessions", result);
});

document.getElementById("btnLogout")!.addEventListener("click", async () => {
  const result = await callAPI("/api/v1/auth/logout", "POST", {}, val("accessToken"));
  setOutput("POST /api/v1/auth/logout", result);
});

// --- SIWE helpers ---

async function ensureWalletAddress(): Promise<string> {
  if (!window.ethereum) throw new Error("window.ethereum 不存在，请安装钱包插件");
  let address = val("siweAddress");
  if (!address) {
    const accounts = (await window.ethereum.request({ method: "eth_requestAccounts" })) as string[];
    address = accounts?.[0] ?? "";
    setVal("siweAddress", address);
  }
  return address;
}

async function fetchSiweNonce(): Promise<string> {
  const challenge = await callAPI("/api/v1/auth/challenge", "POST", {
    app_id: val("appId"),
    provider: "siwe",
  });
  if (!challenge.ok) {
    setOutput("POST /api/v1/auth/challenge (siwe)", challenge);
    throw new Error("failed to get siwe challenge");
  }
  const nonce = (challenge.data.data as Record<string, string>).nonce;
  setVal("siweNonce", nonce);
  return nonce;
}

async function signSiweMessage(): Promise<{ message: string; signature: string }> {
  const address = await ensureWalletAddress();
  const nonce = await fetchSiweNonce();
  const message = buildSiweMessage(address, nonce);
  const signature = (await window.ethereum!.request({
    method: "personal_sign",
    params: [message, address],
  })) as string;
  return { message, signature };
}

// --- SIWE ---

document.getElementById("btnSiweConnect")!.addEventListener("click", async () => {
  try {
    const address = await ensureWalletAddress();
    setOutput("SIWE connect", { ok: true, account: address });
  } catch (err) {
    setOutput("SIWE connect", { ok: false, error: String(err) });
  }
});

document.getElementById("btnSiweChallenge")!.addEventListener("click", async () => {
  const result = await callAPI("/api/v1/auth/challenge", "POST", {
    app_id: val("appId"),
    provider: "siwe",
  });
  if (result.ok && result.data.data) {
    setVal("siweNonce", (result.data.data as Record<string, string>).nonce);
  }
  setOutput("POST /api/v1/auth/challenge (siwe)", result);
});

document.getElementById("btnSiweLogin")!.addEventListener("click", async () => {
  try {
    const { message, signature } = await signSiweMessage();
    const result = await callAPI("/api/v1/auth/login", "POST", {
      app_id: val("appId"),
      provider: "siwe",
      params: { message, signature },
    });
    setTokens(result.data);
    setOutput("POST /api/v1/auth/login (siwe)", result);
  } catch (err) {
    setOutput("SIWE login", { ok: false, error: String(err) });
  }
});

document.getElementById("btnSiweBind")!.addEventListener("click", async () => {
  const token = val("accessToken");
  if (!token) {
    setOutput("SIWE bind", { ok: false, error: "请先登录获取 access_token" });
    return;
  }
  try {
    const { message, signature } = await signSiweMessage();
    const result = await callAPI(
      "/api/v1/auth/bind",
      "POST",
      { provider: "siwe", params: { message, signature } },
      token,
    );
    setOutput("POST /api/v1/auth/bind (siwe)", result);
  } catch (err) {
    setOutput("SIWE bind", { ok: false, error: String(err) });
  }
});

// --- WebAuthn helpers ---

async function fetchWebAuthnChallenge(): Promise<Record<string, unknown>> {
  const result = await callAPI("/api/v1/auth/challenge", "POST", {
    app_id: val("appId"),
    provider: "webauthn",
  });
  if (!result.ok || !result.data.challenge_id) {
    setOutput("POST /api/v1/auth/challenge (webauthn)", result);
    throw new Error("failed to get webauthn challenge");
  }
  setVal("webauthnChallengeId", result.data.challenge_id as string);
  return result.data;
}

// --- WebAuthn ---

document.getElementById("btnWebAuthnChallenge")!.addEventListener("click", async () => {
  try {
    const challenge = await fetchWebAuthnChallenge();
    setOutput("POST /api/v1/auth/challenge (webauthn)", {
      status: 200,
      ok: true,
      data: challenge,
    });
  } catch (err) {
    setOutput("WebAuthn challenge", { ok: false, error: String(err) });
  }
});

async function webAuthnRegistrationFallback(): Promise<APIResult> {
  const freshChallenge = await fetchWebAuthnChallenge();
  const freshData = freshChallenge.data as Record<string, unknown>;
  const created = (await navigator.credentials.create({
    publicKey: {
      challenge: fromBase64URL(freshData.challenge as string) as BufferSource,
      rp: { name: "OpenIAM", id: (freshData.rpId as string) || "localhost" },
      user: {
        id: new TextEncoder().encode(`passkey-${Date.now()}`),
        name: "passkey-user@openiam.local",
        displayName: "Passkey User",
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      timeout: 300000,
      authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
    },
  })) as PublicKeyCredential;
  const createdResp = created.response as AuthenticatorAttestationResponse;
  return await callAPI("/api/v1/auth/login", "POST", {
    app_id: val("appId"),
    provider: "webauthn",
    params: {
      challenge_id: freshChallenge.challenge_id as string,
      raw_id: toBase64URL(created.rawId),
      public_key: toBase64URL(createdResp.getPublicKey()!),
      attestation_object: toBase64URL(createdResp.attestationObject),
      client_data_json: toBase64URL(createdResp.clientDataJSON),
    },
  });
}

document.getElementById("btnWebAuthnLogin")!.addEventListener("click", async () => {
  try {
    if (!window.PublicKeyCredential) {
      setOutput("WebAuthn login", { ok: false, error: "当前浏览器不支持 WebAuthn" });
      return;
    }
    const result = await webAuthnRegistrationFallback();
    setTokens(result.data);
    setOutput("POST /api/v1/auth/login (webauthn)", result);
  } catch (err) {
    setOutput("WebAuthn login", { ok: false, error: String(err) });
  }
});

document.getElementById("btnWebAuthnBind")!.addEventListener("click", async () => {
  try {
    if (!window.PublicKeyCredential) {
      setOutput("WebAuthn bind", { ok: false, error: "当前浏览器不支持 WebAuthn" });
      return;
    }
    const token = val("accessToken");
    if (!token) {
      setOutput("WebAuthn bind", { ok: false, error: "请先登录获取 access_token" });
      return;
    }

    const ch = await callAPI("/api/v1/auth/challenge", "POST", {
      app_id: val("appId"),
      provider: "webauthn",
    });
    if (!ch.ok) {
      setOutput("POST /api/v1/auth/challenge (webauthn)", ch);
      return;
    }

    const challengeData = ch.data;
    const chalData = challengeData.data as Record<string, unknown>;

    const publicKeyOptions: PublicKeyCredentialCreationOptions = {
      challenge: fromBase64URL(chalData.challenge as string) as BufferSource,
      rp: { name: "OpenIAM", id: (chalData.rpId as string) || "localhost" },
      user: {
        id: new TextEncoder().encode(`bind-${Date.now()}`),
        name: "user@openiam",
        displayName: "OpenIAM User",
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      timeout: 300000,
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
    };

    const credential = (await navigator.credentials.create({
      publicKey: publicKeyOptions,
    })) as PublicKeyCredential;

    const attestationResponse = credential.response as AuthenticatorAttestationResponse;
    const payload = {
      challenge_id: challengeData.challenge_id as string,
      raw_id: toBase64URL(credential.rawId),
      public_key: toBase64URL(attestationResponse.getPublicKey()!),
      attestation_object: toBase64URL(attestationResponse.attestationObject),
      client_data_json: toBase64URL(attestationResponse.clientDataJSON),
    };
    const result = await callAPI(
      "/api/v1/auth/bind",
      "POST",
      { provider: "webauthn", params: payload },
      token,
    );
    setOutput("POST /api/v1/auth/bind (webauthn)", result);
  } catch (err) {
    setOutput("WebAuthn bind", { ok: false, error: String(err) });
  }
});
