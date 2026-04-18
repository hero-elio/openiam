import { getAddress } from "viem";

export function val(id: string): string {
  return (document.getElementById(id) as HTMLInputElement).value.trim();
}

export function setVal(id: string, value: string): void {
  (document.getElementById(id) as HTMLInputElement).value = value;
}

export function toBase64URL(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function fromBase64URL(value: string): Uint8Array {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "===".slice((b64.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function toChecksumAddress(address: string): string {
  return getAddress(address);
}

export function buildSiweMessage(address: string, nonce: string): string {
  const checksumAddr = toChecksumAddress(address);
  const domain = val("siweDomain");
  const uri = val("siweURI");
  const chainId = val("siweChainID") || "1";
  const statement = val("siweStatement") || "Sign in";
  const issuedAt = new Date().toISOString();

  return (
    `${domain} wants you to sign in with your Ethereum account:\n` +
    `${checksumAddr}\n\n` +
    `${statement}\n\n` +
    `URI: ${uri}\n` +
    `Version: 1\n` +
    `Chain ID: ${chainId}\n` +
    `Nonce: ${nonce}\n` +
    `Issued At: ${issuedAt}`
  );
}
