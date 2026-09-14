export const SESSION_COOKIE = "netqmon_session";

export type SessionPayload = {
  token: string;
  userId: string;
  username: string;
  expiresAt: number;
};

function signingKey() {
  const secret = process.env.NETQMON_SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error(
      "NETQMON_SESSION_SECRET must contain at least 32 characters",
    );
  }
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

function encode(value: Uint8Array | string) {
  const bytes =
    typeof value === "string" ? new TextEncoder().encode(value) : value;
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function decode(value: string) {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export async function sealSession(payload: SessionPayload) {
  const encoded = encode(JSON.stringify(payload));
  const signature = await crypto.subtle.sign(
    "HMAC",
    await signingKey(),
    new TextEncoder().encode(encoded),
  );
  return `${encoded}.${encode(new Uint8Array(signature))}`;
}

export async function openSession(
  value: string | undefined,
): Promise<SessionPayload | null> {
  if (!value) return null;
  const [encoded, signature, extra] = value.split(".");
  if (!encoded || !signature || extra) return null;
  try {
    const valid = await crypto.subtle.verify(
      "HMAC",
      await signingKey(),
      decode(signature),
      new TextEncoder().encode(encoded),
    );
    if (!valid) return null;
    const payload = JSON.parse(
      new TextDecoder().decode(decode(encoded)),
    ) as SessionPayload;
    if (
      typeof payload.token !== "string" ||
      typeof payload.userId !== "string" ||
      typeof payload.username !== "string" ||
      typeof payload.expiresAt !== "number" ||
      payload.expiresAt <= Date.now()
    ) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}
