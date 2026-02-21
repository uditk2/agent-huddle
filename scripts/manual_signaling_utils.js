import process from "node:process";

export const DEFAULT_ICE_SERVERS_JSON = JSON.stringify([
  {
    urls: [
      "stun:stun.l.google.com:19302",
      "stun:stun1.l.google.com:19302",
      "stun:stun2.l.google.com:19302",
    ],
  },
]);

export function parseCliArgs(argv, flagsWithValues) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--help" || token === "-h") {
      out.help = true;
      continue;
    }
    if (flagsWithValues.has(token)) {
      const key = flagsWithValues.get(token);
      out[key] = argv[i + 1];
      i += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${token}`);
  }
  return out;
}

export function parseIceServers(raw) {
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      throw new Error("ICE servers must be an array");
    }
    return parsed;
  } catch (error) {
    throw new Error(`Invalid ICE server JSON: ${error.message}`);
  }
}

export function encodeBlob(payload) {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

export function decodeBlob(blob, label = "blob") {
  const text = Buffer.from(blob.trim(), "base64url").toString("utf8");
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`Invalid ${label} JSON: ${error.message}`);
  }
}

export function readAllStdin() {
  return new Promise((resolve, reject) => {
    let text = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      text += chunk;
    });
    process.stdin.on("end", () => resolve(text.trim()));
    process.stdin.on("error", reject);
  });
}

export async function postJson(url, payload, timeoutMs = 20000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort();
  }, timeoutMs);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    const body = await response.json().catch(() => ({}));
    return { status: response.status, ok: response.ok, body };
  } finally {
    clearTimeout(timeout);
  }
}
