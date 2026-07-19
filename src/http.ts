import {
  MAX_RESPONSE_BYTES,
  NODEROOMS_ORIGIN,
  NodeRoomsError,
  REQUEST_TIMEOUT_MS,
} from "./contracts.js";

type JsonRecord = Record<string, unknown>;

function assertPinnedUrl(rawUrl: string): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new NodeRoomsError("INVALID_ENDPOINT", "NodeRooms returned an invalid endpoint.");
  }
  if (url.origin !== NODEROOMS_ORIGIN || url.protocol !== "https:") {
    throw new NodeRoomsError("ORIGIN_MISMATCH", "The request was stopped because the endpoint is not the official NodeRooms HTTPS origin.");
  }
  return url;
}

export function pinnedNodeRoomsUrl(rawUrl: string): string {
  return assertPinnedUrl(rawUrl).toString();
}

async function readBoundedBody(response: Response): Promise<string> {
  if (!response.body) {
    return "";
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let size = 0;
  let output = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    size += value.byteLength;
    if (size > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new NodeRoomsError("RESPONSE_TOO_LARGE", "The NodeRooms response exceeded the safe size limit.");
    }
    output += decoder.decode(value, { stream: true });
  }
  output += decoder.decode();
  return output;
}

export async function requestJson(
  rawUrl: string,
  init: RequestInit = {},
): Promise<JsonRecord> {
  const url = assertPinnedUrl(rawUrl);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    headers.set("User-Agent", "NodeRooms-OpenClaw-Plugin/1.1.0");
    if (init.body !== undefined) {
      headers.set("Content-Type", "application/json");
    }
    const response = await fetch(url, {
      ...init,
      headers,
      redirect: "manual",
      credentials: "omit",
      signal: controller.signal,
    });
    if (response.status >= 300 && response.status < 400) {
      throw new NodeRoomsError("REDIRECT_REJECTED", "NodeRooms redirected the request; the plugin stopped instead of following it.", response.status);
    }
    const body = await readBoundedBody(response);
    if (!response.ok) {
      throw new NodeRoomsError(
        `HTTP_${response.status}`,
        `NodeRooms rejected the request with HTTP ${response.status}. Remote error text was not returned to the Agent.`,
        response.status,
      );
    }
    const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
    if (!contentType.includes("application/json")) {
      throw new NodeRoomsError("NON_JSON_RESPONSE", "NodeRooms returned a non-JSON response.");
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      throw new NodeRoomsError("INVALID_JSON", "NodeRooms returned invalid JSON.");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new NodeRoomsError("INVALID_RESPONSE_SHAPE", "NodeRooms returned an unexpected response shape.");
    }
    return parsed as JsonRecord;
  } catch (error) {
    if (error instanceof NodeRoomsError) {
      throw error;
    }
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new NodeRoomsError("REQUEST_TIMEOUT", "The NodeRooms request timed out safely.");
    }
    throw new NodeRoomsError("NETWORK_ERROR", "The NodeRooms request could not be completed.");
  } finally {
    clearTimeout(timeout);
  }
}

export function jsonBody(value: JsonRecord): string {
  return JSON.stringify(value);
}

export function pick(record: JsonRecord, keys: readonly string[]): JsonRecord {
  const result: JsonRecord = {};
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(record, key)) {
      result[key] = record[key];
    }
  }
  return result;
}
