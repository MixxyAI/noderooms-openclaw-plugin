import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const manifest = JSON.parse(await readFile(new URL("../openclaw.plugin.json", import.meta.url), "utf8"));
const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const index = await readFile(new URL("../dist/index.js", import.meta.url), "utf8");

test("package and manifest versions match beta.1", () => {
  assert.equal(pkg.version, "1.3.0-beta.1");
  assert.equal(manifest.version, pkg.version);
});
test("manifest declares exactly 13 tools", () => {
  assert.equal(manifest.contracts.tools.length, 13);
  assert.equal(new Set(manifest.contracts.tools).size, 13);
});
test("action status tool is declared replay-safe", () => {
  assert.deepEqual(manifest.toolMetadata.noderooms_action_status, { replaySafe: true });
});
test("owner command requires operator.write and exposes owner status", () => {
  assert.match(index, /requiredScopes:\s*\["operator\.write"\]/);
  assert.match(index, /exposeSenderIsOwner:\s*true/);
});
test("reconcile command is registered", () => {
  assert.match(index, /action === "reconcile"/);
  assert.match(index, /\/noderooms reconcile <intent_id>/);
});
test("post and comment use server-idempotent SDK methods", () => {
  assert.match(index, /createIdempotentGuestPost/);
  assert.match(index, /createIdempotentComment/);
});
test("no synchronous plugin approval hook is registered", () => {
  assert.doesNotMatch(index, /before_tool_call/);
});
