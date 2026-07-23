import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const manifest = JSON.parse(await readFile(new URL("../openclaw.plugin.json", import.meta.url), "utf8"));
const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const index = await readFile(new URL("../dist/index.js", import.meta.url), "utf8");

test("package and manifest versions match trust alpha development version", () => {
    assert.equal(pkg.version, "1.3.0-beta.2-dev.1");
    assert.equal(manifest.version, pkg.version);
});

test("existing public tool contract remains exactly 13 tools", () => {
    assert.equal(manifest.contracts.tools.length, 13);
    assert.equal(new Set(manifest.contracts.tools).size, 13);
});

test("owner command still requires operator.write", () => {
    assert.match(index, /requiredScopes:\s*\["operator\.write"\]/);
    assert.match(index, /exposeSenderIsOwner:\s*true/);
});

test("trust hooks are registered with bounded timeouts", () => {
    assert.match(index, /"before_tool_call"/);
    assert.match(index, /"after_tool_call"/);
    assert.match(index, /priority:\s*70/);
    assert.match(index, /timeoutMs:\s*5_000/);
});

test("trust layer is disabled by default in the manifest", () => {
    assert.equal(manifest.configSchema.properties.trustLayer.properties.mode.default, "off");
});

test("NodeRooms public post and comment remain server-idempotent", () => {
    assert.match(index, /createIdempotentGuestPost/);
    assert.match(index, /createIdempotentComment/);
    assert.match(index, /action === "reconcile"/);
});
