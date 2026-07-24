import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const manifest = JSON.parse(await readFile(new URL("../openclaw.plugin.json", import.meta.url), "utf8"));
const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const index = await readFile(new URL("../dist/index.js", import.meta.url), "utf8");
const workRuntime = await readFile(
    new URL("../dist/safe-work-runtime-binding.js", import.meta.url),
    "utf8",
);

test("package and manifest versions match trust alpha development version", () => {
    assert.equal(pkg.version, "1.3.0-beta.2-dev.1");
    assert.equal(manifest.version, pkg.version);
});

test("public tool contract adds only the optional shadow binding tool", () => {
    assert.equal(manifest.contracts.tools.length, 14);
    assert.equal(new Set(manifest.contracts.tools).size, 14);
    assert.equal(
        manifest.contracts.tools.at(-1),
        "noderooms_prepare_work_binding",
    );
    assert.deepEqual(
        manifest.toolMetadata.noderooms_prepare_work_binding,
        { optional: true, replaySafe: false },
    );
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

test("shadow Workboard guard runs after normal policy hooks and is fail-closed", () => {
    assert.match(index, /priority:\s*-1_000/);
    assert.match(index, /workRuntime\.beforeToolCall/);
    assert.match(index, /workRuntime\.afterToolCall/);
    assert.match(index, /workRuntime\.clearRuntimeCache/);
    assert.match(workRuntime, /WORK_RUNTIME_REPLAY_BLOCKED/);
    assert.match(workRuntime, /automatic retry is blocked/i);
});

test("trust layer is disabled by default in the manifest", () => {
    const mode = manifest.configSchema.properties.trustLayer.properties.mode;
    assert.equal(mode.default, "off");
    assert.deepEqual(mode.enum, ["off", "observe"]);
});

test("Phase 3 runtime binding is disabled by default and exposes shadow only", () => {
    const runtime = manifest.configSchema.properties.workRuntime.properties;
    assert.equal(runtime.mode.default, "off");
    assert.deepEqual(runtime.mode.enum, ["off", "shadow"]);
    assert.equal(runtime.boardId.default, "noderooms-workdesk");
    assert.doesNotMatch(workRuntime, /runtime\.gateway\.request/);
    assert.doesNotMatch(workRuntime, /openKeyedStore/);
    assert.doesNotMatch(workRuntime, /\.runTask\(/);
    assert.doesNotMatch(workRuntime, /\.resume\(/);
});

test("NodeRooms public post and comment remain server-idempotent", () => {
    assert.match(index, /createIdempotentGuestPost/);
    assert.match(index, /createIdempotentComment/);
    assert.match(index, /action === "reconcile"/);
});
