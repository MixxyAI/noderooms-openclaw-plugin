#!/usr/bin/env node

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
    access,
    mkdir,
    mkdtemp,
    readFile,
    rm,
    writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const CONTRACT_VERSION =
    "noderooms-phase3c-isolated-shadow-runtime-e2e-v1";
const EXPECTED_OPENCLAW_VERSION = "2026.7.1-2";
const EXPECTED_PLUGIN_VERSION = "1.3.0-beta.2-dev.1";
const EXPECTED_NODEROOMS_TOOL_COUNT = 14;
const EXPECTED_NODEROOMS_HOOK_COUNT = 5;
const BOARD_ID = "noderooms-workdesk";

function parseArguments(argv) {
    const values = new Map();
    for (let index = 0; index < argv.length; index += 1) {
        const token = argv[index];
        if (!token.startsWith("--")) {
            throw new Error(`Unexpected argument: ${token}`);
        }
        const value = argv[index + 1];
        if (!value || value.startsWith("--")) {
            throw new Error(`Missing value for ${token}`);
        }
        values.set(token.slice(2), value);
        index += 1;
    }
    return {
        evidencePath: values.has("evidence")
            ? path.resolve(values.get("evidence"))
            : null,
        pluginRoot: values.has("plugin-root")
            ? path.resolve(values.get("plugin-root"))
            : path.resolve(
                path.dirname(fileURLToPath(import.meta.url)),
                "..",
            ),
    };
}

async function exists(target) {
    try {
        await access(target);
        return true;
    }
    catch {
        return false;
    }
}

async function optionalFileHash(target) {
    if (!await exists(target)) {
        return null;
    }
    return createHash("sha256")
        .update(await readFile(target))
        .digest("hex");
}

function childEnvironment(stateDir, configPath, workspaceDir) {
    return {
        ...process.env,
        NO_COLOR: "1",
        OPENCLAW_CONFIG_PATH: configPath,
        OPENCLAW_STATE_DIR: stateDir,
        OPENCLAW_WORKSPACE_DIR: workspaceDir,
    };
}

function runCommand({
    args,
    cwd,
    env,
    label,
    parseJson = false,
}) {
    const result = spawnSync(process.execPath, args, {
        cwd,
        env,
        encoding: "utf8",
        maxBuffer: 16 * 1024 * 1024,
        windowsHide: true,
    });
    if (result.error) {
        throw new Error(`${label} failed to start: ${result.error.message}`);
    }
    if (result.status !== 0) {
        throw new Error([
            `${label} exited with ${result.status}.`,
            result.stdout?.trim(),
            result.stderr?.trim(),
        ].filter(Boolean).join("\n"));
    }
    const stdout = result.stdout.trim();
    if (!parseJson) {
        return {
            stdout,
            stderr: result.stderr.trim(),
        };
    }
    try {
        return JSON.parse(stdout);
    }
    catch {
        throw new Error(`${label} did not return one JSON document.`);
    }
}

function openClawCommand(context, args, label, parseJson = false) {
    return runCommand({
        args: [context.openClawCli, ...args],
        cwd: context.pluginRoot,
        env: context.env,
        label,
        parseJson,
    });
}

function workerCommand(context, phase, issuedAt, deadlineAt) {
    return runCommand({
        args: [
            context.workerPath,
            "--phase",
            phase,
            "--plugin-root",
            context.pluginRoot,
            "--issued-at",
            issuedAt,
            "--deadline-at",
            deadlineAt,
        ],
        cwd: context.pluginRoot,
        env: context.env,
        label: `Phase 3C worker ${phase}`,
        parseJson: true,
    });
}

async function createScenarioContext(pluginRoot, root, name) {
    const scenarioRoot = path.join(root, name);
    const stateDir = path.join(scenarioRoot, "state");
    const workspaceDir = path.join(scenarioRoot, "workspace");
    const configPath = path.join(stateDir, "openclaw.json");
    await Promise.all([
        mkdir(stateDir, { recursive: true }),
        mkdir(workspaceDir, { recursive: true }),
    ]);
    const openClawCli = path.join(
        pluginRoot,
        "node_modules",
        "openclaw",
        "openclaw.mjs",
    );
    const workerPath = path.join(
        pluginRoot,
        "scripts",
        "isolated-shadow-runtime-worker.mjs",
    );
    const context = {
        configPath,
        env: childEnvironment(stateDir, configPath, workspaceDir),
        openClawCli,
        pluginRoot,
        scenarioRoot,
        stateDir,
        workerPath,
        workspaceDir,
    };

    openClawCommand(
        context,
        ["plugins", "install", "--link", pluginRoot],
        `${name}: linked plugin install`,
    );
    openClawCommand(
        context,
        ["plugins", "enable", "workboard"],
        `${name}: enable Workboard`,
    );
    openClawCommand(
        context,
        [
            "config",
            "set",
            "agents.defaults.workspace",
            JSON.stringify(workspaceDir),
            "--strict-json",
        ],
        `${name}: isolate workspace`,
    );
    openClawCommand(
        context,
        [
            "config",
            "set",
            "plugins.entries.noderooms.config",
            JSON.stringify({
                trustLayer: { mode: "off" },
                workRuntime: {
                    mode: "shadow",
                    boardId: BOARD_ID,
                    maxEntries: 16,
                },
            }),
            "--strict-json",
        ],
        `${name}: configure shadow runtime`,
    );
    return context;
}

function inspectRuntime(context, pluginId) {
    return openClawCommand(
        context,
        ["plugins", "inspect", pluginId, "--runtime", "--json"],
        `${pluginId}: loader-backed runtime inspect`,
        true,
    );
}

function listTaskFlows(context) {
    return openClawCommand(
        context,
        ["tasks", "flow", "list", "--json"],
        "Task Flow list",
        true,
    );
}

function listWorkboardCards(context) {
    return openClawCommand(
        context,
        [
            "workboard",
            "list",
            "--board",
            BOARD_ID,
            "--include-archived",
            "--json",
        ],
        "Workboard list",
        true,
    );
}

function validateNodeRoomsInspect(inspect, workspaceDir) {
    const plugin = inspect.plugin;
    assert.equal(inspect.workspaceDir, workspaceDir);
    assert.equal(plugin.id, "noderooms");
    assert.equal(plugin.version, EXPECTED_PLUGIN_VERSION);
    assert.equal(plugin.status, "loaded");
    assert.equal(plugin.imported, true);
    assert.equal(inspect.install.source, "path");
    assert.equal(plugin.toolNames.length, EXPECTED_NODEROOMS_TOOL_COUNT);
    assert.equal(plugin.hookCount, EXPECTED_NODEROOMS_HOOK_COUNT);
    assert.ok(plugin.toolNames.includes("noderooms_prepare_work_binding"));
    assert.ok(inspect.typedHooks.some((entry) =>
        entry.name === "before_tool_call" && entry.priority === -1_000));
    assert.ok(inspect.typedHooks.some((entry) =>
        entry.name === "after_tool_call" && entry.priority === 80));
}

function validateWorkboardInspect(inspect, workspaceDir) {
    const plugin = inspect.plugin;
    assert.equal(inspect.workspaceDir, workspaceDir);
    assert.equal(plugin.id, "workboard");
    assert.equal(plugin.status, "loaded");
    assert.ok(plugin.toolNames.includes("workboard_create"));
    assert.ok(plugin.toolNames.includes("workboard_list"));
    assert.ok(plugin.toolNames.includes("workboard_read"));
    assert.ok(plugin.toolNames.includes("workboard_claim"));
    assert.ok(plugin.toolNames.includes("workboard_dispatch"));
}

function validatePrimaryCliState(flows, cards) {
    assert.equal(flows.count, 1);
    assert.equal(flows.flows.length, 1);
    assert.equal(flows.flows[0].syncMode, "managed");
    assert.equal(flows.flows[0].status, "waiting");
    assert.equal(flows.flows[0].controllerId,
        "noderooms/workdesk-shadow-v1");
    assert.equal(flows.flows[0].tasks.length, 0);
    assert.equal(flows.flows[0].taskSummary.total, 0);
    assert.equal(cards.cards.length, 1);
    assert.equal(cards.cards[0].status, "review");
    assert.equal(cards.cards[0].metadata?.claim, undefined);
    assert.equal(cards.cards[0].metadata.automation.boardId, BOARD_ID);
}

function totalCounter(records, key) {
    return records.reduce(
        (sum, record) => sum + Number(record?.counters?.[key] ?? 0),
        0,
    );
}

export async function runIsolatedShadowRuntimeE2E(options = {}) {
    const pluginRoot = path.resolve(options.pluginRoot ?? ".");
    const evidencePath = options.evidencePath
        ? path.resolve(options.evidencePath)
        : null;
    const packageJson = JSON.parse(await readFile(
        path.join(pluginRoot, "package.json"),
        "utf8",
    ));
    const openClawPackage = JSON.parse(await readFile(
        path.join(pluginRoot, "node_modules", "openclaw", "package.json"),
        "utf8",
    ));
    assert.equal(packageJson.version, EXPECTED_PLUGIN_VERSION);
    assert.equal(openClawPackage.version, EXPECTED_OPENCLAW_VERSION);

    const root = await mkdtemp(
        path.join(os.tmpdir(), "noderooms-phase3c-e2e-"),
    );
    const defaultConfigPath = path.join(
        os.homedir(),
        ".openclaw",
        "openclaw.json",
    );
    const defaultConfigBefore = await optionalFileHash(defaultConfigPath);
    const issuedAt = new Date().toISOString();
    const deadlineAt = new Date(Date.now() + 24 * 60 * 60 * 1_000)
        .toISOString();
    let summary;
    try {
        const primary = await createScenarioContext(
            pluginRoot,
            root,
            "primary",
        );
        const noderoomsInspect = inspectRuntime(primary, "noderooms");
        const workboardInspect = inspectRuntime(primary, "workboard");
        validateNodeRoomsInspect(noderoomsInspect, primary.workspaceDir);
        validateWorkboardInspect(workboardInspect, primary.workspaceDir);

        const primaryInitialFlows = listTaskFlows(primary);
        const primaryInitialCards = listWorkboardCards(primary);
        assert.equal(primaryInitialFlows.count, 0);
        assert.equal(primaryInitialCards.cards.length, 0);

        const primaryCreate = workerCommand(
            primary,
            "create",
            issuedAt,
            deadlineAt,
        );
        const primaryAfterCreateFlows = listTaskFlows(primary);
        const primaryAfterCreateCards = listWorkboardCards(primary);
        validatePrimaryCliState(
            primaryAfterCreateFlows,
            primaryAfterCreateCards,
        );

        const primaryVerify = workerCommand(
            primary,
            "verify",
            issuedAt,
            deadlineAt,
        );
        const primaryFinalFlows = listTaskFlows(primary);
        const primaryFinalCards = listWorkboardCards(primary);
        validatePrimaryCliState(primaryFinalFlows, primaryFinalCards);
        assert.equal(
            primaryFinalFlows.flows[0].flowId,
            primaryAfterCreateFlows.flows[0].flowId,
        );
        assert.equal(
            primaryFinalCards.cards[0].id,
            primaryAfterCreateCards.cards[0].id,
        );

        const cancellation = await createScenarioContext(
            pluginRoot,
            root,
            "cancellation",
        );
        validateNodeRoomsInspect(
            inspectRuntime(cancellation, "noderooms"),
            cancellation.workspaceDir,
        );
        validateWorkboardInspect(
            inspectRuntime(cancellation, "workboard"),
            cancellation.workspaceDir,
        );
        const cancellationCreate = workerCommand(
            cancellation,
            "create",
            issuedAt,
            deadlineAt,
        );
        const cancellationProof = workerCommand(
            cancellation,
            "cancel",
            issuedAt,
            deadlineAt,
        );
        const cancellationFlows = listTaskFlows(cancellation);
        const cancellationCards = listWorkboardCards(cancellation);
        assert.equal(cancellationFlows.count, 1);
        assert.equal(cancellationFlows.flows[0].tasks.length, 0);
        assert.ok(Number.isFinite(
            cancellationFlows.flows[0].cancelRequestedAt,
        ));
        assert.equal(cancellationCards.cards.length, 1);
        assert.equal(cancellationCards.cards[0].status, "review");
        assert.equal(
            cancellationCards.cards[0].metadata?.claim,
            undefined,
        );

        const phaseRecords = [
            primaryCreate,
            primaryVerify,
            cancellationCreate,
            cancellationProof,
        ];
        assert.equal(totalCounter(phaseRecords, "runTask"), 0);
        assert.equal(totalCounter(phaseRecords, "resume"), 0);
        assert.equal(totalCounter(phaseRecords, "workboard_claim"), 0);
        assert.equal(totalCounter(phaseRecords, "workboard_dispatch"), 0);
        assert.equal(totalCounter(phaseRecords, "connector_calls"), 0);
        assert.equal(
            totalCounter(phaseRecords, "external_network_attempts"),
            0,
        );
        assert.equal(totalCounter(phaseRecords, "external_writes"), 0);

        summary = {
            ok: true,
            contract_version: CONTRACT_VERSION,
            host: {
                node_version: process.version,
                openclaw_version: openClawPackage.version,
                plugin_version: packageJson.version,
                exact_host_version_pinned:
                    openClawPackage.version === EXPECTED_OPENCLAW_VERSION,
            },
            isolation: {
                exact_state_env_used: true,
                exact_config_env_used: true,
                isolated_workspace_configured: true,
                default_config_unchanged: false,
                gateway_started: false,
                gateway_restart_attempted: false,
            },
            loader: {
                noderooms_status: noderoomsInspect.plugin.status,
                noderooms_tool_count:
                    noderoomsInspect.plugin.toolNames.length,
                noderooms_hook_count: noderoomsInspect.plugin.hookCount,
                workboard_status: workboardInspect.plugin.status,
                linked_source_install: true,
            },
            primary: {
                create: primaryCreate,
                restart_verify: primaryVerify,
                final_task_flow: {
                    count: primaryFinalFlows.count,
                    flow_id: primaryFinalFlows.flows[0].flowId,
                    sync_mode: primaryFinalFlows.flows[0].syncMode,
                    status: primaryFinalFlows.flows[0].status,
                    revision: primaryFinalFlows.flows[0].revision,
                    child_task_count:
                        primaryFinalFlows.flows[0].tasks.length,
                },
                final_workboard: {
                    count: primaryFinalCards.cards.length,
                    card_id: primaryFinalCards.cards[0].id,
                    status: primaryFinalCards.cards[0].status,
                    claim_created: false,
                    dispatch_attempted: false,
                },
            },
            cancellation: {
                create: cancellationCreate,
                proof: cancellationProof,
                flow_status: cancellationFlows.flows[0].status,
                cancel_requested: Number.isFinite(
                    cancellationFlows.flows[0].cancelRequestedAt,
                ),
                workboard_status:
                    cancellationCards.cards[0].status,
            },
            safety: {
                task_run_started: false,
                task_flow_resume_attempted: false,
                workboard_claim_attempted: false,
                workboard_dispatch_attempted: false,
                connector_call_attempted: false,
                external_network_attempted: false,
                external_write_attempted: false,
                automatic_retry_attempted: false,
                raw_work_content_in_evidence: false,
                provider_credentials_in_evidence: false,
                claim_token_in_evidence: false,
                production_modified: false,
            },
            rollback: {
                isolated_state_removal_attempted: true,
                temp_root_removed: false,
            },
        };
    }
    finally {
        await rm(root, { recursive: true, force: true });
    }

    summary.rollback.temp_root_removed = !await exists(root);
    const defaultConfigAfter = await optionalFileHash(defaultConfigPath);
    summary.isolation.default_config_unchanged =
        defaultConfigAfter === defaultConfigBefore;
    assert.equal(summary.rollback.temp_root_removed, true);
    assert.equal(summary.isolation.default_config_unchanged, true);

    const serializedSummary = JSON.stringify(summary);
    for (const forbidden of [
        "Prepare one GitHub Draft pull request",
        "example-org/example-repo",
        "session-noderooms-phase3c-owner",
        "owner-noderooms-phase3c",
        "NRP-000042-AGENT",
        "NRPB-CCCCCCCCCCCCCCCCCCCCCCCC",
    ]) {
        assert.equal(serializedSummary.includes(forbidden), false);
    }

    if (evidencePath) {
        await mkdir(path.dirname(evidencePath), { recursive: true });
        await writeFile(
            evidencePath,
            `${JSON.stringify(summary, null, 2)}\n`,
            { encoding: "utf8", mode: 0o600 },
        );
    }
    return summary;
}

const invokedPath = process.argv[1]
    ? path.resolve(process.argv[1])
    : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
    const options = parseArguments(process.argv.slice(2));
    const result = await runIsolatedShadowRuntimeE2E(options);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
