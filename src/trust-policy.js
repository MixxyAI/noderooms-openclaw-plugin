const PUBLIC_MODES = new Set(["off", "observe"]);
const RISKS = new Set(["low", "medium", "high", "critical"]);
const APPROVALS = new Set(["none", "allow-once"]);
const TOOL_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;
const SCOPE_PATTERN = /^[a-z][a-z0-9._:-]{2,127}$/;

export const LIVE_ENFORCE_ALLOWED = false;

function normalizeRule(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        return undefined;
    }
    const toolName = typeof value.toolName === "string" ? value.toolName.trim() : "";
    const requiredScope = typeof value.requiredScope === "string" ? value.requiredScope.trim() : "";
    const risk = typeof value.risk === "string" ? value.risk.trim() : "medium";
    const approval = typeof value.approval === "string" ? value.approval.trim() : "none";
    if (!TOOL_PATTERN.test(toolName) || toolName.startsWith("noderooms_")) {
        return undefined;
    }
    if (!SCOPE_PATTERN.test(requiredScope) || !RISKS.has(risk) || !APPROVALS.has(approval)) {
        return undefined;
    }
    const effectiveApproval = risk === "high" || risk === "critical"
        ? "allow-once"
        : approval;
    return Object.freeze({
        toolName,
        requiredScope,
        risk,
        approval: effectiveApproval,
    });
}

export function normalizeTrustLayerConfig(pluginConfig) {
    const raw = pluginConfig?.trustLayer;
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
        return Object.freeze({
            mode: "off",
            rules: Object.freeze([]),
            ledgerMaxEntries: 256,
            liveEnforceAllowed: LIVE_ENFORCE_ALLOWED,
            enforceActivationBlocked: false,
        });
    }
    const enforceActivationBlocked = raw.mode === "enforce";
    const mode = PUBLIC_MODES.has(raw.mode) ? raw.mode : "off";
    const normalizedRules = [];
    const seen = new Set();
    if (Array.isArray(raw.rules)) {
        for (const candidate of raw.rules.slice(0, 64)) {
            const rule = normalizeRule(candidate);
            if (!rule || seen.has(rule.toolName)) {
                continue;
            }
            seen.add(rule.toolName);
            normalizedRules.push(rule);
        }
    }
    const ledgerMaxEntries = Number.isSafeInteger(raw.ledgerMaxEntries)
        ? Math.max(1, Math.min(1000, raw.ledgerMaxEntries))
        : 256;
    return Object.freeze({
        mode,
        rules: Object.freeze(normalizedRules),
        ledgerMaxEntries,
        liveEnforceAllowed: LIVE_ENFORCE_ALLOWED,
        enforceActivationBlocked,
    });
}

export function buildTrustRuleIndex(config) {
    return new Map(config.rules.map((rule) => [rule.toolName, rule]));
}

export function evaluateTrustDecision({ mode, rule, agentId, safeState }) {
    if (!rule || mode === "off") {
        return { decision: "not_governed" };
    }
    if (!agentId) {
        return { decision: mode === "observe" ? "would_block_missing_agent" : "block_missing_agent" };
    }
    if (safeState.run_lease_held_in_memory !== true) {
        return { decision: mode === "observe" ? "would_block_no_lease" : "block_no_lease" };
    }
    if (safeState.run_lease_bound_agent_id !== agentId) {
        return { decision: mode === "observe" ? "would_block_agent_mismatch" : "block_agent_mismatch" };
    }
    const scopes = Array.isArray(safeState.run_lease_scopes) ? safeState.run_lease_scopes : [];
    if (!scopes.includes(rule.requiredScope)) {
        return { decision: mode === "observe" ? "would_block_scope" : "block_scope" };
    }
    if (rule.approval === "allow-once") {
        return { decision: mode === "observe" ? "would_require_approval" : "require_approval" };
    }
    return { decision: mode === "observe" ? "would_allow" : "allow" };
}

export function isBlockingDecision(decision) {
    return typeof decision === "string" && decision.startsWith("block_");
}
