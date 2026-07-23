import { buildTrustRuleIndex, evaluateTrustDecision, isBlockingDecision } from "./trust-policy.js";

function bounded(value, maxLength) {
    return typeof value === "string" && value.trim()
        ? value.trim().slice(0, maxLength)
        : undefined;
}

function contextValue(ctx, primary, fallback) {
    return bounded(ctx?.[primary], 160) ?? bounded(ctx?.[fallback], 160);
}

function errorCategory(error) {
    if (!error) {
        return undefined;
    }
    if (typeof error === "string") {
        return "tool_error";
    }
    return bounded(error.name, 80) ?? bounded(error.code, 80) ?? "tool_error";
}

function approvalSeverity(risk) {
    if (risk === "critical") {
        return "critical";
    }
    if (risk === "high") {
        return "warning";
    }
    return "info";
}

export class NodeRoomsTrustMiddleware {
    constructor(options) {
        this.config = options.config;
        this.ruleIndex = buildTrustRuleIndex(this.config);
        this.safeState = options.safeState;
        this.ledger = options.ledger;
        this.ledgerHealthy = true;
    }

    async record(input) {
        try {
            await this.ledger.append(input);
        } catch {
            this.ledgerHealthy = false;
        }
    }

    async beforeToolCall(event, ctx = {}) {
        const rule = this.ruleIndex.get(event?.toolName);
        if (!rule || this.config.mode === "off" || event.toolName.startsWith("noderooms_")) {
            return undefined;
        }
        const agentId = contextValue(ctx, "agentId");
        const decision = evaluateTrustDecision({
            mode: this.config.mode,
            rule,
            agentId,
            safeState: this.safeState(),
        });
        await this.record({
            phase: "before",
            mode: this.config.mode,
            decision: decision.decision,
            toolName: event.toolName,
            params: event.params,
            requiredScope: rule.requiredScope,
            risk: rule.risk,
            approval: rule.approval,
            agentId,
            channel: contextValue(ctx, "channel", "messageProvider"),
            runId: contextValue(ctx, "runId"),
            toolCallId: bounded(event.toolCallId, 160),
        });
        if (this.config.mode === "observe") {
            return undefined;
        }
        if (isBlockingDecision(decision.decision)) {
            return {
                block: true,
                blockReason: "NodeRooms trust policy denied this tool call because no matching active Agent lease was available.",
            };
        }
        if (decision.decision === "require_approval") {
            return {
                requireApproval: {
                    title: `Approve ${event.toolName}`.slice(0, 80),
                    description: `Allow one ${event.toolName} call under NodeRooms scope ${rule.requiredScope}.`.slice(0, 256),
                    severity: approvalSeverity(rule.risk),
                    allowedDecisions: ["allow-once", "deny"],
                    timeoutMs: 120_000,
                    timeoutBehavior: "deny",
                    onResolution: async (resolution) => {
                        await this.record({
                            phase: "approval",
                            mode: this.config.mode,
                            decision: `approval_${resolution}`,
                            toolName: event.toolName,
                            requiredScope: rule.requiredScope,
                            risk: rule.risk,
                            approval: rule.approval,
                            agentId,
                            channel: contextValue(ctx, "channel", "messageProvider"),
                            runId: contextValue(ctx, "runId"),
                            toolCallId: bounded(event.toolCallId, 160),
                        });
                    },
                },
            };
        }
        return undefined;
    }

    async afterToolCall(event, ctx = {}) {
        const rule = this.ruleIndex.get(event?.toolName);
        if (!rule || this.config.mode === "off" || event.toolName.startsWith("noderooms_")) {
            return;
        }
        await this.record({
            phase: "after",
            mode: this.config.mode,
            decision: "observed_result",
            toolName: event.toolName,
            requiredScope: rule.requiredScope,
            risk: rule.risk,
            approval: rule.approval,
            agentId: contextValue(ctx, "agentId"),
            channel: contextValue(ctx, "channel", "messageProvider"),
            runId: contextValue(ctx, "runId"),
            toolCallId: bounded(event.toolCallId, 160),
            outcome: event.error ? "error" : "success",
            errorCategory: errorCategory(event.error),
            durationMs: event.durationMs,
        });
    }

    async status() {
        return {
            mode: this.config.mode,
            configured_rule_count: this.config.rules.length,
            governed_tools: this.config.rules.map((rule) => ({
                tool_name: rule.toolName,
                required_scope: rule.requiredScope,
                risk: rule.risk,
                approval: rule.approval,
            })),
            lease: this.safeState(),
            ledger: {
                ...(await this.ledger.summary()),
                healthy_in_current_process: this.ledgerHealthy,
            },
            default_behavior_for_unlisted_tools: "not_governed",
            raw_parameters_persisted: false,
            raw_results_persisted: false,
            raw_prompts_observed: false,
            secrets_persisted: false,
        };
    }

    clearRuntimeCache() {
        this.ledger.clearRuntimeCache();
    }
}
