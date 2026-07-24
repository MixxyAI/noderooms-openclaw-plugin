import type { JsonRecord } from "./passport-runtime-binding.js";

export declare class WorkdeskTaskFlowContractError extends Error {
    readonly code: string;
    constructor(code: string, message: string);
}

export type WorkdeskTaskFlowValidationOptions = {
    allowFixture?: boolean;
    allowContractOnly?: boolean;
    requireUnexpired?: boolean;
    now?: number | Date;
};

export type WorkMissionInput = {
    workItem: JsonRecord;
    card: JsonRecord;
    flow: JsonRecord;
    receipts: JsonRecord[];
};

export type WorkMissionDecision = Readonly<{
    decision: "contract_match_not_dispatched" | "block_invalid_work_mission";
    reason_code: string;
    work_item_id?: string;
    mission_id?: string;
    card_id?: string;
    flow_id?: string;
    current_step_id?: string;
    work_receipt_count?: number;
    mission_card_idempotent?: true;
    owner_review_waiting?: boolean;
    restart_reconciled?: boolean;
    live_dispatch_allowed: false;
}>;

export declare function workItemProjection(workItem: JsonRecord): JsonRecord;
export declare function workItemFingerprint(workItem: JsonRecord): string;
export declare function validateWorkItemV1(
    workItem: JsonRecord,
    options?: WorkdeskTaskFlowValidationOptions,
): JsonRecord;
export declare function publicWorkReceiptProjection(receipt: JsonRecord): JsonRecord;
export declare function publicWorkReceiptProjectionFingerprint(receipt: JsonRecord): string;
export declare function workStepReceiptProjection(receipt: JsonRecord): JsonRecord;
export declare function workStepReceiptFingerprint(receipt: JsonRecord): string;
export declare function validateWorkStepReceiptV1(
    receipt: JsonRecord,
    workItem: JsonRecord,
    options?: WorkdeskTaskFlowValidationOptions,
): JsonRecord;
export declare function taskFlowRunProjection(flow: JsonRecord): JsonRecord;
export declare function taskFlowRunFingerprint(flow: JsonRecord): string;
export declare function validateTaskFlowRunV1(
    input: {
        flow: JsonRecord;
        workItem: JsonRecord;
        receipts?: JsonRecord[];
    },
    options?: WorkdeskTaskFlowValidationOptions,
): JsonRecord;
export declare function workboardCardProjection(card: JsonRecord): JsonRecord;
export declare function workboardCardFingerprint(card: JsonRecord): string;
export declare function validateWorkboardCardV1(
    input: WorkMissionInput,
    options?: WorkdeskTaskFlowValidationOptions,
): JsonRecord;
export declare function validateMissionSet(
    records: WorkMissionInput[],
    options?: WorkdeskTaskFlowValidationOptions,
): Readonly<{
    mission_count: number;
    work_item_count: number;
    workboard_card_count: number;
    task_flow_count: number;
    one_to_one_mapping: true;
    live_dispatch_allowed: false;
}>;
export declare function evaluateWorkMissionV1(
    input: WorkMissionInput,
    options?: WorkdeskTaskFlowValidationOptions,
): WorkMissionDecision;
