export type TrustEventLedgerOptions = {
    filePath: string;
    maxEntries?: number;
};
export declare class TrustEventLedger {
    private filePath;
    private maxEntries;
    private queue;
    constructor(options: TrustEventLedgerOptions);
    append(input: Record<string, unknown>): Promise<void>;
    summary(): Promise<Record<string, unknown>>;
    clearRuntimeCache(): void;
}
