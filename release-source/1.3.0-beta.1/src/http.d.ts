type JsonRecord = Record<string, unknown>;
export declare function pinnedNodeRoomsUrl(rawUrl: string): string;
export declare function requestJson(rawUrl: string, init?: RequestInit): Promise<JsonRecord>;
export declare function jsonBody(value: JsonRecord): string;
export declare function pick(record: JsonRecord, keys: readonly string[]): JsonRecord;
export {};
//# sourceMappingURL=http.d.ts.map