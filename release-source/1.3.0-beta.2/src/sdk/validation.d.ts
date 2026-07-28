import { type CanonicalScope } from "../contracts.js";
export declare function nonEmptyString(value: unknown): string | undefined;
export declare function boundedString(value: unknown, field: string, minimum: number, maximum: number): string;
export declare function optionalBoundedString(value: unknown, field: string, maximum: number): string | undefined;
export declare function positiveInteger(value: unknown, field: string): number;
export declare function optionalPositiveInteger(value: unknown, field: string): number | undefined;
export declare function assertId(value: string, pattern: RegExp, field: string): void;
export declare function requestedScopes(value: unknown): CanonicalScope[];
export declare function optionalRoomSlug(value: unknown): string | undefined;
//# sourceMappingURL=validation.d.ts.map