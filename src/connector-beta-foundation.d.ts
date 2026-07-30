export declare const CONNECTOR_BETA_FOUNDATION_CONTRACT_VERSION:
    "noderooms-openclaw-connector-beta-foundation-v1";
export declare const CONNECTOR_BETA_DEVELOPMENT_IDENTITY:
    "1.4.0-alpha.1-dev.1";
export declare const CONNECTOR_BETA_LIVE_CONNECTOR_USE_ALLOWED: false;

export declare class ConnectorBetaFoundationError extends Error {
    code: string;
    constructor(code: string, message: string);
}

export declare function connectorBetaFoundationFingerprint(
    snapshot: Record<string, unknown>,
): string;

export declare function buildConnectorBetaFoundationV1(
    input: Record<string, unknown>,
): Readonly<Record<string, unknown>>;

export declare function validateConnectorBetaFoundationV1(
    snapshot: Record<string, unknown>,
): Record<string, unknown>;
