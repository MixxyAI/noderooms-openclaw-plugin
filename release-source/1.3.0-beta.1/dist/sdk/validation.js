import { ALL_SCOPES, NodeRoomsError, } from "../contracts.js";
export function nonEmptyString(value) {
    return typeof value === "string" && value.trim() ? value.trim() : undefined;
}
export function boundedString(value, field, minimum, maximum) {
    if (typeof value !== "string" || value.length < minimum || value.length > maximum) {
        throw new NodeRoomsError(`INVALID_${field.toUpperCase()}`, `The NodeRooms ${field} must contain between ${minimum} and ${maximum} characters.`);
    }
    return value;
}
export function optionalBoundedString(value, field, maximum) {
    if (value === undefined || value === null || value === "") {
        return undefined;
    }
    if (typeof value !== "string" || value.length > maximum) {
        throw new NodeRoomsError(`INVALID_${field.toUpperCase()}`, `The NodeRooms ${field} must contain at most ${maximum} characters.`);
    }
    return value.trim();
}
export function positiveInteger(value, field) {
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed <= 0) {
        throw new NodeRoomsError(`INVALID_${field.toUpperCase()}`, `The NodeRooms ${field} is invalid.`);
    }
    return parsed;
}
export function optionalPositiveInteger(value, field) {
    if (value === undefined || value === null) {
        return undefined;
    }
    return positiveInteger(value, field);
}
export function assertId(value, pattern, field) {
    if (!pattern.test(value)) {
        throw new NodeRoomsError(`INVALID_${field.toUpperCase()}`, `The NodeRooms ${field} is invalid.`);
    }
}
export function requestedScopes(value) {
    if (!Array.isArray(value) || value.length < 1 || value.length > ALL_SCOPES.length) {
        throw new NodeRoomsError("INVALID_SCOPES", "Request between one and eleven canonical NodeRooms scopes.");
    }
    const unique = [...new Set(value)];
    if (unique.length !== value.length || unique.some((scope) => !ALL_SCOPES.includes(scope))) {
        throw new NodeRoomsError("INVALID_SCOPES", "Scopes must be unique canonical NodeRooms scope names.");
    }
    return unique;
}
export function optionalRoomSlug(value) {
    if (value === undefined || value === null || value === "") {
        return undefined;
    }
    if (typeof value !== "string" || !/^[a-z0-9-]{1,80}$/.test(value)) {
        throw new NodeRoomsError("INVALID_ROOM", "The NodeRooms room slug is invalid.");
    }
    return value;
}
