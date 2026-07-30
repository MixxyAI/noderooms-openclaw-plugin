import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
    lstat,
    open,
    readdir,
    realpath,
} from "node:fs/promises";
import {
    dirname,
    isAbsolute,
    join,
    relative,
    resolve,
    sep,
} from "node:path";
import { pathToFileURL } from "node:url";
import { IsUri } from "typebox/format";

import {
    canonicalJson,
    sha256Fingerprint,
} from "../../src/passport-runtime-binding.js";

export const FINGERPRINT_CONTRACT_VERSION =
    "noderooms-artifact-runtime-fingerprint.v1";
export const FINGERPRINT_SCHEMA_ID =
    "https://noderooms.com/contracts/artifact-runtime-fingerprint-v1.schema.json";
export const ARCHIVE_FINGERPRINT_PROFILE = "raw-artifact-bytes-sha256-v1";
export const DIRECTORY_NORMALIZATION_PROFILE =
    "noderooms-portable-directory-tree-sha256-v1";
export const RUNTIME_FINGERPRINT_PROFILE =
    "noderooms-runtime-observation-sha256-v1";

const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const PACKAGE_NAME_PATTERN = /^[A-Za-z0-9@][A-Za-z0-9._@/-]{0,213}$/;
const VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,79}$/;
const SAFE_IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,159}$/;
const COMMIT_SHA_PATTERN = /^[a-f0-9]{40}$/;
const HTTPS_URI_WITHOUT_QUERY_PATTERN = /^https:\/\/[^?#]+$/;
const WINDOWS_RESERVED_NAME_PATTERN =
    /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;
const SENSITIVE_FIELD_PATTERN =
    /(?:api[_-]?key|oauth[_-]?token|access[_-]?token|refresh[_-]?token|authorization|cookie|credential|private[_-]?key|run[_-]?secret|invite[_-]?token|raw[_-]?(?:prompt|conversation|message|email|tool|request|response|result|body)|owner[_-]?sender|session[_-]?key|home[_-]?path|environment[_-]?value|workboard[_-]?claim[_-]?token)/i;
const ARCHIVE_FORMATS = new Set(["npm_tgz", "zip", "tar", "other_declared"]);
const PLATFORMS = new Set([
    "aix",
    "android",
    "darwin",
    "freebsd",
    "linux",
    "openbsd",
    "sunos",
    "win32",
]);
const ARCHITECTURES = new Set([
    "arm",
    "arm64",
    "ia32",
    "loong64",
    "mips",
    "mipsel",
    "ppc",
    "ppc64",
    "riscv64",
    "s390",
    "s390x",
    "x64",
]);
const MAX_ENTRY_COUNT = 100_000;
const MAX_TOTAL_FILE_BYTES = 2_147_483_648;
const MAX_FILE_BYTES = 2_147_483_648;
const MAX_PACKAGE_JSON_BYTES = 1_048_576;
const MAX_RELATIVE_PATH_BYTES = 512;
const MAX_PATH_SEGMENT_BYTES = 120;
const MAX_ORIGIN_URI_LENGTH = 512;
const READ_FLAGS = fsConstants.O_RDONLY
    | (Number.isInteger(fsConstants.O_NOFOLLOW) ? fsConstants.O_NOFOLLOW : 0);

export class ArtifactRuntimeFingerprintError extends Error {
    constructor(code, message) {
        super(message);
        this.name = "ArtifactRuntimeFingerprintError";
        this.code = code;
    }
}

function fail(code, message) {
    throw new ArtifactRuntimeFingerprintError(code, message);
}

function isRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertExactKeys(value, required, optional, label) {
    if (!isRecord(value)) {
        fail("INVALID_OBJECT", `${label} must be an object.`);
    }
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail("UNKNOWN_FIELD", `${label} contains unsupported field ${key}.`);
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) {
            fail("MISSING_FIELD", `${label} is missing ${key}.`);
        }
    }
}

function assertPattern(value, pattern, code, label) {
    if (typeof value !== "string" || !pattern.test(value)) {
        fail(code, `${label} is invalid.`);
    }
    return value;
}

function assertSha256(value, label) {
    return assertPattern(value, SHA256_PATTERN, "INVALID_SHA256", label);
}

function assertIntegerRange(value, minimum, maximum, code, label) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        fail(code, `${label} is invalid.`);
    }
    return value;
}

function assertSafeHttpsUrl(value, label) {
    if (typeof value !== "string"
        || value.length > MAX_ORIGIN_URI_LENGTH
        || !HTTPS_URI_WITHOUT_QUERY_PATTERN.test(value)
        || !IsUri(value)) {
        fail(
            "UNSAFE_ORIGIN_URI",
            `${label} must match the schema HTTPS URI profile.`,
        );
    }
    let parsed;
    try {
        parsed = new URL(value);
    }
    catch {
        fail("UNSAFE_ORIGIN_URI", `${label} is not a valid URL.`);
    }
    if (parsed.protocol !== "https:"
        || parsed.username
        || parsed.password
        || parsed.search
        || parsed.hash) {
        fail(
            "UNSAFE_ORIGIN_URI",
            `${label} must be HTTPS without userinfo, query, or fragment.`,
        );
    }
    return value;
}

function assertNoSensitiveFields(value, path = "$") {
    if (Array.isArray(value)) {
        value.forEach((entry, index) => {
            assertNoSensitiveFields(entry, `${path}[${index}]`);
        });
        return;
    }
    if (!isRecord(value)) {
        return;
    }
    for (const [key, entry] of Object.entries(value)) {
        const safePolicyBoolean = typeof entry === "boolean"
            && /(?:allowed|included|normalized|proven|claimed|granted|enabled|automated|complete)$/i
                .test(key);
        if (!safePolicyBoolean && SENSITIVE_FIELD_PATTERN.test(key)) {
            fail(
                "SENSITIVE_FIELD_FORBIDDEN",
                `Sensitive material is forbidden at ${path}.${key}.`,
            );
        }
        assertNoSensitiveFields(entry, `${path}.${key}`);
    }
}

function byteOrder(left, right) {
    return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function asciiCaseFold(value) {
    return value.replace(/[A-Z]/g, (character) => character.toLowerCase());
}

export function assertPortableRelativePath(value) {
    if (typeof value !== "string"
        || value.length === 0
        || isAbsolute(value)
        || value.includes("\\")
        || value.includes("\0")
        || value !== value.normalize("NFC")
        || !/^[\x20-\x7e]+$/.test(value)) {
        fail(
            "NON_PORTABLE_PATH",
            "Directory entries must use non-empty NFC portable ASCII relative paths.",
        );
    }
    if (Buffer.byteLength(value, "utf8") > MAX_RELATIVE_PATH_BYTES) {
        fail("PATH_TOO_LONG", "A normalized relative path exceeds the profile limit.");
    }
    const segments = value.split("/");
    for (const segment of segments) {
        if (segment.length === 0
            || segment === "."
            || segment === ".."
            || /[<>:"|?*]/.test(segment)
            || /[. ]$/.test(segment)
            || WINDOWS_RESERVED_NAME_PATTERN.test(segment)
            || Buffer.byteLength(segment, "utf8") > MAX_PATH_SEGMENT_BYTES) {
            fail(
                "NON_PORTABLE_PATH",
                "A directory entry violates the portable path profile.",
            );
        }
    }
    return value;
}

function isContained(rootPath, candidatePath) {
    const relativePath = relative(rootPath, candidatePath);
    return relativePath === ""
        || (!isAbsolute(relativePath)
            && relativePath !== ".."
            && !relativePath.startsWith(`..${sep}`));
}

function statSnapshot(stat) {
    return {
        dev: stat.dev,
        ino: stat.ino,
        size: stat.size,
        mtimeNs: stat.mtimeNs,
        ctimeNs: stat.ctimeNs,
    };
}

function sameStat(left, right) {
    return left.dev === right.dev
        && left.ino === right.ino
        && left.size === right.size
        && left.mtimeNs === right.mtimeNs
        && left.ctimeNs === right.ctimeNs;
}

async function readRegularFile(
    filePath,
    label,
    { collectBytes = false, maxBytes = MAX_FILE_BYTES } = {},
) {
    let suppliedStat;
    try {
        suppliedStat = await lstat(filePath, { bigint: true });
    }
    catch {
        fail("FILE_OPEN_FAILED", `${label} does not exist.`);
    }
    if (suppliedStat.isSymbolicLink() || !suppliedStat.isFile()) {
        fail("UNSUPPORTED_FILE_TYPE", `${label} is not a regular file.`);
    }
    let handle;
    try {
        handle = await open(filePath, READ_FLAGS);
    }
    catch {
        fail("FILE_OPEN_FAILED", `${label} could not be opened without following links.`);
    }
    try {
        const before = await handle.stat({ bigint: true });
        if (!before.isFile()) {
            fail("UNSUPPORTED_FILE_TYPE", `${label} is not a regular file.`);
        }
        if (!sameStat(statSnapshot(suppliedStat), statSnapshot(before))) {
            fail("FILE_CHANGED_DURING_SCAN", `${label} changed before fingerprinting.`);
        }
        if (before.size < 0n || before.size > BigInt(maxBytes)) {
            fail("FILE_SIZE_LIMIT", `${label} exceeds the profile size limit.`);
        }
        const hash = createHash("sha256");
        const chunks = [];
        const buffer = Buffer.allocUnsafe(64 * 1024);
        let position = 0;
        while (true) {
            const { bytesRead } = await handle.read(
                buffer,
                0,
                buffer.length,
                position,
            );
            if (bytesRead === 0) {
                break;
            }
            const chunk = buffer.subarray(0, bytesRead);
            hash.update(chunk);
            if (collectBytes) {
                chunks.push(Buffer.from(chunk));
            }
            position += bytesRead;
            if (position > maxBytes) {
                fail("FILE_SIZE_LIMIT", `${label} exceeds the profile size limit.`);
            }
        }
        const after = await handle.stat({ bigint: true });
        if (!sameStat(statSnapshot(before), statSnapshot(after))
            || BigInt(position) !== before.size) {
            fail("FILE_CHANGED_DURING_SCAN", `${label} changed during fingerprinting.`);
        }
        return {
            sha256: `sha256:${hash.digest("hex")}`,
            size_bytes: position,
            bytes: collectBytes ? Buffer.concat(chunks) : undefined,
        };
    }
    finally {
        await handle.close();
    }
}

async function resolveDirectoryRoot(rootPath) {
    if (typeof rootPath !== "string" || rootPath.length === 0) {
        fail("INVALID_ROOT", "The package root is invalid.");
    }
    const resolvedRoot = resolve(rootPath);
    let suppliedRootStat;
    try {
        suppliedRootStat = await lstat(resolvedRoot, { bigint: true });
    }
    catch {
        fail("INVALID_ROOT", "The package root does not exist.");
    }
    if (suppliedRootStat.isSymbolicLink() || !suppliedRootStat.isDirectory()) {
        fail("INVALID_ROOT", "The package root must be a real directory.");
    }
    let canonicalRoot;
    try {
        canonicalRoot = await realpath(resolvedRoot);
    }
    catch {
        fail("INVALID_ROOT", "The package root does not exist.");
    }
    const rootStat = await lstat(canonicalRoot, { bigint: true });
    if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
        fail("INVALID_ROOT", "The package root must be a real directory.");
    }
    const suppliedRootAfter = await lstat(resolvedRoot, { bigint: true });
    if (suppliedRootAfter.isSymbolicLink()
        || !sameStat(
            statSnapshot(suppliedRootStat),
            statSnapshot(suppliedRootAfter),
        )) {
        fail("ROOT_CHANGED_DURING_SCAN", "The package root changed during resolution.");
    }
    return canonicalRoot;
}

async function collectDirectoryEntries(rootPath) {
    const entries = [];
    const seenExact = new Set();
    const seenCaseFolded = new Set();
    let fileCount = 0;
    let directoryCount = 0;
    let totalFileBytes = 0;

    function registerPath(relativePath) {
        assertPortableRelativePath(relativePath);
        if (seenExact.has(relativePath)) {
            fail("DUPLICATE_PATH", "The directory tree contains a duplicate path.");
        }
        const folded = asciiCaseFold(relativePath);
        if (seenCaseFolded.has(folded)) {
            fail(
                "CASE_COLLISION",
                "The directory tree contains a cross-platform case collision.",
            );
        }
        seenExact.add(relativePath);
        seenCaseFolded.add(folded);
        if (seenExact.size > MAX_ENTRY_COUNT) {
            fail("ENTRY_COUNT_LIMIT", "The directory tree exceeds the entry limit.");
        }
    }

    async function walk(currentPath, prefix) {
        const before = await lstat(currentPath, { bigint: true });
        if (before.isSymbolicLink() || !before.isDirectory()) {
            fail("DIRECTORY_TYPE_CHANGED", "A directory changed type during scanning.");
        }
        const canonicalCurrent = await realpath(currentPath);
        if (!isContained(rootPath, canonicalCurrent)) {
            fail("ROOT_ESCAPE", "A directory resolved outside the package root.");
        }
        const names = await readdir(currentPath);
        names.sort(byteOrder);
        for (const name of names) {
            const relativePath = prefix ? `${prefix}/${name}` : name;
            registerPath(relativePath);
            const absolutePath = join(currentPath, name);
            const entryStat = await lstat(absolutePath, { bigint: true });
            if (entryStat.isSymbolicLink()) {
                fail("SYMLINK_FORBIDDEN", "Symlinks are forbidden by the v1 profile.");
            }
            if (entryStat.isDirectory()) {
                directoryCount += 1;
                entries.push({
                    kind: "directory",
                    path: relativePath,
                });
                await walk(absolutePath, relativePath);
                continue;
            }
            if (!entryStat.isFile()) {
                fail(
                    "UNSUPPORTED_FILE_TYPE",
                    "Only regular files and directories are supported.",
                );
            }
            const file = await readRegularFile(absolutePath, relativePath);
            fileCount += 1;
            totalFileBytes += file.size_bytes;
            if (totalFileBytes > MAX_TOTAL_FILE_BYTES) {
                fail(
                    "TOTAL_SIZE_LIMIT",
                    "The directory tree exceeds the total byte limit.",
                );
            }
            entries.push({
                kind: "file",
                path: relativePath,
                size_bytes: file.size_bytes,
                sha256: file.sha256,
            });
        }
        const after = await lstat(currentPath, { bigint: true });
        if (!sameStat(statSnapshot(before), statSnapshot(after))) {
            fail(
                "DIRECTORY_CHANGED_DURING_SCAN",
                "A directory changed during fingerprinting.",
            );
        }
    }

    await walk(rootPath, "");
    entries.sort((left, right) => byteOrder(left.path, right.path));
    return {
        entries,
        fileCount,
        directoryCount,
        totalFileBytes,
    };
}

export async function fingerprintDirectory(packageRoot) {
    const rootPath = await resolveDirectoryRoot(packageRoot);
    const {
        entries,
        fileCount,
        directoryCount,
        totalFileBytes,
    } = await collectDirectoryEntries(rootPath);
    const manifest = {
        normalization_profile: DIRECTORY_NORMALIZATION_PROFILE,
        root_label: "package_root",
        file_count: fileCount,
        directory_count: directoryCount,
        total_file_bytes: totalFileBytes,
        entries,
    };
    return {
        binding: {
            root_label: "package_root",
            normalization_profile: DIRECTORY_NORMALIZATION_PROFILE,
            tree_fingerprint_sha256: sha256Fingerprint(manifest),
            file_count: fileCount,
        },
        manifest,
    };
}

export async function fingerprintArchive(archivePath, format) {
    if (!ARCHIVE_FORMATS.has(format)) {
        fail("ARCHIVE_FORMAT_INVALID", "The declared archive format is invalid.");
    }
    const archive = await readRegularFile(archivePath, "artifact archive");
    return {
        format,
        sha256: archive.sha256,
        size_bytes: archive.size_bytes,
    };
}

async function readPackageIdentity(packageRoot, directoryManifest) {
    const packageJsonPath = join(packageRoot, "package.json");
    const packageJson = await readRegularFile(
        packageJsonPath,
        "package.json",
        {
            collectBytes: true,
            maxBytes: MAX_PACKAGE_JSON_BYTES,
        },
    );
    let parsed;
    try {
        parsed = JSON.parse(
            new TextDecoder("utf-8", { fatal: true }).decode(packageJson.bytes),
        );
    }
    catch {
        fail("PACKAGE_JSON_INVALID", "package.json is not valid UTF-8 JSON.");
    }
    if (!isRecord(parsed)) {
        fail("PACKAGE_JSON_INVALID", "package.json must contain an object.");
    }
    assertPattern(
        parsed.name,
        PACKAGE_NAME_PATTERN,
        "PACKAGE_NAME_INVALID",
        "package name",
    );
    assertPattern(
        parsed.version,
        VERSION_PATTERN,
        "PACKAGE_VERSION_INVALID",
        "package version",
    );
    const manifestEntry = directoryManifest.entries.find(
        (entry) => entry.kind === "file" && entry.path === "package.json",
    );
    if (!manifestEntry
        || manifestEntry.sha256 !== packageJson.sha256
        || manifestEntry.size_bytes !== packageJson.size_bytes) {
        fail(
            "PACKAGE_IDENTITY_RACE",
            "package.json changed between identity and directory observations.",
        );
    }
    return {
        package_name: parsed.name,
        package_version: parsed.version,
        package_json_sha256: packageJson.sha256,
    };
}

export async function fingerprintArtifact(config) {
    assertExactKeys(config, [
        "package_root",
        "publisher_id",
        "origin_uri",
    ], [
        "archive_path",
        "archive_format",
    ], "artifact config");
    assertPattern(
        config.publisher_id,
        SAFE_IDENTIFIER_PATTERN,
        "PUBLISHER_ID_INVALID",
        "publisher_id",
    );
    assertSafeHttpsUrl(config.origin_uri, "origin_uri");
    const rootPath = await resolveDirectoryRoot(config.package_root);
    const directory = await fingerprintDirectory(rootPath);
    const identity = await readPackageIdentity(rootPath, directory.manifest);
    let archive;
    if (Object.hasOwn(config, "archive_path")
        || Object.hasOwn(config, "archive_format")) {
        if (typeof config.archive_path !== "string"
            || typeof config.archive_format !== "string") {
            fail(
                "ARCHIVE_INPUT_INCOMPLETE",
                "archive_path and archive_format must be supplied together.",
            );
        }
        archive = await fingerprintArchive(
            config.archive_path,
            config.archive_format,
        );
    }
    return {
        artifact_binding: {
            package_name: identity.package_name,
            package_version: identity.package_version,
            publisher_id: config.publisher_id,
            origin_uri: config.origin_uri,
            ...(archive ? { archive } : {}),
            directory: directory.binding,
        },
        package_json_sha256: identity.package_json_sha256,
        directory_manifest: directory.manifest,
    };
}

function validateArtifactBinding(artifactBinding) {
    assertExactKeys(artifactBinding, [
        "package_name",
        "package_version",
        "publisher_id",
        "origin_uri",
        "directory",
    ], [
        "archive",
    ], "artifact binding");
    assertPattern(
        artifactBinding.package_name,
        PACKAGE_NAME_PATTERN,
        "PACKAGE_NAME_INVALID",
        "artifact package name",
    );
    assertPattern(
        artifactBinding.package_version,
        VERSION_PATTERN,
        "PACKAGE_VERSION_INVALID",
        "artifact package version",
    );
    assertPattern(
        artifactBinding.publisher_id,
        SAFE_IDENTIFIER_PATTERN,
        "PUBLISHER_ID_INVALID",
        "artifact publisher_id",
    );
    assertSafeHttpsUrl(artifactBinding.origin_uri, "artifact origin_uri");
    assertExactKeys(artifactBinding.directory, [
        "root_label",
        "normalization_profile",
        "tree_fingerprint_sha256",
        "file_count",
    ], [], "artifact binding.directory");
    if (artifactBinding.directory.root_label !== "package_root"
        || artifactBinding.directory.normalization_profile
            !== DIRECTORY_NORMALIZATION_PROFILE) {
        fail(
            "DIRECTORY_PROFILE_MISMATCH",
            "The artifact directory binding uses an unsupported profile.",
        );
    }
    assertSha256(
        artifactBinding.directory.tree_fingerprint_sha256,
        "artifact directory fingerprint",
    );
    assertIntegerRange(
        artifactBinding.directory.file_count,
        1,
        MAX_ENTRY_COUNT,
        "FILE_COUNT_INVALID",
        "artifact directory file_count",
    );
    if (artifactBinding.archive) {
        assertExactKeys(artifactBinding.archive, [
            "format",
            "sha256",
            "size_bytes",
        ], [], "artifact binding.archive");
        if (!ARCHIVE_FORMATS.has(artifactBinding.archive.format)) {
            fail(
                "ARCHIVE_FORMAT_INVALID",
                "The artifact archive format is invalid.",
            );
        }
        assertSha256(artifactBinding.archive.sha256, "artifact archive sha256");
        assertIntegerRange(
            artifactBinding.archive.size_bytes,
            0,
            MAX_FILE_BYTES,
            "ARCHIVE_SIZE_INVALID",
            "artifact archive size_bytes",
        );
    }
    return artifactBinding;
}

function validateRuntimeObservation(observation) {
    assertNoSensitiveFields(observation);
    assertExactKeys(observation, [
        "openclaw",
        "node",
        "bindings",
        "environment",
    ], [
        "source_commit_sha",
    ], "runtime observation");
    assertExactKeys(observation.openclaw, [
        "version",
        "package_json_sha256",
        "directory_tree_fingerprint_sha256",
        "plugin_api_fingerprint_sha256",
    ], [], "runtime observation.openclaw");
    assertExactKeys(observation.node, [
        "version",
        "executable_sha256",
    ], [], "runtime observation.node");
    assertExactKeys(observation.bindings, [
        "gateway_fingerprint_sha256",
        "openclaw_agent_fingerprint_sha256",
        "runtime_key_thumbprint_sha256",
        "sanitized_config_fingerprint_sha256",
    ], [], "runtime observation.bindings");
    assertExactKeys(observation.environment, [
        "platform",
        "arch",
        "environment_class",
    ], [], "runtime observation.environment");
    assertPattern(
        observation.openclaw.version,
        VERSION_PATTERN,
        "OPENCLAW_VERSION_INVALID",
        "openclaw.version",
    );
    for (const [key, value] of Object.entries(observation.openclaw)) {
        if (key.endsWith("_sha256")) {
            assertSha256(value, `openclaw.${key}`);
        }
    }
    assertPattern(
        observation.node.version,
        VERSION_PATTERN,
        "NODE_VERSION_INVALID",
        "node.version",
    );
    assertSha256(observation.node.executable_sha256, "node.executable_sha256");
    for (const [key, value] of Object.entries(observation.bindings)) {
        assertSha256(value, `bindings.${key}`);
    }
    if (!PLATFORMS.has(observation.environment.platform)
        || !ARCHITECTURES.has(observation.environment.arch)) {
        fail("ENVIRONMENT_INVALID", "The runtime platform or architecture is invalid.");
    }
    const majorMatch = /^([0-9]+)\./.exec(observation.node.version);
    if (!majorMatch) {
        fail("NODE_VERSION_INVALID", "node.version must start with a numeric major.");
    }
    const expectedEnvironmentClass =
        `${observation.environment.platform}-${observation.environment.arch}`
        + `-node${majorMatch[1]}`;
    if (observation.environment.environment_class !== expectedEnvironmentClass) {
        fail(
            "ENVIRONMENT_CLASS_MISMATCH",
            "environment_class does not match platform, architecture, and Node major.",
        );
    }
    if (Object.hasOwn(observation, "source_commit_sha")) {
        assertPattern(
            observation.source_commit_sha,
            COMMIT_SHA_PATTERN,
            "SOURCE_COMMIT_INVALID",
            "source_commit_sha",
        );
    }
    return observation;
}

export function fingerprintRuntimeObservation(observation, artifactBinding) {
    validateRuntimeObservation(observation);
    validateArtifactBinding(artifactBinding);
    const runtimeManifest = {
        fingerprint_profile: RUNTIME_FINGERPRINT_PROFILE,
        openclaw: structuredClone(observation.openclaw),
        node: structuredClone(observation.node),
        plugin: {
            package_name: artifactBinding.package_name,
            package_version: artifactBinding.package_version,
            package_directory_tree_fingerprint_sha256:
                artifactBinding.directory.tree_fingerprint_sha256,
            package_archive_sha256: artifactBinding.archive?.sha256 ?? null,
        },
        bindings: structuredClone(observation.bindings),
        environment: structuredClone(observation.environment),
        ...(observation.source_commit_sha
            ? { source_commit_sha: observation.source_commit_sha }
            : {}),
    };
    const runtimeInstanceFingerprint = sha256Fingerprint(runtimeManifest);
    return {
        runtime_observation_manifest: runtimeManifest,
        runtime_binding: {
            openclaw_version: observation.openclaw.version,
            openclaw_plugin_api_fingerprint_sha256:
                observation.openclaw.plugin_api_fingerprint_sha256,
            plugin_package_name: artifactBinding.package_name,
            plugin_package_version: artifactBinding.package_version,
            gateway_fingerprint_sha256:
                observation.bindings.gateway_fingerprint_sha256,
            runtime_instance_fingerprint_sha256: runtimeInstanceFingerprint,
            openclaw_agent_fingerprint_sha256:
                observation.bindings.openclaw_agent_fingerprint_sha256,
            runtime_key_thumbprint_sha256:
                observation.bindings.runtime_key_thumbprint_sha256,
            sanitized_config_fingerprint_sha256:
                observation.bindings.sanitized_config_fingerprint_sha256,
            environment_class: observation.environment.environment_class,
            ...(observation.source_commit_sha
                ? { source_commit_sha: observation.source_commit_sha }
                : {}),
        },
    };
}

export function fingerprintResultProjection(result) {
    const {
        $schema: _schema,
        result_fingerprint_sha256: _fingerprint,
        ...projection
    } = result;
    return projection;
}

export function fingerprintResult(result) {
    return sha256Fingerprint(fingerprintResultProjection(result));
}

export async function buildArtifactRuntimeFingerprintResult(config) {
    assertExactKeys(config, [
        "package_root",
        "publisher_id",
        "origin_uri",
        "runtime_observation",
        "fixture",
    ], [
        "archive_path",
        "archive_format",
    ], "fingerprint config");
    if (typeof config.fixture !== "boolean") {
        fail("FIXTURE_FLAG_INVALID", "fixture must be boolean.");
    }
    const hasArchivePath = Object.hasOwn(config, "archive_path");
    const hasArchiveFormat = Object.hasOwn(config, "archive_format");
    if (hasArchivePath !== hasArchiveFormat) {
        fail(
            "ARCHIVE_INPUT_INCOMPLETE",
            "archive_path and archive_format must be supplied together.",
        );
    }
    const artifact = await fingerprintArtifact({
        package_root: config.package_root,
        publisher_id: config.publisher_id,
        origin_uri: config.origin_uri,
        ...(hasArchivePath
            ? {
                archive_path: config.archive_path,
                archive_format: config.archive_format,
            }
            : {}),
    });
    const runtime = fingerprintRuntimeObservation(
        config.runtime_observation,
        artifact.artifact_binding,
    );
    const result = {
        $schema: FINGERPRINT_SCHEMA_ID,
        contract_version: FINGERPRINT_CONTRACT_VERSION,
        fixture: config.fixture,
        authority_status: "evidence_only_no_authority",
        profiles: {
            archive_fingerprint: ARCHIVE_FINGERPRINT_PROFILE,
            directory_normalization: DIRECTORY_NORMALIZATION_PROFILE,
            runtime_fingerprint: RUNTIME_FINGERPRINT_PROFILE,
        },
        artifact_binding: artifact.artifact_binding,
        package_json_sha256: artifact.package_json_sha256,
        directory_manifest: artifact.directory_manifest,
        runtime_observation_manifest: runtime.runtime_observation_manifest,
        runtime_binding: runtime.runtime_binding,
        claims: {
            archive_bytes_exactly_hashed: Boolean(
                artifact.artifact_binding.archive,
            ),
            directory_contents_exactly_hashed: true,
            archive_directory_correspondence_proven: false,
            publisher_control_verified: false,
            origin_content_verified: false,
            runtime_observation_source_verified: false,
            file_modes_included: false,
            symlinks_allowed: false,
            line_endings_normalized: false,
            runtime_observation_exactly_fingerprinted: true,
            artifact_safe_claimed: false,
            execution_authority_granted: false,
            production_enforcement_enabled: false,
            owner_decision_automated: false,
            external_validation_complete: false,
        },
        zero_side_effects: {
            NODE_ROOMS_PRODUCTION_NETWORK_CALLS: 0,
            PUBLIC_WRITES: 0,
            PROVIDER_WRITES: 0,
            OWNER_COMMANDS: 0,
            LIVE_LEASE_REQUESTS: 0,
            GATEWAY_STARTS: 0,
            GATEWAY_RESTARTS: 0,
            CLAWHUB_PUBLISH_ATTEMPTS: 0,
            NPM_PUBLISH_ATTEMPTS: 0,
            OPENCLAW_CONFIG_WRITES: 0,
            ARTIFACT_INSTALL_ATTEMPTS: 0,
            ARTIFACT_BLOCK_ATTEMPTS: 0,
        },
    };
    assertNoSensitiveFields(result);
    result.result_fingerprint_sha256 = fingerprintResult(result);
    return result;
}

async function runCli(argv) {
    if (argv.length !== 2 || argv[0] !== "build") {
        fail(
            "CLI_USAGE",
            "Usage: node artifact-runtime-fingerprint.mjs build <input.json>",
        );
    }
    const inputPath = resolve(argv[1]);
    const inputFile = await readRegularFile(
        inputPath,
        "CLI input",
        {
            collectBytes: true,
            maxBytes: MAX_PACKAGE_JSON_BYTES,
        },
    );
    let input;
    try {
        input = JSON.parse(
            new TextDecoder("utf-8", { fatal: true }).decode(inputFile.bytes),
        );
    }
    catch {
        fail("CLI_INPUT_INVALID", "The CLI input is not valid UTF-8 JSON.");
    }
    const inputDirectory = dirname(inputPath);
    const result = await buildArtifactRuntimeFingerprintResult({
        ...input,
        package_root: resolve(inputDirectory, input.package_root),
        ...(input.archive_path
            ? { archive_path: resolve(inputDirectory, input.archive_path) }
            : {}),
    });
    process.stdout.write(`${canonicalJson(result)}\n`);
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (invokedPath === import.meta.url) {
    runCli(process.argv.slice(2)).catch((error) => {
        const code = error instanceof ArtifactRuntimeFingerprintError
            ? error.code
            : "UNEXPECTED_ERROR";
        process.stderr.write(`${code}: ${error.message}\n`);
        process.exitCode = 1;
    });
}
