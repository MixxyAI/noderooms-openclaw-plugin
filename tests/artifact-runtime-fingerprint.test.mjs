import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
    chmod,
    cp,
    mkdir,
    mkdtemp,
    readFile,
    rm,
    symlink,
    writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Value } from "typebox/value";

import { sha256Fingerprint } from "../src/passport-runtime-binding.js";
import {
    ARCHIVE_FINGERPRINT_PROFILE,
    ArtifactRuntimeFingerprintError,
    DIRECTORY_NORMALIZATION_PROFILE,
    FINGERPRINT_CONTRACT_VERSION,
    RUNTIME_FINGERPRINT_PROFILE,
    assertPortableRelativePath,
    buildArtifactRuntimeFingerprintResult,
    fingerprintArchive,
    fingerprintDirectory,
    fingerprintResult,
    fingerprintRuntimeObservation,
} from "../tools/trustbridge/artifact-runtime-fingerprint.mjs";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const fixtureRoot = join(
    repositoryRoot,
    "contracts/fixtures/artifact-runtime-fingerprint-v1",
);
const fixturePackageRoot = join(fixtureRoot, "package");

const readJson = async (relativePath) => JSON.parse(await readFile(
    join(repositoryRoot, relativePath),
    "utf8",
));

const schema = await readJson(
    "contracts/artifact-runtime-fingerprint-v1.schema.json",
);
const evidenceSchema = await readJson(
    "contracts/claw-runtime-evidence-v0.1.schema.json",
);
const expectedResult = await readJson(
    "contracts/fixtures/artifact-runtime-fingerprint-v1/expected-result.json",
);
const runtimeObservation = await readJson(
    "contracts/fixtures/artifact-runtime-fingerprint-v1/runtime-observation.json",
);
const evidenceFixture = await readJson(
    "contracts/fixtures/claw-runtime-evidence.readonly-pass-v0.1.json",
);
const packageJson = await readJson("package.json");
const pluginManifest = await readJson("openclaw.plugin.json");
const engineSource = await readFile(
    join(
        repositoryRoot,
        "tools/trustbridge/artifact-runtime-fingerprint.mjs",
    ),
    "utf8",
);

async function tempDirectory(t) {
    const path = await mkdtemp(join(tmpdir(), "noderooms-005b-"));
    t.after(async () => {
        await rm(path, { recursive: true, force: true });
    });
    return path;
}

async function expectCode(action, code) {
    await assert.rejects(
        action,
        (error) => error instanceof ArtifactRuntimeFingerprintError
            && error.code === code,
    );
}

function fixtureConfig(overrides = {}) {
    return {
        package_root: fixturePackageRoot,
        publisher_id: "example-fixture-publisher",
        origin_uri: "https://example.invalid/registry/trustbridge-fixture",
        runtime_observation: structuredClone(runtimeObservation),
        fixture: true,
        ...overrides,
    };
}

function evidenceProjection(value) {
    const {
        $schema: _schema,
        evidence_fingerprint_sha256: _fingerprint,
        attestation: _attestation,
        ...projection
    } = value;
    return projection;
}

test("005B freezes distinct archive, directory, and runtime profiles", () => {
    assert.equal(
        FINGERPRINT_CONTRACT_VERSION,
        "noderooms-artifact-runtime-fingerprint.v1",
    );
    assert.equal(
        ARCHIVE_FINGERPRINT_PROFILE,
        "raw-artifact-bytes-sha256-v1",
    );
    assert.equal(
        DIRECTORY_NORMALIZATION_PROFILE,
        "noderooms-portable-directory-tree-sha256-v1",
    );
    assert.equal(
        RUNTIME_FINGERPRINT_PROFILE,
        "noderooms-runtime-observation-sha256-v1",
    );
});

test("canonical 005B fixture is byte-stable and schema-valid", async () => {
    const result = await buildArtifactRuntimeFingerprintResult(fixtureConfig());
    assert.deepEqual(result, expectedResult);
    assert.equal(Value.Check(schema, result), true);
    assert.equal(result.result_fingerprint_sha256, fingerprintResult(result));
    assert.equal(
        result.artifact_binding.directory.tree_fingerprint_sha256,
        "sha256:9c45a6821f4b0b47dbf26024baa3cd4d301127c9ede974c668c267323d8fb2a0",
    );
    assert.equal(
        result.runtime_binding.runtime_instance_fingerprint_sha256,
        "sha256:bd1fee1c2da451cb651875e7e302694257690c7f9e37591b2e6430741644ab15",
    );
});

test("directory manifest is sorted by UTF-8 bytes and binds exact raw files", async () => {
    const result = await fingerprintDirectory(fixturePackageRoot);
    const paths = result.manifest.entries.map((entry) => entry.path);
    assert.deepEqual(paths, [
        "LICENSE",
        "assets",
        "assets/policy.json",
        "dist",
        "dist/index.js",
        "package.json",
    ]);
    assert.equal(result.manifest.file_count, 4);
    assert.equal(result.manifest.directory_count, 2);
    assert.equal(result.manifest.total_file_bytes, 241);
    for (const entry of result.manifest.entries) {
        if (entry.kind === "file") {
            assert.match(entry.sha256, /^sha256:[a-f0-9]{64}$/);
        }
    }
});

test("archive digest covers raw bytes and stays separate from a tree fingerprint", async (t) => {
    const root = await tempDirectory(t);
    const archivePath = join(root, "fixture.tgz");
    const bytes = Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x0d, 0x0a, 0xff]);
    await writeFile(archivePath, bytes);
    const archive = await fingerprintArchive(archivePath, "npm_tgz");
    assert.deepEqual(archive, {
        format: "npm_tgz",
        sha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
        size_bytes: bytes.length,
    });
    assert.notEqual(
        archive.sha256,
        expectedResult.artifact_binding.directory.tree_fingerprint_sha256,
    );
});

test("directory creation order does not change the canonical fingerprint", async (t) => {
    const root = await tempDirectory(t);
    const first = join(root, "first");
    const second = join(root, "second");
    await mkdir(join(first, "dist"), { recursive: true });
    await writeFile(join(first, "z.txt"), "z\n");
    await writeFile(join(first, "dist", "a.js"), "a\n");
    await mkdir(join(second, "dist"), { recursive: true });
    await writeFile(join(second, "dist", "a.js"), "a\n");
    await writeFile(join(second, "z.txt"), "z\n");
    const left = await fingerprintDirectory(first);
    const right = await fingerprintDirectory(second);
    assert.deepEqual(left, right);
});

test("line endings are exact bytes and are never normalized", async (t) => {
    const root = await tempDirectory(t);
    const lf = join(root, "lf");
    const crlf = join(root, "crlf");
    await mkdir(lf);
    await mkdir(crlf);
    await writeFile(join(lf, "text.txt"), "one\ntwo\n");
    await writeFile(join(crlf, "text.txt"), "one\r\ntwo\r\n");
    const lfResult = await fingerprintDirectory(lf);
    const crlfResult = await fingerprintDirectory(crlf);
    assert.notEqual(
        lfResult.binding.tree_fingerprint_sha256,
        crlfResult.binding.tree_fingerprint_sha256,
    );
});

test("portable v1 explicitly excludes permission bits from the claim", async (t) => {
    if (process.platform === "win32") {
        t.skip("POSIX permission-bit check is not applicable on win32.");
        return;
    }
    const root = await tempDirectory(t);
    const first = join(root, "first");
    const second = join(root, "second");
    await cp(fixturePackageRoot, first, { recursive: true });
    await cp(fixturePackageRoot, second, { recursive: true });
    await chmod(join(first, "dist", "index.js"), 0o644);
    await chmod(join(second, "dist", "index.js"), 0o755);
    const left = await fingerprintDirectory(first);
    const right = await fingerprintDirectory(second);
    assert.equal(
        left.binding.tree_fingerprint_sha256,
        right.binding.tree_fingerprint_sha256,
    );
    assert.equal(expectedResult.claims.file_modes_included, false);
});

test("symlinks and a symlinked root fail closed", async (t) => {
    if (process.platform === "win32") {
        t.skip("Symlink creation may require an elevated Windows token.");
        return;
    }
    const root = await tempDirectory(t);
    const packageRoot = join(root, "package");
    await mkdir(packageRoot);
    await writeFile(join(packageRoot, "file.txt"), "data");
    await symlink("file.txt", join(packageRoot, "link.txt"));
    await expectCode(
        () => fingerprintDirectory(packageRoot),
        "SYMLINK_FORBIDDEN",
    );
    const target = join(root, "target");
    const linkedRoot = join(root, "linked-root");
    await mkdir(target);
    await writeFile(join(target, "file.txt"), "data");
    await symlink(target, linkedRoot);
    await expectCode(
        () => fingerprintDirectory(linkedRoot),
        "INVALID_ROOT",
    );
});

test("portable path profile rejects traversal and cross-platform ambiguity", () => {
    for (const path of [
        "../escape",
        "./relative",
        "folder\\file.txt",
        "folder/CON",
        "folder/trailing.",
        "folder/trailing ",
        "árvíz.txt",
        "/absolute/path",
    ]) {
        assert.throws(
            () => assertPortableRelativePath(path),
            (error) => error instanceof ArtifactRuntimeFingerprintError
                && error.code === "NON_PORTABLE_PATH",
        );
    }
    assert.equal(
        assertPortableRelativePath("@scope/package/dist/index.js"),
        "@scope/package/dist/index.js",
    );
});

test("ASCII case collisions fail closed on case-sensitive hosts", async (t) => {
    if (process.platform === "win32" || process.platform === "darwin") {
        t.skip("The default filesystem may not permit both case variants.");
        return;
    }
    const root = await tempDirectory(t);
    await writeFile(join(root, "Agent.txt"), "one");
    await writeFile(join(root, "agent.txt"), "two");
    await expectCode(() => fingerprintDirectory(root), "CASE_COLLISION");
});

test("runtime fingerprint changes when any exact runtime observation changes", () => {
    const artifactBinding = expectedResult.artifact_binding;
    const first = fingerprintRuntimeObservation(
        structuredClone(runtimeObservation),
        artifactBinding,
    );
    const changed = structuredClone(runtimeObservation);
    changed.node.executable_sha256 = `sha256:${"9".repeat(64)}`;
    const second = fingerprintRuntimeObservation(changed, artifactBinding);
    assert.notEqual(
        first.runtime_binding.runtime_instance_fingerprint_sha256,
        second.runtime_binding.runtime_instance_fingerprint_sha256,
    );
});

test("runtime observations reject unknown, sensitive, and inconsistent inputs", () => {
    const artifactBinding = expectedResult.artifact_binding;
    const unknown = structuredClone(runtimeObservation);
    unknown.hostname = "not-public";
    assert.throws(
        () => fingerprintRuntimeObservation(unknown, artifactBinding),
        (error) => error instanceof ArtifactRuntimeFingerprintError
            && error.code === "UNKNOWN_FIELD",
    );
    const sensitive = structuredClone(runtimeObservation);
    sensitive.openclaw.access_token = "forbidden";
    assert.throws(
        () => fingerprintRuntimeObservation(sensitive, artifactBinding),
        (error) => error instanceof ArtifactRuntimeFingerprintError
            && error.code === "SENSITIVE_FIELD_FORBIDDEN",
    );
    const inconsistent = structuredClone(runtimeObservation);
    inconsistent.environment.environment_class = "linux-arm64-node24";
    assert.throws(
        () => fingerprintRuntimeObservation(inconsistent, artifactBinding),
        (error) => error instanceof ArtifactRuntimeFingerprintError
            && error.code === "ENVIRONMENT_CLASS_MISMATCH",
    );
    const wrongProfile = structuredClone(artifactBinding);
    wrongProfile.directory.normalization_profile = "unversioned-profile";
    assert.throws(
        () => fingerprintRuntimeObservation(runtimeObservation, wrongProfile),
        (error) => error instanceof ArtifactRuntimeFingerprintError
            && error.code === "DIRECTORY_PROFILE_MISMATCH",
    );
    const invalidArchive = structuredClone(artifactBinding);
    invalidArchive.archive = {
        format: "npm_tgz",
        sha256: `sha256:${"A".repeat(64)}`,
        size_bytes: 1,
    };
    assert.throws(
        () => fingerprintRuntimeObservation(runtimeObservation, invalidArchive),
        (error) => error instanceof ArtifactRuntimeFingerprintError
            && error.code === "INVALID_SHA256",
    );
});

test("package byte changes alter both package and tree identity", async (t) => {
    const root = await tempDirectory(t);
    const packageRoot = join(root, "package");
    await cp(fixturePackageRoot, packageRoot, { recursive: true });
    const before = await buildArtifactRuntimeFingerprintResult(
        fixtureConfig({ package_root: packageRoot }),
    );
    const packagePath = join(packageRoot, "package.json");
    const parsed = JSON.parse(await readFile(packagePath, "utf8"));
    parsed.version = "0.0.1-005b-fixture";
    await writeFile(packagePath, `${JSON.stringify(parsed, null, 2)}\n`);
    const after = await buildArtifactRuntimeFingerprintResult(
        fixtureConfig({ package_root: packageRoot }),
    );
    assert.notEqual(before.package_json_sha256, after.package_json_sha256);
    assert.notEqual(
        before.artifact_binding.directory.tree_fingerprint_sha256,
        after.artifact_binding.directory.tree_fingerprint_sha256,
    );
    assert.equal(after.runtime_binding.plugin_package_version, parsed.version);
});

test("005B result remains structurally compatible with the 005A evidence envelope", () => {
    const evidence = structuredClone(evidenceFixture);
    evidence.evidence_profile = "artifact_runtime_assessment";
    delete evidence.authority_binding;
    evidence.artifact_binding = structuredClone(expectedResult.artifact_binding);
    evidence.runtime_binding = structuredClone(expectedResult.runtime_binding);
    evidence.evidence_fingerprint_sha256 = sha256Fingerprint(
        evidenceProjection(evidence),
    );
    assert.equal(Value.Check(evidenceSchema, evidence), true);
});

test("005B output exposes no local root, secret, or authority expansion", async () => {
    const result = await buildArtifactRuntimeFingerprintResult(fixtureConfig());
    const serialized = JSON.stringify(result);
    assert.equal(serialized.includes(repositoryRoot), false);
    assert.doesNotMatch(
        serialized,
        /(?:access[_-]?token|authorization|cookie|private[_-]?key|run[_-]?secret)/i,
    );
    assert.equal(result.authority_status, "evidence_only_no_authority");
    assert.equal(result.claims.execution_authority_granted, false);
    assert.equal(result.claims.production_enforcement_enabled, false);
    assert.equal(result.claims.publisher_control_verified, false);
    assert.equal(result.claims.origin_content_verified, false);
    assert.equal(result.claims.runtime_observation_source_verified, false);
    assert.deepEqual(
        new Set(Object.values(result.zero_side_effects)),
        new Set([0]),
    );
});

test("005B engine has no network, process execution, environment, or write API", () => {
    assert.doesNotMatch(
        engineSource,
        /node:(?:http|https|net|tls|dgram|child_process|worker_threads)/,
    );
    assert.doesNotMatch(engineSource, /\bfetch\s*\(/);
    assert.doesNotMatch(engineSource, /process\.env/);
    assert.doesNotMatch(
        engineSource,
        /\b(?:writeFile|appendFile|rename|unlink|mkdir|rm|rmdir)\b/,
    );
});

test("005B remains outside immutable stable 1.3.0 package bytes", () => {
    assert.equal(packageJson.version, "1.3.0");
    assert.equal(pluginManifest.version, "1.3.0");
    assert.equal(pluginManifest.contracts.tools.length, 14);
    const files = new Set(packageJson.files);
    const candidatePaths = [
        "contracts/artifact-runtime-fingerprint-v1.schema.json",
        "contracts/fixtures/artifact-runtime-fingerprint-v1",
        "docs/adr/005B-exact-artifact-runtime-fingerprint.md",
        "tests/artifact-runtime-fingerprint.test.mjs",
        "tools/trustbridge/artifact-runtime-fingerprint.mjs",
    ];
    for (const candidatePath of candidatePaths) {
        assert.equal(
            [...files].some((entry) => candidatePath === entry
                || candidatePath.startsWith(`${entry}/`)),
            false,
            `${candidatePath} must remain outside the npm package`,
        );
    }
});

test("schema and engine agree on exact 005B profile and claim boundaries", () => {
    assert.equal(
        schema.properties.contract_version.const,
        FINGERPRINT_CONTRACT_VERSION,
    );
    assert.equal(
        schema.$defs.profiles.properties.directory_normalization.const,
        DIRECTORY_NORMALIZATION_PROFILE,
    );
    assert.equal(
        schema.$defs.claims.properties.archive_directory_correspondence_proven.const,
        false,
    );
    assert.equal(
        schema.$defs.claims.properties.file_modes_included.const,
        false,
    );
    assert.equal(
        schema.$defs.claims.properties.runtime_observation_source_verified.const,
        false,
    );
    assert.equal(
        schema.$defs.claims.properties.symlinks_allowed.const,
        false,
    );
    assert.equal(
        schema["x-noderooms-contract"].stable_package_identity_modified,
        false,
    );
});
