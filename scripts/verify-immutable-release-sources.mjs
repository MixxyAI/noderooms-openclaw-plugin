import { execFileSync } from "node:child_process";

const EXPECTED_RELEASE_TREES = Object.freeze({
    "release-source/1.3.0-beta.1":
        "43f43635714769503ae33677a45fc1c12beb2753",
    "release-source/1.3.0-beta.2":
        "056349783b36d969ce97868c82828f43645ba5af",
    "release-source/1.3.0":
        "9561e93d46b4cdf3a2d7e7d6f8e33780bc97bd80",
});

function git(...args) {
    return execFileSync("git", args, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
    }).trim();
}

for (const [path, expectedTree] of Object.entries(EXPECTED_RELEASE_TREES)) {
    let actualTree;
    try {
        actualTree = git("rev-parse", `HEAD:${path}`);
    } catch {
        throw new Error(`IMMUTABLE_RELEASE_SOURCE_MISSING: ${path}`);
    }
    if (actualTree !== expectedTree) {
        throw new Error(
            "IMMUTABLE_RELEASE_SOURCE_DRIFT: "
            + `${path} expected=${expectedTree} actual=${actualTree}`,
        );
    }
}

process.stdout.write(
    `IMMUTABLE_RELEASE_SOURCES=PASS count=${
        Object.keys(EXPECTED_RELEASE_TREES).length
    }\n`,
);
