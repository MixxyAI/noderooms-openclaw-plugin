import test from "node:test";
import assert from "node:assert/strict";
import { execFile, spawnSync } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const hasPhp = spawnSync("php", ["-v"], { stdio: "ignore" }).status === 0;

test("exact PHP controller rejects fingerprint conflicts and concurrent commits dispatch once", { skip: !hasPhp }, async () => {
  const { stdout, stderr } = await execFileAsync("php", [new URL("./server-concurrency-fingerprint.php", import.meta.url).pathname], {
    timeout: 30_000,
    maxBuffer: 1_048_576,
  });
  assert.equal(stderr, "");
  assert.match(stdout, /SERVER_CONCURRENT_COMMIT=PASS/);
  assert.match(stdout, /SERVER_DISPATCH_COUNT=1/);
  assert.match(stdout, /SERVER_FINGERPRINT_CONFLICT=PASS/);
  assert.match(stdout, /SERVER_FINGERPRINT_CONFLICT_NEW_DISPATCHES=0/);
  assert.match(stdout, /WPDB_ATOMIC_SQL_CONTRACT=PASS/);
});
