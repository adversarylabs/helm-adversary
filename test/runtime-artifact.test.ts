import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execute = promisify(execFile);
const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));

test("the published runtime executes without node_modules", async () => {
  const artifact = await mkdtemp(join(tmpdir(), "helm-artifact-"));
  const repository = await mkdtemp(join(tmpdir(), "helm-target-"));
  const entrypoint = join(artifact, "dist", "index.js");
  const input = join(artifact, "input.json");
  const output = join(artifact, "output.json");

  await mkdir(dirname(entrypoint), { recursive: true });
  await mkdir(join(artifact, "schemas"), { recursive: true });
  await copyFile(join(projectRoot, "dist", "index.js"), entrypoint);
  await copyFile(
    join(projectRoot, "schemas", "adversary.review.v1.schema.json"),
    join(artifact, "schemas", "adversary.review.v1.schema.json"),
  );
  await writeFile(join(artifact, "package.json"), '{"type":"module"}\n');
  await writeFile(join(repository, "Chart.yaml"), "apiVersion: v2\nname: sample\nversion: 0.1.0\n");
  await writeFile(input, `${JSON.stringify({ source: { path: repository } })}\n`);

  const bundle = await readFile(entrypoint, "utf8");
  assert.doesNotMatch(bundle, /from\s+["']@adversarylabs\/sdk["']/);
  assert.doesNotMatch(bundle, /\/Users\/marc|\/private\/tmp\/helm-runtime-version-fix/);

  await execute(process.execPath, [entrypoint], {
    cwd: artifact,
    env: {
      ...process.env,
      ADVERSARY_INPUT: input,
      ADVERSARY_OUTPUT: output,
      ADVERSARY_REPO: repository,
    },
  });

  const envelope = JSON.parse(await readFile(output, "utf8"));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "helm");
  assert.equal(envelope.result.adversary.version, "0.0.13");
});
