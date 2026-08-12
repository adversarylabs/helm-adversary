import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

test("an unrelated edit does not surface a legacy Helm finding", async () => {
  const repo = await committedRepository({
    "values.yaml": valuesSource("latest", "old diagnostic"),
  });
  await writeFile(join(repo, "values.yaml"), valuesSource("latest", "new diagnostic"));

  const output = await changedReview(repo, ["values.yaml"]);

  assert.equal(
    output.findings.some((finding) => finding.ruleId === "helm.latest-default"),
    false,
  );
});

test("a direct finding on a changed line remains eligible", async () => {
  const repo = await committedRepository({
    "values.yaml": valuesSource("1.2.3", "unchanged"),
  });
  await writeFile(join(repo, "values.yaml"), valuesSource("latest", "unchanged"));

  const output = await changedReview(repo, ["values.yaml"]);

  const finding = output.findings.find((item) => item.ruleId === "helm.latest-default");
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.line, 3);
});

test("unchanged block context supports a changed trigger anchor", async () => {
  const original = capabilitiesSource("drop: [\"NET_RAW\"]");
  const updated = capabilitiesSource("add: [\"NET_ADMIN\"]");
  const repo = await committedRepository({ "values.yaml": original });
  await writeFile(join(repo, "values.yaml"), updated);

  const output = await changedReview(repo, ["values.yaml"]);

  const finding = output.findings.find(
    (item) => item.ruleId === "helm.capabilities-add-without-drop-all",
  );
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.line, 4);
});

test("unchanged hook context supports a changed privileged anchor", async () => {
  const repo = await committedRepository({
    "templates/hook.yaml": hookSource(false),
  });
  await writeFile(join(repo, "templates/hook.yaml"), hookSource(true));

  const output = await changedReview(repo, ["templates/hook.yaml"]);

  const finding = output.findings.find((item) => item.ruleId === "helm.hook-privileged");
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.line, 14);
});

test("an unrelated line inside a multiline rule does not reactivate a legacy hook", async () => {
  const original = hookSource(true);
  const repo = await committedRepository({ "templates/hook.yaml": original });
  await writeFile(
    join(repo, "templates/hook.yaml"),
    original.replace("image: migrate:1", "image: migrate:2"),
  );

  const output = await changedReview(repo, ["templates/hook.yaml"]);

  assert.equal(
    output.findings.some((finding) => finding.ruleId === "helm.hook-privileged"),
    false,
  );
});

test("unchanged label context supports a changed selector-helper anchor", async () => {
  const original = selectorTemplate("example.commonLabels");
  const repo = await committedRepository({ "templates/deployment.yaml": original });
  await writeFile(
    join(repo, "templates/deployment.yaml"),
    selectorTemplate("example.selectorLabels"),
  );

  const output = await changedReview(repo, ["templates/deployment.yaml"]);

  const finding = output.findings.find((item) => item.ruleId === "helm.selector-label-override");
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.line, 14);
});

test("an added manifest remains eligible in full", async () => {
  const repo = await committedRepository({ "Chart.yaml": "apiVersion: v2\nname: fixture\n" });
  await writeRepositoryFile(repo, "values.yaml", valuesSource("latest", "added"));

  const output = await changedReview(repo, ["values.yaml"]);

  assert.equal(
    output.findings.some((finding) => finding.ruleId === "helm.latest-default"),
    true,
  );
});

test("an all-files review remains eligible in full", async () => {
  const repo = await committedRepository({
    "values.yaml": valuesSource("latest", "old diagnostic"),
  });
  await writeFile(join(repo, "values.yaml"), valuesSource("latest", "new diagnostic"));

  const output = await createApp().run({
    input: {
      source: { path: repo },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "all",
        changed_files: ["values.yaml"],
      },
    },
  });

  assert.equal(
    output.findings.some((finding) => finding.ruleId === "helm.latest-default"),
    true,
  );
});

async function committedRepository(files: Record<string, string>): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "helm-adversary-scope-"));
  await execute("git", ["init", "--quiet"], { cwd: repo });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repo });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repo });
  for (const [path, source] of Object.entries(files)) {
    await writeRepositoryFile(repo, path, source);
  }
  await execute("git", ["add", "."], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repo });
  return repo;
}

async function writeRepositoryFile(repo: string, path: string, source: string): Promise<void> {
  await mkdir(join(repo, dirname(path)), { recursive: true });
  await writeFile(join(repo, path), source);
}

async function changedReview(repoPath: string, changedFiles: string[]) {
  return createApp().run({
    input: {
      source: { path: repoPath },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
  });
}

function valuesSource(tag: string, diagnostic: string): string {
  return `image:
  repository: example/app
  tag: ${tag}

diagnostic: ${diagnostic}
`;
}

function capabilitiesSource(entry: string): string {
  return `sidecar:
  securityContext:
    capabilities:
      ${entry}
`;
}

function hookSource(privileged: boolean): string {
  return `apiVersion: batch/v1
kind: Job
metadata:
  name: migrate
  annotations:
    "helm.sh/hook": pre-install
spec:
  template:
    spec:
      containers:
        - name: migrate
          image: migrate:1
          securityContext:
            privileged: ${privileged}
`;
}

function selectorTemplate(helper: string): string {
  return `apiVersion: apps/v1
kind: Deployment
metadata:
  name: example
spec:
  selector:
    matchLabels:
      {{ include "example.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        app: example
        tier: backend
        {{ include "${helper}" . | nindent 8 }}
      {{- with .Values.podLabels }}
        {{ toYaml . | nindent 8 }}
      {{- end }}
`;
}
