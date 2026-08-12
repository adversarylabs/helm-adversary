import assert from "node:assert/strict";
import test from "node:test";
import { createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const fixture = (name: string) => new URL(`../fixtures/${name}`, import.meta.url).pathname;
const review = (name: string, raw = false) => createApp().run({ input: { source: { path: fixture(name) } }, includeRawObservations: raw });
const ruleCases = [{"key": "wildcard-rbac", "id": "helm.wildcard-rbac"}, {"key": "cluster-admin-binding", "id": "helm.cluster-admin-binding"}, {"key": "privileged-pod-default", "id": "helm.privileged-pod-default"}, {"key": "latest-default", "id": "helm.latest-default"}, {"key": "root-security-context-default", "id": "helm.root-security-context-default"}, {"key": "secrets-in-values", "id": "helm.secrets-in-values"}, {"key": "unbounded-dependency", "id": "helm.unbounded-dependency"}, {"key": "rbac-secrets-cluster-read", "id": "helm.rbac-secrets-cluster-read"}, {"key": "hook-privileged", "id": "helm.hook-privileged"}, {"key": "capabilities-add-without-drop-all", "id": "helm.capabilities-add-without-drop-all"}];

test("every shipped rule has focused vulnerable and clean coverage", async () => {
  for (const rule of ruleCases) {
    const vulnerable = await review(`rules/${rule.key}/vulnerable`, true);
    assert.equal(vulnerable.findings.some((finding) => finding.ruleId === rule.id), true, `${rule.id} did not detect its vulnerable fixture`);
    assert.equal(vulnerable.rawObservations?.every((item) => item.location?.file !== undefined), true);
    const clean = await review(`rules/${rule.key}/clean`);
    assert.equal(clean.findings.some((finding) => finding.ruleId === rule.id), false, `${rule.id} flagged its clean fixture`);
  }
});

test("accepts a repository without applicable configuration", async () => {
  const output = await review("clean");
  assert.deepEqual(output.findings, []);
  assert.equal(output.assessment?.risk, "none");
  assert.equal(output.opinion?.ship, true);
});

test("anchors capability additions across values, templates, and partial drops", async () => {
  const output = await review("rules/capabilities-add-without-drop-all/vulnerable", true);
  const observations = output.rawObservations?.filter(
    (item) => item.ruleId === "helm.capabilities-add-without-drop-all",
  );
  assert.deepEqual(observations?.map((item) => ({
    file: item.location?.file,
    line: item.location?.line,
  })), [
    { file: "templates/daemonset.yaml", line: 12 },
    { file: "values.yaml", line: 4 },
    { file: "values.yaml", line: 10 },
  ]);
});

test("output ordering and protocol envelope are deterministic", async () => {
  const first = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  const second = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  assert.deepEqual(second, first);
  const envelope = JSON.parse(JSON.stringify(createAdversaryRunEnvelope(first)));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "helm");
});
