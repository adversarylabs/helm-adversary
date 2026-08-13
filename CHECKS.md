> **Shipped in 0.0.4:** , , , , , , , 
>
> Rules documented below that are not in that list are deferred (not yet in `src/spec.ts`).

# Checks — what helm detects

This file is the **public audit list** of detectors for the **helm** adversary. High-confidence Helm chart packaging and template defects—not a full Kubernetes runtime auditor of every rendered cluster (see `kubernetes` for raw manifests).

Runtime source of truth: [`src/spec.ts`](src/spec.ts) / [`src/rules.ts`](src/rules.ts).

**Scope:** `Chart.yaml`, `Chart.lock`, `values.yaml`, `values*.yaml`, and templates under `templates/**/*.yaml` (including `_helpers.tpl` only when RBAC/snippets appear).

**Precision stance:** Wildcard ClusterRole and cluster-admin bindings fire. Namespaced Roles with narrow verbs stay quiet. `:latest` defaults fire; digest-pinned values do not.

Public grounding: Helm RBAC docs, [Prisma “wildcard use is not minimized in Roles/ClusterRoles”](https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/ensure-minimized-wildcard-use-in-roles-and-clusterroles), Microsoft Defender blog on [insecure Helm chart defaults](https://techcommunity.microsoft.com/blog/microsoftdefendercloudblog/the-risk-of-default-configuration-how-out-of-the-box-helm-charts-can-breach-your/4409560), and chart audits showing `verbs: ["*"]` / `resources: ["*"]` patterns.

---

## Critical

### `helm.wildcard-rbac`

| | |
| --- | --- |
| **What** | Chart templates define Role/ClusterRole with wildcard verbs and resources |
| **Why** | Install grants near-admin API power to the release’s ServiceAccount |
| **Looks for** | Templates with `kind: ClusterRole` or `Role` containing `verbs: ["*"]` / `resources: ["*"]` / `apiGroups: ["*"]` combinations |
| **Stays quiet when** | Verbs and resources are enumerated; read-only list on non-sensitive resources without full `*` |
| **Public examples** | [Building and Breaking Secure Kubernetes Helm Charts](https://blog.devsecopsguides.com/p/building-and-breaking-secure-kubernetes) wildcard ClusterRole examples; Prisma/Cortex wildcard policies |
| **Remediation** | Replace wildcards with exact namespaced resources and verbs |

### `helm.cluster-admin-binding`

| | |
| --- | --- |
| **What** | Chart binds workloads to `cluster-admin` |
| **Why** | Any pod using the SA controls the cluster |
| **Looks for** | `ClusterRoleBinding` templates with `roleRef.name: cluster-admin` |
| **Stays quiet when** | Custom least-privilege ClusterRole used instead |
| **Public examples** | Kubernetes RBAC best practices; chart default over-permission findings |
| **Remediation** | Ship a minimal Role/ClusterRole for the app only |

### `helm.privileged-pod-default`

| | |
| --- | --- |
| **What** | Default values or templates set `privileged: true` or hostPath to docker.sock |
| **Why** | Default install becomes host-compromising |
| **Looks for** | `values.yaml` defaults or templates with `privileged: true`, hostPath `/var/run/docker.sock` |
| **Stays quiet when** | Privileged false/absent; no docker.sock |
| **Public examples** | [Out-of-the-box Helm chart risks](https://techcommunity.microsoft.com/blog/microsoftdefendercloudblog/the-risk-of-default-configuration-how-out-of-the-box-helm-charts-can-breach-your/4409560) |
| **Remediation** | Secure defaults; require explicit opt-in for privileged |

---

## High

### `helm.conditional-file-mount`

| | |
| --- | --- |
| **What** | A static file-valued container argument can render when its matching named volume mount or backing volume is disabled by an additional Helm values condition |
| **Why** | The process starts with a path argument for a file that is absent from its filesystem |
| **Looks for** | A literal absolute path in a file/path/cert/key/config flag, an exact covering `mountPath`, a matching volume name, and a provable positive-condition mismatch in the same rendered YAML document |
| **Stays quiet when** | The argument, mount, and volume share the same conditions; the mount is unconditional; names or paths do not match; or complex template flow prevents proving availability |
| **Remediation** | Share one requirement across the argument, volumeMount, and volume, or make the mount available whenever the argument renders |

### `helm.latest-default`

| | |
| --- | --- |
| **What** | Default image tag is `latest` or empty floating tag |
| **Why** | Non-reproducible installs; tag mutation |
| **Looks for** | `values.yaml` `image.tag: latest` or missing tag with repository only; templates rendering `:latest` |
| **Stays quiet when** | Default tag is semver or digest; values comment alone does not suppress |
| **Public examples** | Chart supply-chain guidance; same class as k8s mutable images |
| **Remediation** | Default to a release version or digest |

### `helm.secrets-in-values`

| | |
| --- | --- |
| **What** | Default `values.yaml` contains password/token/key literals |
| **Why** | Charts are copied; defaults become committed secrets |
| **Looks for** | values keys like `password`, `apiKey`, `secret`, `token` with non-empty default strings that look real (length/entropy), not empty or `changeme` placeholders that are clearly docs—still fire on long high-entropy defaults |
| **Stays quiet when** | Empty string defaults, `null`, or explicit `""` requiring override; `existingSecret` pattern |
| **Public examples** | Chart secret-in-values incidents; Bitnami-style `existingSecret` pattern as good contrast |
| **Remediation** | Use `existingSecret`; never ship real credentials as defaults |

### `helm.create-clusterrole-default-true`

| | |
| --- | --- |
| **What** | Values default `rbac.create: true` with cluster-wide permissions for simple apps |
| **Why** | Users install with cluster-scoped power unintentionally |
| **Looks for** | ClusterRole templates gated only by `rbac.create` defaulting true **and** rules are wildcard/admin-level |
| **Stays quiet when** | Namespaced Role only; or cluster permissions clearly required (operators) with narrow rules |
| **Public examples** | Helm chart RBAC overprivilege studies |
| **Remediation** | Prefer namespaced Roles; document when ClusterRole is required |

### `helm.unbounded-dependency`

| | |
| --- | --- |
| **What** | `Chart.yaml` dependencies lack version pins or Chart.lock |
| **Why** | Dependent charts can move under you |
| **Looks for** | `dependencies:` entries without `version`, or version `*` / `>0.0.0`; missing `Chart.lock` when dependencies exist |
| **Stays quiet when** | Versions pinned and `Chart.lock` committed |
| **Public examples** | Helm dependency docs; lockfile reproducibility |
| **Remediation** | Pin chart dependencies and commit Chart.lock |

### `helm.rbac-secrets-cluster-read`

| | |
| --- | --- |
| **What** | ClusterRole grants read access to Secrets cluster-wide |
| **Why** | `get/list/watch` on all secrets is effectively cluster takeover — every ServiceAccount token and credential becomes readable |
| **Looks for** | `ClusterRole` rules with `resources: ["secrets"]` and verbs including `get`, `list`, `watch`, or `*` |
| **Stays quiet when** | Namespaced `Role` scoped to the release namespace; rules restricted with `resourceNames` |
| **Public examples** | Kubernetes RBAC good practices call out cluster-wide secrets read; common chart-audit finding |
| **Remediation** | Use a namespaced Role, restrict with `resourceNames`, or mount only the release’s own secrets |

---

## Medium

### `helm.capabilities-add-without-drop-all`

| | |
| --- | --- |
| **What** | A chart explicitly adds Linux capabilities without dropping the runtime defaults |
| **Why** | The container receives both the requested capability and the runtime default capability set, which is broader than the chart communicates |
| **Looks for** | `capabilities` blocks in changed values or templates with non-empty `add` entries and no `drop: ["ALL"]` in that same block |
| **Stays quiet when** | The block drops `ALL`; only drops capabilities; or capability text appears only in comments |
| **Public examples** | Istio PR #53478 restored `drop: ALL` after maintainer review when explicit capabilities remained |
| **Remediation** | Drop `ALL`, then add back only the capabilities the workload requires |

### `helm.hook-privileged`

| | |
| --- | --- |
| **What** | Hook Jobs run privileged or mount host paths |
| **Why** | Hooks still execute with release identity |
| **Looks for** | `"helm.sh/hook"` annotations on privileged pods |
| **Stays quiet when** | Hooks are non-privileged Jobs |
| **Public examples** | Helm hooks security discussions |
| **Remediation** | Harden hook pods like any workload |

---

## Out of scope

| Concern | Owner |
| --- | --- |
| Raw Kubernetes manifests outside charts | `kubernetes` |
| Terraform helm provider resources | `terraform` |
| Generic secret scanning of all files | `security/secrets` |
| Dockerfile for chart build tooling | `container/dockerfile` |
