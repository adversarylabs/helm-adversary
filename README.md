# helm

**helm** reviews Helm charts for **wildcard RBAC, privileged defaults, floating image tags, secrets in values, and unpinned chart dependencies**.

It is a **chart packaging reviewer**, not a full cluster scanner of rendered objects (see `kubernetes` for raw manifests). When it reports, a default install is likely over-privileged or non-reproducible.

## What it does

1. **Discovers** Chart.yaml, values, and templates.
2. **Runs deterministic detectors** for RBAC, securityContext defaults, images, and deps.
3. **Synthesizes a review** with file:line evidence.
4. Optionally **enhances** with a model when provided.

It never executes the scanned project as the product under review, never installs dependencies into it, and never needs network access to the target repository.

## What it detects

Every **shipped rule id**, severity, and short description lives in **[CHECKS.md](CHECKS.md)**.

Highlights:

| Area | Examples |
| --- | --- |
| RBAC | verbs/resources *; cluster-admin bindings; cluster-wide secrets read |
| Defaults | privileged: true; docker.sock; tag: latest |
| Secrets | password/apiKey literals in values.yaml |
| Deps | unbounded chart dependency versions |

### Ownership boundaries

| Concern | Owned by |
| --- | --- |
| Raw Kubernetes manifests | [`kubernetes`](https://github.com/adversarylabs/kubernetes-adversary) |
| Terraform helm provider | [`terraform`](https://github.com/adversarylabs/terraform-adversary) |
| Generic secret scanning | [`security/secrets`](https://github.com/adversarylabs/secrets-adversary) |

## Precision stance

- **High confidence** only for deterministic, evidence-backed patterns.
- Clean fixtures must stay quiet; vulnerable fixtures must fire.
- Prefer missing a weak signal over a false positive on normal production code.
