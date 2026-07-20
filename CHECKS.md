# Initial checks

## helm.wildcard-rbac

- Severity: high
- Category: permissions
- Recommendation: Replace wildcards with exact namespaced resources and verbs.

## helm.latest-default

- Severity: medium
- Category: supply-chain
- Recommendation: Default to a release version or digest.

## helm.unbounded-dependency

- Severity: medium
- Category: supply-chain
- Recommendation: Pin chart dependencies and commit Chart.lock.

