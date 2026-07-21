# Helm adversary

Reviews Helm charts for excessive RBAC, mutable images, and unbounded dependencies.

## Checks

- **Chart grants wildcard RBAC permissions:** Replace wildcards with exact namespaced resources and verbs.
- **Chart defaults an image tag to latest:** Default to a release version or digest.
- **Chart dependency uses an unbounded version:** Pin chart dependencies and commit Chart.lock.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```

## Automatic detection

`adversary auto` selects the helm adversary when changes include `Chart.yaml` or `**/Chart.yaml`, plus the other domain-specific patterns declared in `adversary.yaml`. Unrelated changes do not select it.
