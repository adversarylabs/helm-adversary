# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `helm.capabilities-add-without-drop-all` | Medium | A chart explicitly adds Linux capabilities without dropping the runtime defaults |
| `helm.cluster-admin-binding` | Critical | Chart binds workloads to `cluster-admin` |
| `helm.conditional-file-mount` | High | A static file-valued item under a container's `args` or `command` can render when that same container's matching named volume mount or the pod's backing volume is disabled by an additional Helm values condition |
| `helm.hook-privileged` | Medium | Hook Jobs run privileged or mount host paths |
| `helm.latest-default` | High | Default image tag is `latest` or empty floating tag |
| `helm.privileged-pod-default` | Critical | Default values or templates set `privileged: true` or hostPath to docker.sock |
| `helm.rbac-secrets-cluster-read` | High | ClusterRole grants read access to Secrets cluster-wide |
| `helm.root-security-context-default` | High | Chart defaults containers to run as root |
| `helm.secrets-in-values` | High | Default `values.yaml` contains password/token/key literals |
| `helm.selector-label-override` | High | Custom pod labels can override workload selectors |
| `helm.unbounded-dependency` | High | `Chart.yaml` dependencies lack version pins or Chart.lock |
| `helm.wildcard-rbac` | Critical | Chart templates define Role/ClusterRole with wildcard verbs and resources |
