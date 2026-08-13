export const spec = {
    "id": "helm",
    "displayName": "Helm",
    "description": "Reviews Helm charts for excessive RBAC, privileged defaults, mutable images, and dependency pinning.",
    "files": [
        "Chart.yaml",
        "**/Chart.yaml",
        "Chart.lock",
        "**/Chart.lock",
        "values.yaml",
        "**/values.yaml",
        "templates/*.yaml",
        "**/templates/*.yaml",
        "templates/*.yml",
        "**/templates/*.yml"
    ],
    "rules": [
        {
            "id": "helm.wildcard-rbac",
            "title": "Chart grants wildcard RBAC permissions",
            "summary": "Chart grants wildcard RBAC permissions",
            "category": "permissions",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "Wildcard RBAC grants near-admin API power to the release SA.",
            "impact": "Compromised pod escalates to broad cluster or namespace control.",
            "recommendation": "Replace wildcards with exact namespaced resources and verbs.",
            "complexity": "small",
            "tags": [
                "permissions",
                "rbac"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "templates/*.yaml",
                    "**/templates/*.yaml",
                    "templates/*.yml",
                    "**/templates/*.yml"
                ],
                "pattern": {
                    "pattern": "(?:verbs|resources):\\s*\\[[^\\]]*[\\\"']?\\*[\\\"']?",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "helm.cluster-admin-binding",
            "title": "Chart binds workloads to cluster-admin",
            "summary": "Chart binds workloads to cluster-admin",
            "category": "permissions",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "Any pod using the SA controls the cluster.",
            "impact": "Full cluster takeover from the release.",
            "recommendation": "Ship a minimal Role/ClusterRole for the app only.",
            "complexity": "small",
            "tags": [
                "permissions",
                "cluster-admin"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "templates/*.yaml",
                    "**/templates/*.yaml",
                    "templates/*.yml",
                    "**/templates/*.yml"
                ],
                "pattern": {
                    "pattern": "kind:\\s*ClusterRoleBinding[\\s\\S]{0,300}name:\\s*cluster-admin",
                    "flags": "i"
                },
                "anchors": [
                    {
                        "pattern": "kind:\\s*ClusterRoleBinding",
                        "flags": "i"
                    },
                    {
                        "pattern": "name:\\s*cluster-admin",
                        "flags": "i"
                    }
                ],
                "requires": []
            }
        },
        {
            "id": "helm.privileged-pod-default",
            "title": "Chart defaults privileged or docker.sock hostPath",
            "summary": "Chart defaults privileged or docker.sock hostPath",
            "category": "security",
            "severity": "critical",
            "confidence": "high",
            "whyItMatters": "Default install becomes host-compromising.",
            "impact": "Host root via privileged container or docker socket.",
            "recommendation": "Secure defaults; require explicit opt-in for privileged.",
            "complexity": "small",
            "tags": [
                "security",
                "privileged"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "values.yaml",
                    "**/values.yaml",
                    "templates/*.yaml",
                    "**/templates/*.yaml"
                ],
                "pattern": {
                    "pattern": "privileged:\\s*true|/var/run/docker\\.sock",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "helm.latest-default",
            "title": "Chart defaults an image tag to latest",
            "summary": "Chart defaults an image tag to latest",
            "category": "supply-chain",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Floating tags make installs non-reproducible.",
            "impact": "Unexpected image content on upgrade/redeploy.",
            "recommendation": "Default to a release version or digest.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "image"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "values.yaml",
                    "**/values.yaml"
                ],
                "pattern": {
                    "pattern": "(?:tag|imageTag):\\s*[\\\"']?latest\\b",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "helm.root-security-context-default",
            "title": "Chart defaults containers to run as root",
            "summary": "Chart defaults containers to run as root",
            "category": "security",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "A root-enabling security context in values.yaml applies to chart installations unless every operator overrides it.",
            "impact": "A compromised workload runs with greater privileges and has a larger container-escape blast radius.",
            "recommendation": "Default to runAsNonRoot: true and a non-zero user; require an explicit opt-in for components that must run as root.",
            "complexity": "small",
            "tags": [
                "security",
                "root",
                "defaults"
            ],
            "match": {
                "kind": "indented-block-content",
                "files": [
                    "values.yaml",
                    "**/values.yaml"
                ],
                "blockStart": {
                    "pattern": "^[ \\t]*(?:(?:container|pod)SecurityContext|securityContext):\\s*$",
                    "flags": "im"
                },
                "pattern": {
                    "pattern": "(?:runAsUser:\\s*0\\b|runAsNonRoot:\\s*false\\b)",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "helm.secrets-in-values",
            "title": "Default values contain credential-like literals",
            "summary": "Default values contain credential-like literals",
            "category": "secrets",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Charts are copied; defaults become committed secrets.",
            "impact": "Credential leakage via values.yaml.",
            "recommendation": "Use existingSecret; never ship real credentials as defaults.",
            "complexity": "small",
            "tags": [
                "secrets",
                "values"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "values.yaml",
                    "**/values.yaml"
                ],
                "pattern": {
                    "pattern": "(?:password|apiKey|api_key|secret|token|privateKey):\\s*[\\\"'][A-Za-z0-9/+=_\\-]{12,}[\\\"']",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "helm.unbounded-dependency",
            "title": "Chart dependency missing version or Chart.lock",
            "summary": "Chart dependency missing version or Chart.lock",
            "category": "supply-chain",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Dependent charts can move under you.",
            "impact": "Non-reproducible chart installs.",
            "recommendation": "Pin chart dependencies and commit Chart.lock.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "deps"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "Chart.yaml",
                    "**/Chart.yaml"
                ],
                "pattern": {
                    "pattern": "version:\\s*[\\\"']?\\*",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "helm.rbac-secrets-cluster-read",
            "title": "ClusterRole can read secrets cluster-wide",
            "summary": "ClusterRole can read secrets cluster-wide",
            "category": "permissions",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Cluster-wide secrets read is effectively takeover of credentials.",
            "impact": "Every SA token and secret becomes readable.",
            "recommendation": "Use a namespaced Role or resourceNames restrictions.",
            "complexity": "small",
            "tags": [
                "permissions",
                "secrets"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "templates/*.yaml",
                    "**/templates/*.yaml"
                ],
                "pattern": {
                    "pattern": "kind:\\s*ClusterRole[\\s\\S]{0,400}resources:\\s*\\[[^\\]]*secrets[^\\]]*\\][\\s\\S]{0,120}verbs:\\s*\\[[^\\]]*(?:get|list|watch|\\*)",
                    "flags": "i"
                },
                "anchors": [
                    {
                        "pattern": "kind:\\s*ClusterRole",
                        "flags": "i"
                    },
                    {
                        "pattern": "resources:\\s*\\[[^\\]]*secrets[^\\]]*\\]",
                        "flags": "i"
                    },
                    {
                        "pattern": "verbs:\\s*\\[[^\\]]*(?:get|list|watch|\\*)",
                        "flags": "i"
                    }
                ],
                "requires": []
            }
        },
        {
            "id": "helm.hook-privileged",
            "title": "Helm hook runs privileged",
            "summary": "Helm hook runs privileged",
            "category": "security",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "Hooks still execute with release identity.",
            "impact": "Privileged hook pods compromise the host.",
            "recommendation": "Harden hook pods like any workload.",
            "complexity": "small",
            "tags": [
                "security",
                "hooks"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "templates/*.yaml",
                    "**/templates/*.yaml"
                ],
                "pattern": {
                    "pattern": "helm\\.sh/hook[\\\"']?[^\\n]*\\n[\\s\\S]{0,400}privileged:\\s*true",
                    "flags": "i"
                },
                "anchors": [
                    {
                        "pattern": "helm\\.sh/hook[\\\"']?[^\\n]*",
                        "flags": "i"
                    },
                    {
                        "pattern": "privileged:\\s*true",
                        "flags": "i"
                    }
                ],
                "requires": []
            }
        },
        {
            "id": "helm.selector-label-override",
            "title": "Custom pod labels can override workload selectors",
            "summary": "Custom pod labels can override workload selectors",
            "category": "correctness",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Rendering selector labels and user-controlled pod labels separately can create duplicate YAML keys or change a selector key only on the pod template.",
            "impact": "The rendered workload can be rejected or its pod template can stop matching the immutable workload selector.",
            "recommendation": "Merge custom and selector label maps before rendering them, with selector labels taking precedence.",
            "complexity": "small",
            "tags": [
                "helm",
                "kubernetes",
                "selectors",
                "labels"
            ],
            "match": {
                "kind": "selector-label-override",
                "files": [
                    "templates/*.yaml",
                    "**/templates/*.yaml",
                    "templates/*.yml",
                    "**/templates/*.yml"
                ]
            }
        },
        {
            "id": "helm.conditional-file-mount",
            "title": "File argument can render without its mounted file",
            "summary": "A container file argument is available under broader values than its matching volume mount",
            "category": "correctness",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Helm can render the file-valued argument while omitting the volume mount or backing volume that provides that path.",
            "impact": "The container can fail at startup when it tries to open a file that was not mounted.",
            "recommendation": "Gate the argument, matching volumeMount, and backing volume with the same requirement, or make the mount available whenever the argument renders.",
            "complexity": "small",
            "tags": [
                "helm",
                "kubernetes",
                "volumes",
                "templates",
                "correctness"
            ],
            "match": {
                "kind": "conditional-file-mount",
                "files": [
                    "templates/*.yaml",
                    "**/templates/*.yaml",
                    "templates/*.yml",
                    "**/templates/*.yml"
                ]
            }
        },
        {
            "id": "helm.capabilities-add-without-drop-all",
            "title": "Chart adds Linux capabilities without dropping runtime defaults",
            "summary": "Chart adds Linux capabilities without dropping runtime defaults",
            "category": "security",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "Adding a capability without first dropping ALL preserves the container runtime default capability set as well as the requested capability.",
            "impact": "The rendered workload receives broader kernel privileges than the chart configuration communicates.",
            "recommendation": "Add drop: [\"ALL\"] in the same capabilities block, then add back only the capabilities the workload requires.",
            "complexity": "small",
            "tags": [
                "security",
                "capabilities",
                "defaults"
            ],
            "match": {
                "kind": "indented-block-missing-content",
                "files": [
                    "values.yaml",
                    "**/values.yaml",
                    "templates/*.yaml",
                    "**/templates/*.yaml",
                    "templates/*.yml",
                    "**/templates/*.yml"
                ],
                "blockStart": {
                    "pattern": "^[ \\t]*capabilities:\\s*$",
                    "flags": "im"
                },
                "trigger": {
                    "pattern": "^[ \\t]*add:\\s*(?:\\[[^\\]\\r\\n]*[A-Za-z0-9_][^\\]\\r\\n]*\\]|(?:\\r?\\n[ \\t]+-[ \\t]*[\\\"']?[A-Za-z0-9_]))",
                    "flags": "im"
                },
                "required": {
                    "pattern": "^[ \\t]*drop:\\s*(?:\\[[^\\]\\r\\n]*[\\\"']?ALL[\\\"']?[^\\]\\r\\n]*\\]|(?:\\r?\\n[ \\t]+-[ \\t]*[\\\"']?ALL[\\\"']?[ \\t]*(?:#.*)?$))",
                    "flags": "im"
                }
            }
        }
    ]
};
