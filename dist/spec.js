export const spec = {
    "id": "helm",
    "displayName": "Helm",
    "description": "Reviews Helm charts for excessive RBAC, mutable images, and unbounded dependencies.",
    "files": [
        "Chart.yaml",
        "**/Chart.yaml",
        "values.yaml",
        "**/values.yaml",
        "templates/*.yaml",
        "**/templates/*.yaml"
    ],
    "rules": [
        {
            "id": "helm.wildcard-rbac",
            "title": "Chart grants wildcard RBAC permissions",
            "summary": "Chart grants wildcard RBAC permissions",
            "category": "permissions",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Chart grants wildcard RBAC permissions weakens an important permissions boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Replace wildcards with exact namespaced resources and verbs.",
            "complexity": "small",
            "tags": [
                "permissions",
                "wildcard-rbac"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "templates/*.yaml",
                    "**/templates/*.yaml"
                ],
                "pattern": {
                    "pattern": "(?:verbs|resources):\\s*\\[[^\\]]*[\"']?\\*[\"']?",
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
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "Chart defaults an image tag to latest weakens an important supply-chain boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Default to a release version or digest.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "latest-default"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "values.yaml",
                    "**/values.yaml"
                ],
                "pattern": {
                    "pattern": "(?:tag|imageTag):\\s*[\"']?latest",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "helm.unbounded-dependency",
            "title": "Chart dependency uses an unbounded version",
            "summary": "Chart dependency uses an unbounded version",
            "category": "supply-chain",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "Chart dependency uses an unbounded version weakens an important supply-chain boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Pin chart dependencies and commit Chart.lock.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "unbounded-dependency"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "Chart.yaml",
                    "**/Chart.yaml"
                ],
                "pattern": {
                    "pattern": "version:\\s*[\"']?(?:\\*|>=|~|\\^|latest)",
                    "flags": "i"
                },
                "requires": []
            }
        }
    ]
};
