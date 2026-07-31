import { type Confidence, type Severity } from "@adversarylabs/sdk";

export interface MatchExpression { pattern: string; flags: string }
interface ContentMatch { kind: "content"; files: string[]; pattern: MatchExpression; requires: MatchExpression[] }
interface MissingContentMatch { kind: "missing-content"; files: string[]; trigger: MatchExpression; required: MatchExpression }
interface MissingFileMatch { kind: "missing-file"; triggerFiles: string[]; requiredFiles: string[] }
export interface RuleSpec {
  id: string; title: string; summary: string; category: string; severity: Severity; confidence: Confidence;
  whyItMatters: string; impact: string; recommendation: string; complexity: "trivial" | "small" | "medium" | "large"; tags: string[];
  match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec { id: string; displayName: string; description: string; files: string[]; rules: RuleSpec[] }

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
        "requires": []
      }
    }
  ]
} as const satisfies AdversarySpec;
