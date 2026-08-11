import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
    requires: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
    required: MatchExpression;
}
interface IndentedBlockContentMatch {
    kind: "indented-block-content";
    files: string[];
    blockStart: MatchExpression;
    pattern: MatchExpression;
    requires: MatchExpression[];
}
interface MissingFileMatch {
    kind: "missing-file";
    triggerFiles: string[];
    requiredFiles: string[];
}
export interface RuleSpec {
    id: string;
    title: string;
    summary: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    whyItMatters: string;
    impact: string;
    recommendation: string;
    complexity: "trivial" | "small" | "medium" | "large";
    tags: string[];
    match: ContentMatch | MissingContentMatch | IndentedBlockContentMatch | MissingFileMatch;
}
export interface AdversarySpec {
    id: string;
    displayName: string;
    description: string;
    files: string[];
    rules: RuleSpec[];
}
export declare const spec: {
    readonly id: "helm";
    readonly displayName: "Helm";
    readonly description: "Reviews Helm charts for excessive RBAC, privileged defaults, mutable images, and dependency pinning.";
    readonly files: ["Chart.yaml", "**/Chart.yaml", "Chart.lock", "**/Chart.lock", "values.yaml", "**/values.yaml", "templates/*.yaml", "**/templates/*.yaml", "templates/*.yml", "**/templates/*.yml"];
    readonly rules: [{
        readonly id: "helm.wildcard-rbac";
        readonly title: "Chart grants wildcard RBAC permissions";
        readonly summary: "Chart grants wildcard RBAC permissions";
        readonly category: "permissions";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Wildcard RBAC grants near-admin API power to the release SA.";
        readonly impact: "Compromised pod escalates to broad cluster or namespace control.";
        readonly recommendation: "Replace wildcards with exact namespaced resources and verbs.";
        readonly complexity: "small";
        readonly tags: ["permissions", "rbac"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["templates/*.yaml", "**/templates/*.yaml", "templates/*.yml", "**/templates/*.yml"];
            readonly pattern: {
                readonly pattern: "(?:verbs|resources):\\s*\\[[^\\]]*[\\\"']?\\*[\\\"']?";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "helm.cluster-admin-binding";
        readonly title: "Chart binds workloads to cluster-admin";
        readonly summary: "Chart binds workloads to cluster-admin";
        readonly category: "permissions";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Any pod using the SA controls the cluster.";
        readonly impact: "Full cluster takeover from the release.";
        readonly recommendation: "Ship a minimal Role/ClusterRole for the app only.";
        readonly complexity: "small";
        readonly tags: ["permissions", "cluster-admin"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["templates/*.yaml", "**/templates/*.yaml", "templates/*.yml", "**/templates/*.yml"];
            readonly pattern: {
                readonly pattern: "kind:\\s*ClusterRoleBinding[\\s\\S]{0,300}name:\\s*cluster-admin";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "helm.privileged-pod-default";
        readonly title: "Chart defaults privileged or docker.sock hostPath";
        readonly summary: "Chart defaults privileged or docker.sock hostPath";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Default install becomes host-compromising.";
        readonly impact: "Host root via privileged container or docker socket.";
        readonly recommendation: "Secure defaults; require explicit opt-in for privileged.";
        readonly complexity: "small";
        readonly tags: ["security", "privileged"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["values.yaml", "**/values.yaml", "templates/*.yaml", "**/templates/*.yaml"];
            readonly pattern: {
                readonly pattern: "privileged:\\s*true|/var/run/docker\\.sock";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "helm.latest-default";
        readonly title: "Chart defaults an image tag to latest";
        readonly summary: "Chart defaults an image tag to latest";
        readonly category: "supply-chain";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Floating tags make installs non-reproducible.";
        readonly impact: "Unexpected image content on upgrade/redeploy.";
        readonly recommendation: "Default to a release version or digest.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "image"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["values.yaml", "**/values.yaml"];
            readonly pattern: {
                readonly pattern: "(?:tag|imageTag):\\s*[\\\"']?latest\\b";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "helm.root-security-context-default";
        readonly title: "Chart defaults containers to run as root";
        readonly summary: "Chart defaults containers to run as root";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "A root-enabling security context in values.yaml applies to chart installations unless every operator overrides it.";
        readonly impact: "A compromised workload runs with greater privileges and has a larger container-escape blast radius.";
        readonly recommendation: "Default to runAsNonRoot: true and a non-zero user; require an explicit opt-in for components that must run as root.";
        readonly complexity: "small";
        readonly tags: ["security", "root", "defaults"];
        readonly match: {
            readonly kind: "indented-block-content";
            readonly files: ["values.yaml", "**/values.yaml"];
            readonly blockStart: {
                readonly pattern: "^[ \\t]*(?:(?:container|pod)SecurityContext|securityContext):\\s*$";
                readonly flags: "im";
            };
            readonly pattern: {
                readonly pattern: "(?:runAsUser:\\s*0\\b|runAsNonRoot:\\s*false\\b)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "helm.secrets-in-values";
        readonly title: "Default values contain credential-like literals";
        readonly summary: "Default values contain credential-like literals";
        readonly category: "secrets";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Charts are copied; defaults become committed secrets.";
        readonly impact: "Credential leakage via values.yaml.";
        readonly recommendation: "Use existingSecret; never ship real credentials as defaults.";
        readonly complexity: "small";
        readonly tags: ["secrets", "values"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["values.yaml", "**/values.yaml"];
            readonly pattern: {
                readonly pattern: "(?:password|apiKey|api_key|secret|token|privateKey):\\s*[\\\"'][A-Za-z0-9/+=_\\-]{12,}[\\\"']";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "helm.unbounded-dependency";
        readonly title: "Chart dependency missing version or Chart.lock";
        readonly summary: "Chart dependency missing version or Chart.lock";
        readonly category: "supply-chain";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Dependent charts can move under you.";
        readonly impact: "Non-reproducible chart installs.";
        readonly recommendation: "Pin chart dependencies and commit Chart.lock.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "deps"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["Chart.yaml", "**/Chart.yaml"];
            readonly pattern: {
                readonly pattern: "version:\\s*[\\\"']?\\*";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "helm.rbac-secrets-cluster-read";
        readonly title: "ClusterRole can read secrets cluster-wide";
        readonly summary: "ClusterRole can read secrets cluster-wide";
        readonly category: "permissions";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Cluster-wide secrets read is effectively takeover of credentials.";
        readonly impact: "Every SA token and secret becomes readable.";
        readonly recommendation: "Use a namespaced Role or resourceNames restrictions.";
        readonly complexity: "small";
        readonly tags: ["permissions", "secrets"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["templates/*.yaml", "**/templates/*.yaml"];
            readonly pattern: {
                readonly pattern: "kind:\\s*ClusterRole[\\s\\S]{0,400}resources:\\s*\\[[^\\]]*secrets[^\\]]*\\][\\s\\S]{0,120}verbs:\\s*\\[[^\\]]*(?:get|list|watch|\\*)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "helm.hook-privileged";
        readonly title: "Helm hook runs privileged";
        readonly summary: "Helm hook runs privileged";
        readonly category: "security";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Hooks still execute with release identity.";
        readonly impact: "Privileged hook pods compromise the host.";
        readonly recommendation: "Harden hook pods like any workload.";
        readonly complexity: "small";
        readonly tags: ["security", "hooks"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["templates/*.yaml", "**/templates/*.yaml"];
            readonly pattern: {
                readonly pattern: "helm\\.sh/hook[\\\"']?[^\\n]*\\n[\\s\\S]{0,400}privileged:\\s*true";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
