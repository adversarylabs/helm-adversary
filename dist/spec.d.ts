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
    match: ContentMatch | MissingContentMatch | MissingFileMatch;
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
    readonly description: "Reviews Helm charts for excessive RBAC, mutable images, and unbounded dependencies.";
    readonly files: ["Chart.yaml", "**/Chart.yaml", "values.yaml", "**/values.yaml", "templates/*.yaml", "**/templates/*.yaml"];
    readonly rules: [{
        readonly id: "helm.wildcard-rbac";
        readonly title: "Chart grants wildcard RBAC permissions";
        readonly summary: "Chart grants wildcard RBAC permissions";
        readonly category: "permissions";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Chart grants wildcard RBAC permissions weakens an important permissions boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Replace wildcards with exact namespaced resources and verbs.";
        readonly complexity: "small";
        readonly tags: ["permissions", "wildcard-rbac"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["templates/*.yaml", "**/templates/*.yaml"];
            readonly pattern: {
                readonly pattern: "(?:verbs|resources):\\s*\\[[^\\]]*[\"']?\\*[\"']?";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "helm.latest-default";
        readonly title: "Chart defaults an image tag to latest";
        readonly summary: "Chart defaults an image tag to latest";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Chart defaults an image tag to latest weakens an important supply-chain boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Default to a release version or digest.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "latest-default"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["values.yaml", "**/values.yaml"];
            readonly pattern: {
                readonly pattern: "(?:tag|imageTag):\\s*[\"']?latest";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "helm.unbounded-dependency";
        readonly title: "Chart dependency uses an unbounded version";
        readonly summary: "Chart dependency uses an unbounded version";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Chart dependency uses an unbounded version weakens an important supply-chain boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Pin chart dependencies and commit Chart.lock.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "unbounded-dependency"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["Chart.yaml", "**/Chart.yaml"];
            readonly pattern: {
                readonly pattern: "version:\\s*[\"']?(?:\\*|>=|~|\\^|latest)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
