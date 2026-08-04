# container/helm — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `helm`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Helm charts

## Mission

Review Helm charts for RBAC, privileged defaults, mutable images, dependency pinning.

## In scope (fair miss if humans raised it and we did not)

- Excessive RBAC
- Privileged defaults
- Mutable images / unpinned deps

## Out of scope (not a miss for this adversary)

- App source
- Raw K8s without Helm

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
