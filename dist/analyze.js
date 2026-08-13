import { execFile } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { promisify } from "node:util";
import { observationFor } from "./rules.js";
import { spec } from "./spec.js";
const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const POD_TEMPLATE_KINDS = new Set([
    "CronJob",
    "DaemonSet",
    "Deployment",
    "Job",
    "Pod",
    "ReplicaSet",
    "ReplicationController",
    "StatefulSet",
]);
const MAX_FILES = 5000;
const execute = promisify(execFile);
export async function analyzeRepository(ctx) {
    // Full tree for existence/context checks; content uses CLI/SDK review scope.
    const allPaths = await walk(ctx.repoPath);
    const scoped = await ctx.loadInScopeSources({
        include: (path) => !path.split("/").some((segment) => SKIPPED.has(segment)) &&
            spec.files.some((glob) => matchesGlob(path, glob)),
        limit: MAX_FILES,
    });
    const sources = [];
    const wholeTarget = ctx.change === null || ctx.change.scanMode === "all";
    for (const file of scoped) {
        if (wholeTarget || file.status === "repository") {
            sources.push({
                path: file.path,
                source: file.content,
                status: "repository",
                changedLines: new Set(),
            });
            continue;
        }
        const change = await changedSource(ctx, file.path);
        sources.push({
            path: file.path,
            source: file.content,
            status: change.status,
            changedLines: change.changedLines,
        });
    }
    ctx.summary.files_scanned = sources.length;
    const detections = spec.rules.flatMap((rule) => evaluate(rule, sources, allPaths));
    detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
    for (const detection of detections)
        ctx.observe(observationFor(detection));
    if (sources.length > 0 && detections.length === 0) {
        ctx.review.positive({
            key: `${spec.id}.reviewed`,
            summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
            evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
        });
    }
}
function evaluate(rule, sources, allPaths) {
    const match = rule.match;
    if (match.kind === "missing-file") {
        const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
        const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
        if (triggers.length === 0 || required)
            return [];
        return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
    }
    const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)));
    if (match.kind === "selector-label-override") {
        return matchingSources.flatMap((file) => findSelectorLabelOverrides(rule, file));
    }
    if (match.kind === "conditional-file-mount") {
        return matchingSources.flatMap((file) => findConditionalFileMounts(rule, file));
    }
    if (match.kind === "missing-content") {
        return matchingSources.flatMap((file) => {
            if (!test(file.source, match.trigger) || test(file.source, match.required))
                return [];
            const location = locateEligible(file, match.trigger);
            if (location === undefined)
                return [];
            return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
        });
    }
    if (match.kind === "indented-block-content") {
        return matchingSources.flatMap((file) => extractIndentedBlocks(file.source, match.blockStart).flatMap((block) => {
            if (!match.requires.every((pattern) => test(block.source, pattern)))
                return [];
            const location = locateEligible(file, match.pattern, block.start, block.source);
            if (location === undefined)
                return [];
            return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
        }));
    }
    if (match.kind === "indented-block-missing-content") {
        return matchingSources.flatMap((file) => extractIndentedBlocks(file.source, match.blockStart).flatMap((block) => {
            if (!test(block.source, match.trigger) || test(block.source, match.required))
                return [];
            const location = locateEligible(file, match.trigger, block.start, block.source);
            if (location === undefined)
                return [];
            return [{
                    rule,
                    file: file.path,
                    ...location,
                    label: rule.title,
                    data: { requiredPattern: match.required.pattern },
                }];
        }));
    }
    return matchingSources.flatMap((file) => {
        if (!match.requires.every((pattern) => test(file.source, pattern)))
            return [];
        const location = locateEligible(file, match.pattern, 0, file.source, match.anchors);
        if (location === undefined)
            return [];
        return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
    });
}
function findConditionalFileMounts(rule, file) {
    const detections = [];
    for (const document of helmDocuments(file.source)) {
        const guardedLines = annotateHelmGuards(document.source, document.startLine);
        if (!isPodBearingDocument(guardedLines))
            continue;
        for (let index = 0; index < guardedLines.length; index += 1) {
            const containerHeader = guardedLines[index];
            if (containerHeader === undefined ||
                !containerHeader.activeYaml ||
                !/^(?:containers|initContainers|ephemeralContainers):$/.test(containerHeader.source.trim())) {
                continue;
            }
            const memberIndent = indentation(containerHeader.source);
            const podLines = enclosingYamlBlock(guardedLines, index, memberIndent);
            const volumes = findVolumes(podLines, memberIndent);
            for (const container of findContainerScopes(guardedLines, index)) {
                const args = findFileArguments(container);
                const mounts = findVolumeMounts(container.lines, container.propertyIndent);
                for (const argument of args) {
                    const detection = detectConditionalFileMount(rule, file, container, argument, mounts, volumes);
                    if (detection !== undefined)
                        detections.push(detection);
                }
            }
        }
    }
    return detections;
}
function detectConditionalFileMount(rule, file, container, argument, mounts, volumes) {
    if (!argument.provable)
        return undefined;
    const matchingMounts = mounts.filter((mount) => mount.provable &&
        (argument.path === mount.mountPath || argument.path.startsWith(`${mount.mountPath}/`)));
    if (matchingMounts.length === 0)
        return undefined;
    const fullyAvailable = matchingMounts.some((mount) => {
        if (missingAvailabilityPredicate(argument, mount) !== undefined)
            return false;
        return volumes.some((volume) => volume.provable &&
            volume.name === mount.name &&
            missingAvailabilityPredicate(argument, volume) === undefined);
    });
    if (fullyAvailable)
        return undefined;
    for (const mount of matchingMounts) {
        const matchingVolumes = volumes.filter((volume) => volume.provable && volume.name === mount.name);
        if (matchingVolumes.length === 0)
            continue;
        const mountMismatch = missingAvailabilityPredicate(argument, mount);
        const volumeMismatch = matchingVolumes
            .map((volume) => ({ volume, mismatch: missingAvailabilityPredicate(argument, volume) }))
            .find(({ mismatch }) => mismatch !== undefined);
        if (mountMismatch === undefined && volumeMismatch === undefined)
            continue;
        const mismatch = mountMismatch ?? volumeMismatch?.mismatch;
        const resourceLine = mountMismatch === undefined
            ? (volumeMismatch?.volume.line ?? mount.line)
            : mount.line;
        const guardLine = mismatch === undefined
            ? undefined
            : (mount.predicates.get(mismatch) ?? volumeMismatch?.volume.predicates.get(mismatch));
        const anchor = [argument.line, resourceLine, guardLine]
            .find((line) => line !== undefined && isEligibleLine(file, line));
        if (anchor === undefined)
            continue;
        return {
            rule,
            file: file.path,
            line: anchor,
            snippet: file.source.split(/\r?\n/)[anchor - 1]?.trim().slice(0, 240) ?? "",
            label: rule.title,
            data: {
                argumentPath: argument.path,
                container: container.name,
                volumeMount: mount.name,
                mountPath: mount.mountPath,
                unavailableWhen: mismatch,
            },
        };
    }
    return undefined;
}
function missingAvailabilityPredicate(argument, resource) {
    for (const predicate of resource.predicates.keys()) {
        if (!argument.predicates.has(predicate))
            return predicate;
    }
    return undefined;
}
function helmDocuments(source) {
    const lines = source.split(/\r?\n/);
    const documents = [];
    let start = 0;
    for (let index = 0; index <= lines.length; index += 1) {
        if (index < lines.length && !/^---\s*(?:#.*)?$/.test(lines[index]?.trim() ?? ""))
            continue;
        if (index > start) {
            documents.push({ source: lines.slice(start, index).join("\n"), startLine: start + 1 });
        }
        start = index + 1;
    }
    return documents;
}
function annotateHelmGuards(source, startLine) {
    const stack = [];
    const variables = new Map();
    const guarded = [];
    const lines = source.split(/\r?\n/);
    let blockScalarIndent;
    for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index] ?? "";
        const sourceLine = startLine + index;
        const trimmed = line.trim();
        if (blockScalarIndent !== undefined &&
            trimmed !== "" &&
            indentation(line) <= blockScalarIndent) {
            blockScalarIndent = undefined;
        }
        const activeYaml = blockScalarIndent === undefined;
        const actions = [...line.matchAll(/{{-?\s*([\s\S]*?)\s*-?}}/g)];
        for (const action of actions) {
            const expression = action[1]?.trim() ?? "";
            const assignment = expression.match(/^(\$[A-Za-z_]\w*)\s*:=\s*(.+)$/);
            if (assignment !== null) {
                variables.set(assignment[1] ?? "", parseGuard(assignment[2] ?? "", sourceLine, variables));
                continue;
            }
            const opening = expression.match(/^(if|with)\s+(.+)$/);
            if (opening !== null) {
                stack.push(parseGuard(opening[2] ?? "", sourceLine, variables));
                continue;
            }
            if (/^(?:range|define|block)\b/.test(expression)) {
                stack.push({ predicates: new Map(), provable: false });
                continue;
            }
            if (/^else\b/.test(expression)) {
                if (stack.length > 0)
                    stack[stack.length - 1] = { predicates: new Map(), provable: false };
                continue;
            }
            if (/^end\b/.test(expression))
                stack.pop();
        }
        if (line.replace(/{{-?\s*[\s\S]*?\s*-?}}/g, "").trim() === "")
            continue;
        const predicates = new Map();
        let provable = true;
        for (const frame of stack) {
            provable &&= frame.provable;
            for (const [predicate, lineNumber] of frame.predicates)
                predicates.set(predicate, lineNumber);
        }
        guarded.push({ line: sourceLine, source: line, predicates, provable, activeYaml });
        if (activeYaml && /:\s*[>|](?:[+-][1-9]?|[1-9][+-]?|)\s*(?:#.*)?$/.test(line)) {
            blockScalarIndent = indentation(line);
        }
    }
    return guarded;
}
function parseGuard(expression, line, variables) {
    const normalized = expression.replace(/[()]/g, " ").trim();
    const tokens = normalized.match(/(?:"[^"]*"|'[^']*'|[^\s]+)/g) ?? [];
    if (tokens.length === 1 && tokens[0]?.startsWith("$")) {
        return variables.get(tokens[0]) ?? { predicates: new Map(), provable: false };
    }
    const valueTokens = tokens[0] === "and" ? tokens.slice(1) : tokens;
    if (valueTokens.length === 0 || valueTokens.some((token) => !/^\.Values(?:\.[A-Za-z_]\w*)+$/.test(token))) {
        return { predicates: new Map(), provable: false };
    }
    return {
        predicates: new Map(valueTokens.map((token) => [token, line])),
        provable: true,
    };
}
function findFileArguments(container) {
    const args = [];
    const expression = /^\s*-\s*["']?--[A-Za-z0-9][A-Za-z0-9-]*(?:file|path|cert|key|config)[A-Za-z0-9-]*\s*=\s*(\/[A-Za-z0-9._/-]*[A-Za-z0-9._-])["']?\s*(?:#.*)?$/i;
    for (let index = 0; index < container.lines.length; index += 1) {
        const section = container.lines[index];
        if (section === undefined ||
            !section.activeYaml ||
            indentation(section.source) !== container.propertyIndent ||
            !/^(?:args|command):$/.test(section.source.trim())) {
            continue;
        }
        for (const item of yamlListItems(container.lines, index)) {
            const scalar = item.lines[0];
            if (scalar === undefined ||
                !scalar.activeYaml ||
                scalar.source.trim().startsWith("#")) {
                continue;
            }
            const path = scalar.source.match(expression)?.[1];
            if (path === undefined || path === "/" || path.includes("//"))
                continue;
            const guard = combineGuardStates([container.item, section, scalar]);
            args.push({ line: scalar.line, path, ...guard });
        }
    }
    return args;
}
function findVolumeMounts(lines, sectionIndent) {
    return findNamedYamlEntries(lines, "volumeMounts", sectionIndent).flatMap((entry) => {
        const mountPath = entry.lines
            .map((line) => ({ line, match: line.source.match(/^\s*(?:-\s*)?mountPath:\s*["']?(\/[A-Za-z0-9._/-]+)["']?\s*(?:#.*)?$/) }))
            .find(({ line, match }) => match !== null &&
            (line === entry.lines[0] || indentation(line.source) === entry.propertyIndent));
        if (mountPath?.match?.[1] === undefined)
            return [];
        return [{
                line: entry.nameLine.line,
                name: entry.name,
                mountPath: mountPath.match[1].replace(/\/$/, ""),
                ...combineGuardStates([entry.section, entry.nameLine, mountPath.line]),
            }];
    });
}
function findVolumes(lines, sectionIndent) {
    return findNamedYamlEntries(lines, "volumes", sectionIndent).map((entry) => ({
        line: entry.nameLine.line,
        name: entry.name,
        ...combineGuardStates([entry.section, entry.nameLine]),
    }));
}
function findNamedYamlEntries(lines, sectionName, expectedIndent) {
    const entries = [];
    for (let sectionIndex = 0; sectionIndex < lines.length; sectionIndex += 1) {
        const section = lines[sectionIndex];
        if (section === undefined ||
            !section.activeYaml ||
            section.source.trim() !== `${sectionName}:` ||
            (expectedIndent !== undefined && indentation(section.source) !== expectedIndent)) {
            continue;
        }
        for (const candidate of yamlListItems(lines, sectionIndex)) {
            const first = candidate.lines[0];
            const propertyIndent = indentation(first?.source ?? "") + 2;
            const named = candidate.lines
                .map((line) => ({
                line,
                name: line.source.match(/^\s*(?:-\s*)?name:\s*["']?([A-Za-z0-9._-]+)["']?\s*(?:#.*)?$/)?.[1],
            }))
                .find(({ line, name }) => name !== undefined &&
                (line === first || indentation(line.source) === propertyIndent));
            if (named?.name === undefined)
                continue;
            entries.push({
                section,
                name: named.name,
                nameLine: named.line,
                lines: candidate.lines,
                propertyIndent,
            });
        }
    }
    return entries;
}
function findContainerScopes(lines, sectionIndex) {
    return yamlListItems(lines, sectionIndex).map((item) => {
        const itemIndent = indentation(item.lines[0]?.source ?? "");
        const propertyIndent = itemIndent + 2;
        const named = item.lines
            .map((line) => ({
            line,
            name: line.source.match(/^\s*(?:-\s*)?name:\s*["']?([A-Za-z0-9._-]+)["']?\s*(?:#.*)?$/)?.[1],
        }))
            .find(({ line, name }) => name !== undefined &&
            (line === item.lines[0] || indentation(line.source) === propertyIndent));
        return {
            name: named?.name ?? `container at line ${item.lines[0]?.line ?? 0}`,
            item: item.lines[0] ?? lines[sectionIndex],
            lines: item.lines,
            propertyIndent,
        };
    });
}
function yamlListItems(lines, sectionIndex) {
    const section = lines[sectionIndex];
    if (section === undefined)
        return [];
    const sectionIndent = indentation(section.source);
    let itemIndent;
    let current;
    const items = [];
    for (let index = sectionIndex + 1; index < lines.length; index += 1) {
        const line = lines[index];
        if (line === undefined)
            break;
        const trimmed = line.source.trim();
        if (!line.activeYaml || trimmed === "" || trimmed.startsWith("#"))
            continue;
        const lineIndent = indentation(line.source);
        if (lineIndent <= sectionIndent)
            break;
        if (/^\s*-\s+/.test(line.source) && (itemIndent === undefined || lineIndent === itemIndent)) {
            itemIndent ??= lineIndent;
            current = { lines: [line] };
            items.push(current);
        }
        else if (current !== undefined) {
            current.lines.push(line);
        }
    }
    return items;
}
function enclosingYamlBlock(lines, childIndex, childIndent) {
    let start = 0;
    let parentIndent = -1;
    for (let index = childIndex - 1; index >= 0; index -= 1) {
        const line = lines[index];
        if (line === undefined ||
            !line.activeYaml ||
            line.source.trim().startsWith("#")) {
            continue;
        }
        const lineIndent = indentation(line.source);
        if (lineIndent < childIndent) {
            start = index;
            parentIndent = lineIndent;
            break;
        }
    }
    let end = lines.length;
    for (let index = childIndex + 1; index < lines.length; index += 1) {
        const line = lines[index];
        if (line === undefined ||
            !line.activeYaml ||
            line.source.trim().startsWith("#")) {
            continue;
        }
        if (indentation(line.source) <= parentIndent) {
            end = index;
            break;
        }
    }
    return lines.slice(start, end);
}
function combineGuardStates(states) {
    const predicates = new Map();
    let provable = true;
    for (const state of states) {
        provable &&= state.provable;
        for (const [predicate, line] of state.predicates)
            predicates.set(predicate, line);
    }
    return { predicates, provable };
}
function indentation(source) {
    return source.match(/^[ \t]*/)?.[0].length ?? 0;
}
function isPodBearingDocument(lines) {
    return lines.some((line) => {
        if (!line.activeYaml || indentation(line.source) !== 0)
            return false;
        const kind = line.source.match(/^kind:\s*["']?([A-Za-z][A-Za-z0-9]*)["']?\s*(?:#.*)?$/)?.[1];
        return kind !== undefined && POD_TEMPLATE_KINDS.has(kind);
    });
}
function findSelectorLabelOverrides(rule, file) {
    const lines = file.source.split(/\r?\n/);
    const detections = [];
    for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index] ?? "";
        if (!/\binclude\s+["'][^"']*selectorLabels[^"']*["']/i.test(line))
            continue;
        let labelsIndex = -1;
        for (let candidate = index; candidate >= Math.max(0, index - 3); candidate -= 1) {
            if (/^\s*labels:\s*$/.test(lines[candidate] ?? "")) {
                labelsIndex = candidate;
                break;
            }
        }
        if (labelsIndex < 0)
            continue;
        const end = Math.min(lines.length, index + 9);
        const region = lines.slice(labelsIndex, end).join("\n");
        if (!/\bpodLabels\b/.test(region))
            continue;
        if (!/\btoYaml\b/.test(region))
            continue;
        if (/\bmerge(?:Overwrite)?\s*\(/.test(region))
            continue;
        if (!isEligibleLine(file, index + 1))
            continue;
        detections.push({
            rule,
            file: file.path,
            line: index + 1,
            snippet: line.trim().slice(0, 240),
            label: rule.title,
            data: { selectorHelper: line.trim() },
        });
    }
    return detections;
}
function test(source, expression) {
    return new RegExp(expression.pattern, expression.flags).test(source);
}
function locateEligible(file, expression, offset = 0, source = file.source, anchors) {
    const flags = expression.flags.includes("g") ? expression.flags : `${expression.flags}g`;
    const matcher = new RegExp(expression.pattern, flags);
    for (const match of source.matchAll(matcher)) {
        if (match.index === undefined)
            continue;
        const start = offset + match.index;
        const end = start + match[0].length;
        const startLine = lineAt(file.source, start);
        const endLine = lineAt(file.source, Math.max(start, end - 1));
        const anchor = anchors === undefined
            ? eligibleAnchor(file, startLine, endLine)
            : eligibleSemanticAnchor(file, match[0], start, anchors);
        if (anchor === undefined)
            continue;
        return locationAtLine(file.source, anchor);
    }
    return undefined;
}
function eligibleSemanticAnchor(file, matchedSource, offset, anchors) {
    if (file.status !== "modified")
        return lineAt(file.source, offset);
    for (const anchor of anchors) {
        const flags = anchor.flags.includes("g") ? anchor.flags : `${anchor.flags}g`;
        for (const match of matchedSource.matchAll(new RegExp(anchor.pattern, flags))) {
            if (match.index === undefined)
                continue;
            const start = offset + match.index;
            const end = start + match[0].length;
            const line = eligibleAnchor(file, lineAt(file.source, start), lineAt(file.source, Math.max(start, end - 1)));
            if (line !== undefined)
                return line;
        }
    }
    return undefined;
}
function lineAt(source, index) {
    return source.slice(0, index).split(/\r?\n/).length;
}
function locationAtLine(source, line) {
    return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
}
function eligibleAnchor(file, startLine, endLine) {
    if (file.status !== "modified")
        return startLine;
    for (let line = startLine; line <= endLine; line += 1) {
        if (file.changedLines.has(line))
            return line;
    }
    return undefined;
}
function isEligibleLine(file, line) {
    return file.status !== "modified" || file.changedLines.has(line);
}
async function changedSource(ctx, path) {
    const base = ctx.change?.baseRef;
    if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
        return { changedLines: new Set(), status: "added" };
    }
    const args = ["diff", "--unified=0", base];
    const head = ctx.change?.headRef;
    if (head !== undefined && !ctx.change?.worktree)
        args.push(head);
    args.push("--", path);
    const patch = await gitOutput(ctx.repoPath, args);
    return { changedLines: changedLineNumbers(patch), status: "modified" };
}
async function existsAtRevision(repoPath, revision, path) {
    try {
        await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
            maxBuffer: 1024 * 1024,
        });
        return true;
    }
    catch {
        return false;
    }
}
async function gitOutput(repoPath, args) {
    const result = await execute("git", ["-C", repoPath, ...args], {
        encoding: "utf8",
        maxBuffer: 8 * 1024 * 1024,
    });
    return result.stdout;
}
function changedLineNumbers(patch) {
    const lines = new Set();
    for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
        const start = Number(match[1]);
        const count = match[2] === undefined ? 1 : Number(match[2]);
        for (let line = start; line < start + count; line += 1)
            lines.add(line);
    }
    return lines;
}
function extractIndentedBlocks(source, start) {
    const flags = start.flags.includes("g") ? start.flags : `${start.flags}g`;
    const expression = new RegExp(start.pattern, flags);
    const blocks = [];
    let match;
    while ((match = expression.exec(source)) !== null) {
        const lineStart = source.lastIndexOf("\n", Math.max(0, match.index - 1)) + 1;
        const lineEnd = source.indexOf("\n", match.index);
        const firstLineEnd = lineEnd < 0 ? source.length : lineEnd;
        const indentation = source.slice(lineStart, firstLineEnd).match(/^[ \t]*/)?.[0].length ?? 0;
        let end = source.length;
        let cursor = firstLineEnd < source.length ? firstLineEnd + 1 : source.length;
        while (cursor < source.length) {
            const nextLineEnd = source.indexOf("\n", cursor);
            const currentEnd = nextLineEnd < 0 ? source.length : nextLineEnd;
            const line = source.slice(cursor, currentEnd);
            if (line.trim() !== "") {
                const currentIndentation = line.match(/^[ \t]*/)?.[0].length ?? 0;
                if (currentIndentation <= indentation) {
                    end = cursor;
                    break;
                }
            }
            cursor = currentEnd < source.length ? currentEnd + 1 : source.length;
        }
        blocks.push({ source: source.slice(match.index, end), start: match.index });
        expression.lastIndex = Math.max(expression.lastIndex, end);
    }
    return blocks;
}
async function walk(root) {
    const files = [];
    async function visit(relative) {
        if (files.length >= MAX_FILES)
            return;
        const entries = await readdir(join(root, relative), { withFileTypes: true });
        entries.sort((a, b) => a.name.localeCompare(b.name));
        for (const entry of entries) {
            if (files.length >= MAX_FILES)
                return;
            const path = relative ? join(relative, entry.name) : entry.name;
            if (entry.isDirectory() && !SKIPPED.has(entry.name))
                await visit(path);
            else if (entry.isFile())
                files.push(path.split(sep).join("/"));
        }
    }
    await visit("");
    return files.sort();
}
function matchesGlob(path, glob) {
    let pattern = "^";
    for (let index = 0; index < glob.length; index += 1) {
        const character = glob[index];
        if (character === "*" && glob[index + 1] === "*") {
            if (glob[index + 2] === "/") {
                pattern += "(?:.*/)?";
                index += 2;
            }
            else {
                pattern += ".*";
                index += 1;
            }
        }
        else if (character === "*")
            pattern += "[^/]*";
        else if (character === "?")
            pattern += "[^/]";
        else
            pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
    }
    return new RegExp(`${pattern}$`, "i").test(path);
}
