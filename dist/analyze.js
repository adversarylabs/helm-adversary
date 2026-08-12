import { execFile } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { promisify } from "node:util";
import { observationFor } from "./rules.js";
import { spec } from "./spec.js";
const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
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
