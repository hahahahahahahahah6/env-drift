"""Filesystem-only heuristics. No code is executed and .env is never opened."""
import fnmatch
import os
import re
from collections import Counter
from pathlib import Path

SKIP = {".git", "node_modules", "dist", "__pycache__", ".venv", "venv"}
NAME = r"[A-Z_][A-Z0-9_]+"
PATTERNS = {
    ".py": [r"\bos\s*\.\s*getenv\s*\(\s*(['\"])(" + NAME + r")\1",
            r"\bos\s*\.\s*environ\s*\[\s*(['\"])(" + NAME + r")\1\s*\]",
            r"\bos\s*\.\s*environ\s*\.\s*get\s*\(\s*(['\"])(" + NAME + r")\1"],
    ".go": [r"\bos\.Getenv\s*\(\s*(['\"])(" + NAME + r")\1"],
    ".rs": [r"\b(?:std::)?env::var\s*\(\s*(['\"])(" + NAME + r")\1"],
}
JS = [r"\bprocess\.env\.(" + NAME + r")(?![A-Za-z0-9_$])",
      r"\bprocess\.env\[\s*(['\"])(" + NAME + r")\1\s*\]"]
for suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
    PATTERNS[suffix] = JS
KINDS = {"committed-env-file": "HIGH", "undocumented-var": "HIGH",
         "missing-example": "MEDIUM", "stale-example-var": "MEDIUM",
         "stale-ci-secret": "MEDIUM", "unset-in-ci": "MEDIUM"}


def report(findings, parse_errors=0, ignore=(), fail_on="high", cap=500, notes=()):
    unique = {(f["file"], f["line"], f["kind"], f["claim"]): f for f in findings}
    ordered = sorted(unique.values(), key=lambda f: (f["file"], f["line"], f["kind"], f["claim"]))
    kept = [f for f in ordered if not any(fnmatch.fnmatchcase(f["claim"], g) for g in ignore)]
    severity = Counter(f["severity"] for f in kept)
    verdict = "FAIL" if severity["HIGH"] or (fail_on == "medium" and kept) else "WARN" if kept or parse_errors else "PASS"
    return {"findings": kept[:cap], "total": len(kept), "per_kind": {k: sum(f["kind"] == k for f in kept) for k in KINDS},
            "per_severity": {k: severity[k] for k in ("HIGH", "MEDIUM")},
            "ignored_count": len(ordered) - len(kept), "parse_error_count": parse_errors,
            "truncated": len(kept) > cap, "omitted_count": max(0, len(kept)-cap),
            "verdict": verdict, "notes": list(notes)}


def audit(repo=".", ignore=(), fail_on="high", cap=500):
    root = Path(repo)
    if not root.is_dir():
        raise ValueError("Repository path must exist and be a directory.")
    findings, refs, examples, secrets, ci_env, docker = [], [], [], [], set(), set()
    errors = 0
    infrastructure = False
    example = next((name for name in (".env.example", ".env.sample", ".env.dist") if (root/name).is_file()), None)

    def add(file, line, kind, claim, detail):
        findings.append(dict(file=file, line=line, kind=kind, claim=claim, severity=KINDS[kind], detail=detail))

    def read(path):
        nonlocal errors
        try:
            return path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            errors += 1
            return []

    def walk_error(error):
        nonlocal errors
        errors += 1

    for folder, dirs, files in os.walk(root, onerror=walk_error, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP and not (Path(folder)/d).is_symlink())
        for name in sorted(files):
            path = Path(folder)/name
            relative = path.relative_to(root).as_posix()
            if name == ".env":
                add(relative, 0, "committed-env-file", relative,
                    "Verify it is gitignored and contains no real secrets; the tool did not read it.")
                continue
            if path.is_symlink():
                continue
            if name.startswith(".env"):
                if relative == example:
                    for line, text in enumerate(read(path), 1):
                        match = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", text)
                        if match:
                            examples.append((match[1], relative, line))
                continue
            is_ci = path.parent == root/".github"/"workflows" and path.suffix in (".yml", ".yaml")
            is_docker = path.parent == root and (name == "Dockerfile" or name.startswith("Dockerfile."))
            patterns = PATTERNS.get(path.suffix, ())
            if not (is_ci or is_docker or patterns):
                continue
            infrastructure = infrastructure or is_ci or is_docker
            env_indent = None
            for line, text in enumerate(read(path), 1):
                for pattern in patterns:
                    for match in re.finditer(pattern, text):
                        refs.append((match[match.lastindex], relative, line))
                if is_ci:
                    for match in re.finditer(r"\bsecrets\.([A-Z_][A-Z0-9_]*)(?![A-Za-z0-9_])", text):
                        secrets.append((match[1], relative, line))
                    if text.strip() and not text.lstrip().startswith("#"):
                        indent = len(text) - len(text.lstrip())
                        if env_indent is not None and indent <= env_indent:
                            env_indent = None
                        if re.match(r"^\s*(?:-\s+)?env:\s*(?:#.*)?$", text):
                            env_indent = indent
                        elif env_indent is not None:
                            match = re.match(r"^\s*([A-Z_][A-Z0-9_]*)\s*:", text)
                            if match:
                                ci_env.add(match[1])
                if is_docker:
                    match = re.match(r"^\s*ENV\s+([A-Za-z_][A-Za-z0-9_]*)(?=\s|=|$)", text)
                    if match:
                        docker.add(match[1])
    code_names = {r[0] for r in refs}
    example_names = {r[0] for r in examples}
    supplied = ci_env | docker | {r[0] for r in secrets}
    if refs and example is None:
        add(".", 0, "missing-example", ".", "Code references environment variables but no root example file exists.")
    for name, file, line in refs:
        if example and name not in example_names:
            add(file, line, "undocumented-var", name, "Code variable is absent from the selected example file.")
        if infrastructure and name not in supplied:
            add(file, line, "unset-in-ci", name, "Not supplied by CI or Docker ENV; deploy-time/runtime-set variables can legitimately flag. Check before changing.")
    for name, file, line in examples:
        if name not in code_names | supplied:
            add(file, line, "stale-example-var", name, "Example variable is not referenced in code, CI, or Docker ENV.")
    for name, file, line in secrets:
        if name not in code_names:
            add(file, line, "stale-ci-secret", name, "Secret name is not referenced in code; secret and environment names share a namespace for this heuristic.")
    notes = ["Empty repository: no code references, example, or CI/Docker sources."] if not refs and example is None and not infrastructure else []
    return report(findings, errors, ignore, fail_on, cap, notes)
