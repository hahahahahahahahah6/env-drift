# env-drift 0.1.0

An offline, deterministic environment-variable contract auditor for Python 3.9+.
Runtime uses only the standard library: no network, LLM, keys, subprocesses,
code execution, or login. It never opens `.env` for content and never reports
variable values. It checks `.env` filename presence using filesystem traversal.
Only the first root `.env.example`, `.env.sample`, or `.env.dist` is read as
an explicitly designated example; all other `.env*` content is skipped.

Install with `pip install .` or install a locally built wheel. Run:

```sh
env-drift --version
env-drift audit
env-drift audit examples/sample-repo/good --json
env-drift audit examples/sample-repo/broken --ignore 'OLD_*'
env-drift audit . --fail-on medium --ignore 'APP_*' --ignore '*.env'
```

Repo defaults to `.`. Repeat `--ignore` or supply several globs per occurrence.
Globs match variable names, or relative filenames for file findings. A finding
matching several globs is ignored once. Repo-level missing-example uses `.`.
Exit codes: 0 PASS, 1 WARN, 2 FAIL. HIGH findings fail by default; MEDIUM
findings warn. `--fail-on medium` fails on any finding. Argument/path errors
exit 2. Unreadable or invalid UTF-8 scanned files count as parse errors and
produce WARN unless findings already produce FAIL. They do not abort scanning.

Findings have relative file, 1-based line (0 when unavailable), kind, claim,
severity, and a checkable detail. Repo-level findings use file `.` and line 0.
Deduplication uses (file, line, kind, claim); sorting uses that same order.
Both output modes provide total, per-kind and per-severity counts, ignored and
parse-error counts, verdict, and explicit truncation/omission counts. Only the
first 500 unignored findings display; totals and verdict include all of them.
An empty repo passes with a note.

| Kind | Severity | Meaning |
| --- | --- | --- |
| committed-env-file | HIGH | `.env` exists; verify it is gitignored and contains no real secrets. The tool did not read it. |
| undocumented-var | HIGH | Code name absent from an existing example. |
| missing-example | MEDIUM | Code references exist with no root example (one repo-level finding). |
| stale-example-var | MEDIUM | Example name unused by code, CI, and Docker ENV. |
| stale-ci-secret | MEDIUM | CI secret name unused by code. |
| unset-in-ci | MEDIUM | With a workflow or Dockerfile present, code name absent from CI/Docker sources. |

Python `os.getenv`, `os.environ[...]`, `os.environ.get`, JS/TS `process.env.X`
and `process.env["X"]`, Go `os.Getenv`, and Rust `env::var` / `std::env::var`
are recognized with literal ALL-CAPS names of at least two characters,
including digits/underscores. Example parsing reads `KEY=` and `export KEY=`
names only; blanks, comments, and nonassignment lines are ignored. Values,
including quoted values, are not interpreted.

CI scans root `.github/workflows/*.yml` and `*.yaml` for `secrets.NAME` and
uppercase keys in indented `env:` sections. Secret names and environment names
share a namespace in the stale-secret check. Root `Dockerfile` and
`Dockerfile.*` supply the first key on each `ENV KEY ...` / `ENV KEY=...` line.
Traversal skips `.git`, `node_modules`, `dist`, `__pycache__`, `.venv`, `venv`,
symlink directories, and symlink source files. No git command is invoked.

These are patterns, not semantic judgement. A finding means “check this claim”.
Dynamic access via getattr, f-strings, constructed names, shell `${VAR}`
expansion, and config libraries reading env indirectly is not seen. Comments
and string literals containing complete patterns may be counted. CI scanning
is a line heuristic, not YAML parsing; nested `env:` blocks may be missed or
over-matched. `unset-in-ci` flags legitimate deploy-time/runtime-set variables:
check, don't auto-fix. A `.env` file's presence proves neither that it is
committed nor that it contains secrets; check git status yourself. Existence
says nothing about correctness of values.

Compared with dotenv-linter (dotenv syntax), this cross-checks code ↔ example
↔ CI. Compared with contextleak (Docker build-context inclusion), this checks
the env contract. instruction-drift / skill-drift compare instruction/skill
claims with disk; this compares env references with examples and CI. Compared
with heavy runtimes or secret scanners, this is an offline stdlib CLI that
never reads secret values and executes nothing.

The good fixture supplies APP_PORT and DATABASE_URL in both example and CI
and passes. The broken fixture has an undocumented NEW_API_KEY, stale
OLD_TOKEN, and a placeholder-only `.env`; it fails with exit 2.

Development and local packaging (build tooling is not a runtime dependency):

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python -m build
python -m venv /tmp/env-drift-smoke
/tmp/env-drift-smoke/bin/pip install --no-deps dist/*.whl
/tmp/env-drift-smoke/bin/env-drift --version
/tmp/env-drift-smoke/bin/env-drift audit examples/sample-repo/good
/tmp/env-drift-smoke/bin/env-drift audit examples/sample-repo/broken
```

The standard setuptools build-meta backend produces wheel and sdist. No
custom backend or publication is involved. Licensed under MIT.
