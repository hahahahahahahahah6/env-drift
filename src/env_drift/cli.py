"""Command-line reporting; output contains names only, never source text."""
import argparse
import json

from . import __version__
from .audit import audit


def main(argv=None):
    parser = argparse.ArgumentParser(prog="env-drift", description="Offline environment-variable contract audit")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("audit")
    command.add_argument("repo", nargs="?", default=".")
    command.add_argument("--json", action="store_true")
    command.add_argument("--fail-on", choices=("high", "medium"), default="high")
    command.add_argument("--ignore", action="append", nargs="+", default=[])
    args = parser.parse_args(argv)
    try:
        result = audit(args.repo, [g for group in args.ignore for g in group], args.fail_on)
    except ValueError as error:
        parser.error(str(error))
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(result["verdict"] + ": " + str(result["total"]) + " findings")
        for finding in result["findings"]:
            print("{file}:{line}: {severity} {kind} {claim}: {detail}".format(**finding))
        for key in ("per_kind", "per_severity", "ignored_count", "parse_error_count", "truncated", "omitted_count"):
            print(key + ": " + json.dumps(result[key], sort_keys=True))
        for note in result["notes"]:
            print(note)
    return {"PASS": 0, "WARN": 1, "FAIL": 2}[result["verdict"]]
