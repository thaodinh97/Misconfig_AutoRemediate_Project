"""Unified remediation runner for the capstone project."""
from __future__ import annotations

import argparse
import importlib
import sys
from typing import List

FLOW_MODULES = {
    "openstack-runtime": "src.remediation.runtime_executor",
    "aws-runtime": "src.remediation.aws_runtime_executor",
    "hybrid-dispatch": "src.remediation.hybrid_dispatch",
    "iac-pr": "src.remediation.iac_pr_prepare",
    "open-pr": "src.remediation.open_fix_pr",
    "opa-ticket": "src.remediation.opa_ticket",
    "drift-reconcile": "src.remediation.drift_reconcile",
}


def run_flow(module_name: str, module_args: List[str]) -> int:
    module = importlib.import_module(module_name)
    if not hasattr(module, "main"):
        raise RuntimeError(f"Remediation module {module_name} does not expose a main() entrypoint")

    original_argv = sys.argv
    sys.argv = [module_name, *module_args]
    try:
        return module.main()
    finally:
        sys.argv = original_argv


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a remediation flow using existing project remediation modules"
    )
    parser.add_argument(
        "--flow",
        required=True,
        choices=list(FLOW_MODULES),
        help="Which remediation flow to run",
    )
    parser.add_argument(
        "module_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to the underlying remediation module",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    module_name = FLOW_MODULES[args.flow]
    module_args = args.module_args or []
    if module_args and module_args[0] == "--":
        module_args = module_args[1:]
    return run_flow(module_name, module_args)


if __name__ == "__main__":
    raise SystemExit(main())
