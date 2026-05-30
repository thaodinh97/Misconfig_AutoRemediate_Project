#!/usr/bin/env python3
"""
Hybrid remediation dispatcher
Splits findings by provider and runs appropriate executors
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_json(path: str) -> List[Dict[str, Any]]:
    """Load JSON findings or decisions"""
    with open(path, 'r') as f:
        data = json.load(f)
    
    # Handle wrapped format
    if isinstance(data, dict):
        if 'findings' in data:
            return data['findings']
        if 'decisions' in data:
            return data['decisions']
    
    return data if isinstance(data, list) else []


def split_findings_by_provider(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Split findings into AWS and OpenStack groups"""
    result = {"aws": [], "openstack": []}
    
    for finding in findings:
        provider = str(finding.get("provider", "aws")).lower()
        if provider not in result:
            result[provider] = []
        result[provider].append(finding)
    
    return result


def filter_decisions_by_finding_ids(decisions: List[Dict[str, Any]], finding_ids: set[str]) -> List[Dict[str, Any]]:
    """Filter decisions to only include specific finding IDs"""
    return [d for d in decisions if str(d.get("finding_id", "")) in finding_ids]


def run_executor(
    flow: str,
    findings_path: str,
    decisions_path: str,
    provider: str,
    output_events: str,
    output_findings: str,
    args: List[str],
) -> int:
    """Run a remediation executor flow"""
    cmd = [
        sys.executable, "-m", "src.remediation.runner",
        "--flow", flow,
        "--",
        "--findings", findings_path,
        "--decisions", decisions_path,
        "--provider", provider,
        "--output-events", output_events,
        "--output-findings-after", output_findings,
    ]
    
    # Add additional arguments
    cmd.extend(args)
    
    logger.info(f"Running {flow} executor: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=Path(__file__).parent.parent.parent)
    return result.returncode


def save_json(path: str, data: List[Dict[str, Any]]) -> None:
    """Save JSON data"""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def merge_json_files(aws_file: str, openstack_file: str, output_file: str) -> None:
    """Merge two JSON files"""
    aws_data = load_json(aws_file) if Path(aws_file).exists() else []
    openstack_data = load_json(openstack_file) if Path(openstack_file).exists() else []
    
    merged = aws_data + openstack_data
    save_json(output_file, merged)
    logger.info(f"Merged {len(aws_data)} AWS + {len(openstack_data)} OpenStack items → {output_file}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dispatch hybrid findings to appropriate remediation executors"
    )
    parser.add_argument(
        "--findings",
        required=True,
        help="Hybrid findings JSON file (output from scanner runner)"
    )
    parser.add_argument(
        "--decisions",
        required=True,
        help="Triage decisions JSON file"
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/remediation",
        help="Output directory for remediation events and findings"
    )
    parser.add_argument(
        "--approve-all-manual",
        action="store_true",
        help="Approve all manual-review findings for execution"
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute provider commands for real"
    )
    parser.add_argument(
        "--simulate-success",
        action="store_true",
        help="Simulate success without executing provider commands"
    )
    parser.add_argument(
        "--skip-openstack",
        action="store_true",
        help="Skip OpenStack remediation"
    )
    parser.add_argument(
        "--skip-aws",
        action="store_true",
        help="Skip AWS remediation"
    )
    parser.add_argument(
        "--pipeline-source",
        default="hybrid-remediation",
        help="Pipeline source identifier"
    )
    parser.add_argument(
        "--branch",
        default="",
        help="Git branch name"
    )
    parser.add_argument(
        "--commit-sha",
        default="",
        help="Git commit SHA"
    )
    
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    
    # Load data
    logger.info(f"Loading findings from {args.findings}")
    findings = load_json(args.findings)
    
    logger.info(f"Loading decisions from {args.decisions}")
    decisions = load_json(args.decisions)
    
    logger.info(f"Loaded {len(findings)} findings and {len(decisions)} decisions")
    
    # Split findings by provider
    findings_by_provider = split_findings_by_provider(findings)
    aws_findings = findings_by_provider.get("aws", [])
    openstack_findings = findings_by_provider.get("openstack", [])
    
    logger.info(f"AWS findings: {len(aws_findings)}")
    logger.info(f"OpenStack findings: {len(openstack_findings)}")
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Prepare temporary files
    aws_findings_file = output_dir / "hybrid_aws_findings.json"
    openstack_findings_file = output_dir / "hybrid_openstack_findings.json"
    aws_decisions_file = output_dir / "hybrid_aws_decisions.json"
    openstack_decisions_file = output_dir / "hybrid_openstack_decisions.json"
    
    aws_events_file = output_dir / "hybrid_aws_runtime_events.json"
    aws_findings_after = output_dir / "hybrid_aws_findings_after_runtime.json"
    openstack_events_file = output_dir / "hybrid_openstack_runtime_events.json"
    openstack_findings_after = output_dir / "hybrid_openstack_findings_after_runtime.json"
    
    # Save split findings and decisions
    if aws_findings:
        save_json(str(aws_findings_file), aws_findings)
        aws_decision_ids = {f.get("finding_id") for f in aws_findings}
        aws_decisions = filter_decisions_by_finding_ids(decisions, aws_decision_ids)
        save_json(str(aws_decisions_file), aws_decisions)
    
    if openstack_findings:
        save_json(str(openstack_findings_file), openstack_findings)
        openstack_decision_ids = {f.get("finding_id") for f in openstack_findings}
        openstack_decisions = filter_decisions_by_finding_ids(decisions, openstack_decision_ids)
        save_json(str(openstack_decisions_file), openstack_decisions)
    
    # Build executor arguments
    executor_args = []
    if args.approve_all_manual:
        executor_args.append("--approve-all-manual")
    if args.execute:
        executor_args.append("--execute")
    if args.simulate_success:
        executor_args.append("--simulate-success")
    if args.pipeline_source:
        executor_args.extend(["--pipeline-source", args.pipeline_source])
    if args.branch:
        executor_args.extend(["--branch", args.branch])
    if args.commit_sha:
        executor_args.extend(["--commit-sha", args.commit_sha])
    
    exit_code = 0
    
    # Run AWS remediation
    if aws_findings and not args.skip_aws:
        logger.info(f"Running AWS remediation for {len(aws_findings)} findings...")
        aws_exit = run_executor(
            flow="aws-runtime",
            findings_path=str(aws_findings_file),
            decisions_path=str(aws_decisions_file),
            provider="aws",
            output_events=str(aws_events_file),
            output_findings=str(aws_findings_after),
            args=executor_args,
        )
        exit_code |= aws_exit
    
    # Run OpenStack remediation
    if openstack_findings and not args.skip_openstack:
        logger.info(f"Running OpenStack remediation for {len(openstack_findings)} findings...")
        openstack_exit = run_executor(
            flow="openstack-runtime",
            findings_path=str(openstack_findings_file),
            decisions_path=str(openstack_decisions_file),
            provider="openstack",
            output_events=str(openstack_events_file),
            output_findings=str(openstack_findings_after),
            args=executor_args,
        )
        exit_code |= openstack_exit
    
    # Merge results
    final_events_file = output_dir / "runtime_events.json"
    final_findings_after = output_dir / "findings_after_runtime.json"
    
    merge_json_files(str(aws_events_file), str(openstack_events_file), str(final_events_file))
    merge_json_files(str(aws_findings_after), str(openstack_findings_after), str(final_findings_after))
    
    logger.info(f"Hybrid remediation completed. Results:")
    logger.info(f"  Events: {final_events_file}")
    logger.info(f"  Findings after: {final_findings_after}")
    
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
