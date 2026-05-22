"""
Build owner notification and ticket payloads from findings + triage decisions.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

from .engine import load_findings
from ..siem.publisher import load_decisions

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)
HIGH_RISK_SEVERITIES = {"HIGH", "CRITICAL"}


def save_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def resolve_owner(finding) -> str:
    tags = finding.tags or {}
    metadata = finding.metadata or {}
    return (
        tags.get("owner")
        or metadata.get("asset_owner")
        or metadata.get("owner")
        or os.getenv("DEFAULT_SECURITY_OWNER", "security-team@example.com")
    )


def build_notifications(findings, decisions: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    findings_by_id = {finding.finding_id: finding for finding in findings}
    bundle: Dict[str, List[Dict[str, Any]]] = {
        "owner_notifications": [],
        "jira_tickets": [],
        "servicenow_incidents": [],
        "chat_notifications": [],
    }

    for decision in decisions:
        if decision.get("recommendation") != "manual_review":
            continue

        finding = findings_by_id.get(str(decision.get("finding_id") or ""))
        if not finding:
            continue

        owner = resolve_owner(finding)
        severity = str(getattr(finding, "severity", "MEDIUM"))
        notification = {
            "finding_id": finding.finding_id,
            "owner": owner,
            "channel": "email",
            "severity": severity,
            "title": finding.title,
            "finding_code": finding.finding_code,
            "scanner": finding.scanner,
            "provider": finding.provider,
            "resource_type": finding.resource_type,
            "resource_id": finding.resource_id,
            "reasoning": decision.get("reasoning"),
            "recommendation": decision.get("recommendation"),
        }
        bundle["owner_notifications"].append(notification)

        if severity not in HIGH_RISK_SEVERITIES:
            continue

        description_lines = [
            f"Owner: {owner}",
            f"Finding ID: {finding.finding_id}",
            f"Finding Code: {finding.finding_code}",
            f"Resource: {finding.resource_type} ({finding.resource_id})",
            f"Provider/Scanner: {finding.provider}/{finding.scanner}",
            f"Severity: {severity}",
            f"Recommendation: {decision.get('recommendation')}",
            f"Reasoning: {decision.get('reasoning')}",
        ]
        ticket_summary = f"[Security Review] {finding.title}"

        bundle["jira_tickets"].append(
            {
                "summary": ticket_summary,
                "description": "\n".join(description_lines),
                "priority": "Highest" if severity == "CRITICAL" else "High",
                "labels": ["manual-review", "misconfiguration"],
                "owner": owner,
                "project_key": os.getenv("JIRA_PROJECT_KEY", "SEC"),
            }
        )
        bundle["servicenow_incidents"].append(
            {
                "short_description": ticket_summary,
                "description": "\n".join(description_lines),
                "urgency": "1" if severity == "CRITICAL" else "2",
                "impact": "1" if severity == "CRITICAL" else "2",
                "assignment_group": os.getenv("SERVICENOW_ASSIGNMENT_GROUP", "Security Operations"),
                "caller_id": owner,
            }
        )
        bundle["chat_notifications"].append(
            {
                "channel": "slack" if os.getenv("SLACK_WEBHOOK_URL") else "teams" if os.getenv("TEAMS_WEBHOOK_URL") else "chatops",
                "owner": owner,
                "severity": severity,
                "title": finding.title,
                "message": f"{severity} manual review required for {finding.resource_type} {finding.resource_id}",
                "finding_id": finding.finding_id,
            }
        )

    return bundle


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build triage notification artifacts")
    parser.add_argument("--findings", required=True)
    parser.add_argument("--decisions", required=True)
    parser.add_argument("--output-dir", default="artifacts/triage_notifications")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    findings = load_findings(args.findings)
    decisions = load_decisions(args.decisions)
    bundle = build_notifications(findings, decisions)

    output_dir = Path(args.output_dir)
    for filename, payload in (
        ("owner_notifications.json", bundle["owner_notifications"]),
        ("jira_tickets.json", bundle["jira_tickets"]),
        ("servicenow_incidents.json", bundle["servicenow_incidents"]),
        ("chat_notifications.json", bundle["chat_notifications"]),
    ):
        save_json(output_dir / filename, payload)
    logger.info(
        "Generated %s owner notifications, %s JIRA payloads, %s ServiceNow payloads, and %s chat notifications",
        len(bundle["owner_notifications"]),
        len(bundle["jira_tickets"]),
        len(bundle["servicenow_incidents"]),
        len(bundle["chat_notifications"]),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
