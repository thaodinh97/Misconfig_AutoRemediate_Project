"""
Auto-notification service that watches for CloudTrail events and sends Slack alerts.
This is the missing piece that auto-triggers notifications when config changes.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import time

from ..models import NormalizedFinding
from .notifications import notify_from_findings

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]


class AutoNotificationService:
    """
    Automatically detects findings and sends Slack notifications.
    
    Watches for:
    1. CloudTrail events (config changes)
    2. Triage decisions (manual review required)
    3. Critical findings (CRITICAL/HIGH severity)
    
    Then sends Slack notifications to alert the team.
    """
    
    def __init__(
        self,
        findings_dir: str = "artifacts/findings",
        decisions_dir: str = "artifacts/decisions",
        notification_dir: str = "artifacts/auto_notifications"
    ):
        self.findings_dir = Path(findings_dir)
        self.decisions_dir = Path(decisions_dir)
        self.notification_dir = Path(notification_dir)
        self.notification_dir.mkdir(parents=True, exist_ok=True)
        self.processed_findings: set = set()
        
    def process_new_findings(
        self,
        findings: List[Dict[str, Any]],
        decisions: List[Dict[str, Any]],
        auto_dispatch: bool = True
    ) -> Dict[str, Any]:
        """
        Process new findings and send notifications.
        
        Args:
            findings: List of normalized findings
            decisions: List of triage decisions
            auto_dispatch: Whether to send Slack/Teams immediately
            
        Returns:
            Dict with notification summary
        """
        logger.info(f"Processing {len(findings)} findings for notifications")
        
        # Filter for new findings
        new_findings = self._filter_new_findings(findings)
        logger.info(f"Found {len(new_findings)} new findings")
        
        if not new_findings:
            logger.info("No new findings to notify")
            return {'status': 'no_new_findings', 'count': 0}
        
        # Convert to NormalizedFinding objects
        normalized_findings = []
        for finding in new_findings:
            try:
                if isinstance(finding, dict):
                    normalized_findings.append(NormalizedFinding(**finding))
                else:
                    normalized_findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to parse finding: {e}")
                continue
        
        if not normalized_findings:
            logger.warning("No valid findings after normalization")
            return {'status': 'invalid_findings', 'count': 0}
        
        # Build and dispatch notifications
        try:
            result = notify_from_findings(
                findings=normalized_findings,
                decisions=decisions,
                dispatch=auto_dispatch,
                output_dir=str(self.notification_dir)
            )
            
            # Mark findings as processed
            for finding in new_findings:
                self.processed_findings.add(finding.get('finding_id'))
            
            return {
                'status': 'success',
                'findings_count': len(new_findings),
                'notification_result': result
            }
            
        except Exception as e:
            logger.error(f"Failed to send notifications: {e}", exc_info=True)
            return {
                'status': 'notification_failed',
                'error': str(e),
                'findings_count': len(new_findings)
            }
    
    def _filter_new_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter to only new findings not yet notified"""
        new = []
        for finding in findings:
            finding_id = finding.get('finding_id')
            if finding_id not in self.processed_findings:
                new.append(finding)
        return new
    
    def watch_and_notify(
        self,
        findings_file: str,
        decisions_file: str,
        poll_interval: int = 10,
        auto_dispatch: bool = True
    ) -> None:
        """
        Watch findings file for changes and auto-notify.
        
        Args:
            findings_file: Path to findings JSON file
            decisions_file: Path to decisions JSON file
            poll_interval: How often to check for new findings (seconds)
            auto_dispatch: Whether to send Slack immediately
        """
        logger.info(f"Starting auto-notification service")
        logger.info(f"Watching: {findings_file}")
        logger.info(f"Poll interval: {poll_interval}s")
        logger.info(f"Auto-dispatch: {auto_dispatch}")
        
        last_modified = 0
        
        while True:
            try:
                findings_path = Path(findings_file)
                decisions_path = Path(decisions_file)
                
                if not findings_path.exists() or not decisions_path.exists():
                    logger.debug(f"Waiting for files to be created...")
                    time.sleep(poll_interval)
                    continue
                
                current_modified = findings_path.stat().st_mtime
                
                # Check if file was modified
                if current_modified > last_modified:
                    logger.info(f"Finding changes detected, processing...")
                    
                    try:
                        findings = json.loads(findings_path.read_text())
                        decisions = json.loads(decisions_path.read_text())
                        
                        # Handle wrapped format
                        if isinstance(findings, dict) and 'findings' in findings:
                            findings = findings['findings']
                        if isinstance(decisions, dict) and 'decisions' in decisions:
                            decisions = decisions['decisions']
                        
                        result = self.process_new_findings(
                            findings=findings if isinstance(findings, list) else [],
                            decisions=decisions if isinstance(decisions, list) else [],
                            auto_dispatch=auto_dispatch
                        )
                        
                        logger.info(f"Notification result: {result['status']}")
                        
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse JSON: {e}")
                    
                    last_modified = current_modified
                
                time.sleep(poll_interval)
                
            except KeyboardInterrupt:
                logger.info("Auto-notification service stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in watch loop: {e}", exc_info=True)
                time.sleep(poll_interval)


def cli_notify(
    findings_file: str,
    decisions_file: str,
    auto_dispatch: bool = True
) -> int:
    """
    CLI command to send notifications immediately for existing findings.
    
    Usage:
        python -m src.triage.auto_notify \
            --findings ./scan_results/findings.json \
            --decisions ./triage_results/decisions.json \
            --dispatch-live
    """
    logger.info(f"Processing findings for notification: {findings_file}")
    
    try:
        findings_data = json.loads(Path(findings_file).read_text())
        decisions_data = json.loads(Path(decisions_file).read_text())
        
        # Handle wrapped format
        if isinstance(findings_data, dict) and 'findings' in findings_data:
            findings = findings_data['findings']
        else:
            findings = findings_data if isinstance(findings_data, list) else []
        
        if isinstance(decisions_data, dict) and 'decisions' in decisions_data:
            decisions = decisions_data['decisions']
        else:
            decisions = decisions_data if isinstance(decisions_data, list) else []
        
        service = AutoNotificationService()
        result = service.process_new_findings(
            findings=findings,
            decisions=decisions,
            auto_dispatch=auto_dispatch
        )
        
        logger.info(json.dumps(result, indent=2, default=str))
        return 0 if result['status'] == 'success' else 1
        
    except Exception as e:
        logger.error(f"Failed to process findings: {e}", exc_info=True)
        return 1


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Auto-notification service for CloudTrail findings"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Notify command (one-shot)
    notify_parser = subparsers.add_parser('notify', help='Send notifications for findings')
    notify_parser.add_argument('--findings', required=True, help='Findings JSON file')
    notify_parser.add_argument('--decisions', required=True, help='Decisions JSON file')
    notify_parser.add_argument('--dispatch-live', action='store_true', help='Send Slack notifications')
    
    # Watch command (continuous)
    watch_parser = subparsers.add_parser('watch', help='Watch for changes and auto-notify')
    watch_parser.add_argument('--findings', required=True, help='Findings JSON file to watch')
    watch_parser.add_argument('--decisions', required=True, help='Decisions JSON file')
    watch_parser.add_argument('--poll-interval', type=int, default=10, help='Poll interval in seconds')
    watch_parser.add_argument('--dispatch-live', action='store_true', help='Send Slack notifications')
    
    args = parser.parse_args()
    
    if args.command == 'notify':
        return cli_notify(
            findings_file=args.findings,
            decisions_file=args.decisions,
            auto_dispatch=args.dispatch_live
        )
    
    elif args.command == 'watch':
        service = AutoNotificationService()
        service.watch_and_notify(
            findings_file=args.findings,
            decisions_file=args.decisions,
            poll_interval=args.poll_interval,
            auto_dispatch=args.dispatch_live
        )
        return 0
    
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
