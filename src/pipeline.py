"""
Misconfig Auto-Remediation Pipeline
Complete orchestration of scanning, triaging, and remediation
"""
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from src.scanners.runner import ScannerRunner
from src.triage.engine import TriageEngine
from src.remediation.engine import RemediationEngine, RemediationAction
from src.models import NormalizedFinding, TriageDecision
from src.config import Config

logger = logging.getLogger(__name__)


class RemediationPipeline:
    """
    Complete remediation pipeline
    
    Workflow:
    1. SCAN: Execute security scanners (Checkov, ScoutSuite, CloudSploit)
    2. NORMALIZE: Convert scanner outputs to standard format
    3. TRIAGE: Analyze findings and make remediation decisions
    4. REMEDIATE: Execute approved remediation actions
    5. REPORT: Generate results and status
    """
    
    def __init__(
        self,
        terraform_dir: str = "./iac/terraform",
        output_dir: str = "./remediation_results",
        dry_run: bool = False,
    ):
        self.terraform_dir = terraform_dir
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.dry_run = dry_run
        
        # Initialize components
        self.scanner_runner = ScannerRunner(output_dir=str(self.output_dir / "scans"))
        self.triage_engine = TriageEngine(
            config={
                'auto_remediate_threshold': Config.AUTO_REMEDIATE_SEVERITY_THRESHOLD,
                'high_risk_resources': ['prod', 'production', 'critical'],
            }
        )
        self.remediation_engine = RemediationEngine(
            terraform_dir=terraform_dir,
            ansible_playbooks_dir=str(self.output_dir / "playbooks"),
            dry_run=dry_run,
        )
        
        # Pipeline results
        self.scan_results = []
        self.all_findings = []
        self.triage_decisions = []
        self.remediation_actions = []
        self.pipeline_start_time = None
        self.pipeline_end_time = None
    
    def run_complete_pipeline(self) -> Dict[str, Any]:
        """
        Execute complete remediation pipeline
        Returns: Final report with all results
        """
        
        logger.info("=" * 80)
        logger.info("MISCONFIG AUTO-REMEDIATION PIPELINE STARTED")
        logger.info("=" * 80)
        
        self.pipeline_start_time = datetime.utcnow()
        
        try:
            # Step 1: SCAN
            logger.info("\n[STEP 1/4] SCANNING for misconfigurations...")
            self.all_findings = self._step_scan()
            
            if not self.all_findings:
                logger.warning("No findings detected. Pipeline complete.")
                return self._generate_report()
            
            # Step 2: Already normalized by scanners (via NormalizedFinding)
            logger.info(f"\n[STEP 2/4] Normalized {len(self.all_findings)} findings")
            
            # Step 3: TRIAGE
            logger.info("\n[STEP 3/4] TRIAGING findings...")
            self.triage_decisions = self._step_triage(self.all_findings)
            
            # Step 4: REMEDIATE
            logger.info("\n[STEP 4/4] REMEDIATING...")
            self.remediation_actions = self._step_remediate(
                self.all_findings,
                self.triage_decisions
            )
            
            logger.info("=" * 80)
            logger.info("MISCONFIG AUTO-REMEDIATION PIPELINE COMPLETED")
            logger.info("=" * 80)
            
        except Exception as e:
            logger.error(f"Pipeline failed: {str(e)}", exc_info=True)
        
        finally:
            self.pipeline_end_time = datetime.utcnow()
            
            # Generate and save report
            report = self._generate_report()
            self._save_report(report)
            
            return report
    
    def _step_scan(self) -> List[NormalizedFinding]:
        """Execute scanning step"""
        
        all_findings = []
        
        # Run Checkov
        if Config.ENABLE_CHECKOV:
            logger.info("  - Running Checkov...")
            checkov_result = self.scanner_runner.run_checkov(self.terraform_dir)
            if checkov_result:
                all_findings.extend(checkov_result.findings)
                self.scan_results.append(checkov_result)
                logger.info(f"    ✓ Checkov: {len(checkov_result.findings)} findings")
        
        # Run ScoutSuite
        if Config.ENABLE_SCOUTSUITE:
            logger.info("  - Running ScoutSuite...")
            scoutsuite_result = self.scanner_runner.run_scoutsuite()
            if scoutsuite_result:
                all_findings.extend(scoutsuite_result.findings)
                self.scan_results.append(scoutsuite_result)
                logger.info(f"    ✓ ScoutSuite: {len(scoutsuite_result.findings)} findings")
        
        # Run CloudSploit
        if Config.ENABLE_CLOUDSPLOIT:
            logger.info("  - Running CloudSploit...")
            cloudsploit_result = self.scanner_runner.run_cloudsploit()
            if cloudsploit_result:
                all_findings.extend(cloudsploit_result.findings)
                self.scan_results.append(cloudsploit_result)
                logger.info(f"    ✓ CloudSploit: {len(cloudsploit_result.findings)} findings")
        
        logger.info(f"  Total: {len(all_findings)} findings collected")
        return all_findings
    
    def _step_triage(self, findings: List[NormalizedFinding]) -> List[TriageDecision]:
        """Execute triage step"""
        
        decisions = self.triage_engine.triage_batch(findings)
        
        # Analyze decisions
        auto_remediate = sum(1 for d in decisions if d.recommendation == "auto_remediate")
        manual_review = sum(1 for d in decisions if d.recommendation == "manual_review")
        
        logger.info(f"  Triage Results:")
        logger.info(f"    - Auto-remediate: {auto_remediate}")
        logger.info(f"    - Manual review: {manual_review}")
        logger.info(f"    - Avg confidence: {self.triage_engine.get_summary(decisions)['avg_confidence_score']:.2f}")
        
        return decisions
    
    def _step_remediate(
        self,
        findings: List[NormalizedFinding],
        decisions: List[TriageDecision],
    ) -> List[RemediationAction]:
        """Execute remediation step"""
        
        # Plan remediation actions
        logger.info("  Planning remediation actions...")
        actions = self.remediation_engine.plan_remediation(findings, decisions)
        logger.info(f"    - {len(actions)} remediation actions planned")
        
        if not actions:
            logger.info("  No remediation actions planned")
            return []
        
        # Execute remediation
        if Config.ENABLE_AUTO_REMEDIATION or not self.dry_run:
            logger.info("  Executing remediation actions...")
            
            results = self.remediation_engine.execute_batch(dry_run=self.dry_run)
            
            # Summarize results
            summary = self.remediation_engine.get_summary()
            logger.info(f"  Remediation Results:")
            logger.info(f"    - Success: {summary['success']}/{summary['total_actions']}")
            logger.info(f"    - Failed: {summary['failed']}/{summary['total_actions']}")
            logger.info(f"    - Success rate: {summary['success_rate']:.1f}%")
        else:
            logger.info("  DRY RUN MODE - Remediation actions not executed")
        
        return actions
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive pipeline report"""
        
        duration = (self.pipeline_end_time - self.pipeline_start_time).total_seconds() if self.pipeline_end_time else 0
        
        # Categorize findings by severity
        severity_breakdown = {}
        for finding in self.all_findings:
            severity = finding.severity
            if severity not in severity_breakdown:
                severity_breakdown[severity] = 0
            severity_breakdown[severity] += 1
        
        # Count by scanner
        scanner_breakdown = {}
        for finding in self.all_findings:
            scanner = finding.scanner
            if scanner not in scanner_breakdown:
                scanner_breakdown[scanner] = 0
            scanner_breakdown[scanner] += 1
        
        # Get remediation summary
        remediation_summary = self.remediation_engine.get_summary()
        
        # Triage summary
        triage_summary = self.triage_engine.get_summary(self.triage_decisions)
        
        report = {
            'pipeline_execution': {
                'start_time': self.pipeline_start_time.isoformat() if self.pipeline_start_time else None,
                'end_time': self.pipeline_end_time.isoformat() if self.pipeline_end_time else None,
                'duration_seconds': duration,
                'dry_run': self.dry_run,
            },
            'scan_results': {
                'total_scanners': len(self.scan_results),
                'total_findings': len(self.all_findings),
                'by_severity': severity_breakdown,
                'by_scanner': scanner_breakdown,
                'scanners': [
                    {
                        'name': sr.scanner_name,
                        'status': sr.status,
                        'findings_count': sr.findings_count,
                        'start_time': sr.start_time.isoformat(),
                        'end_time': sr.end_time.isoformat(),
                    }
                    for sr in self.scan_results
                ]
            },
            'triage_results': triage_summary,
            'remediation_results': remediation_summary,
            'findings_summary': {
                'total': len(self.all_findings),
                'high_severity': severity_breakdown.get('CRITICAL', 0) + severity_breakdown.get('HIGH', 0),
                'critical': severity_breakdown.get('CRITICAL', 0),
                'auto_remediate_eligible': sum(1 for d in self.triage_decisions if d.recommendation == "auto_remediate"),
                'manual_review_required': sum(1 for d in self.triage_decisions if d.recommendation == "manual_review"),
            },
            'recommendations': self._generate_recommendations(),
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations from pipeline results"""
        
        recommendations = []
        
        # Check for high severity findings
        high_severity_count = sum(
            1 for f in self.all_findings
            if f.severity in ['CRITICAL', 'HIGH']
        )
        if high_severity_count > 0:
            recommendations.append(
                f"Address {high_severity_count} high-severity findings immediately"
            )
        
        # Check for manual reviews
        manual_count = sum(
            1 for d in self.triage_decisions
            if d.recommendation == "manual_review"
        )
        if manual_count > 0:
            recommendations.append(
                f"Review and approve {manual_count} findings for remediation"
            )
        
        # Check remediation success rate
        if self.remediation_engine.execution_results:
            remediation_summary = self.remediation_engine.get_summary()
            success_rate = remediation_summary['success_rate']
            if success_rate < 100:
                recommendations.append(
                    f"Investigate {remediation_summary['failed']} failed remediation actions"
                )
        
        # Recommendations based on resource types
        resource_types = set(f.resource_type for f in self.all_findings)
        if 's3' in resource_types:
            recommendations.append(
                "Review S3 bucket policies and access controls"
            )
        if 'security_group' in resource_types or 'sg' in resource_types:
            recommendations.append(
                "Audit security group ingress/egress rules"
            )
        if 'iam' in resource_types:
            recommendations.append(
                "Review IAM policies and apply least privilege principle"
            )
        
        return recommendations
    
    def _save_report(self, report: Dict[str, Any]) -> None:
        """Save pipeline report to file"""
        
        report_path = self.output_dir / f"pipeline_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"Report saved to {report_path}")
        except Exception as e:
            logger.error(f"Failed to save report: {str(e)}")
    
    def export_findings_json(self) -> Path:
        """Export normalized findings as JSON"""
        
        findings_path = self.output_dir / f"findings_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            findings_data = [
                json.loads(f.json())
                for f in self.all_findings
            ]
            with open(findings_path, 'w') as f:
                json.dump(
                    {
                        'total': len(findings_data),
                        'findings': findings_data,
                    },
                    f,
                    indent=2,
                    default=str
                )
            logger.info(f"Findings exported to {findings_path}")
            return findings_path
        except Exception as e:
            logger.error(f"Failed to export findings: {str(e)}")
            return None
    
    def export_remediation_actions(self) -> Path:
        """Export remediation actions as JSON"""
        
        actions_path = self.output_dir / f"remediation_actions_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            actions_data = [a.to_dict() for a in self.remediation_actions]
            with open(actions_path, 'w') as f:
                json.dump(
                    {
                        'total': len(actions_data),
                        'actions': actions_data,
                    },
                    f,
                    indent=2,
                    default=str
                )
            logger.info(f"Remediation actions exported to {actions_path}")
            return actions_path
        except Exception as e:
            logger.error(f"Failed to export remediation actions: {str(e)}")
            return None


def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description="Misconfig Auto-Remediation Pipeline"
    )
    
    parser.add_argument(
        '--terraform-dir',
        default='./iac/terraform',
        help='Path to Terraform directory'
    )
    parser.add_argument(
        '--output-dir',
        default='./remediation_results',
        help='Output directory for results'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Run in dry-run mode without executing remediations'
    )
    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Logging level'
    )
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run pipeline
    pipeline = RemediationPipeline(
        terraform_dir=args.terraform_dir,
        output_dir=args.output_dir,
        dry_run=args.dry_run,
    )
    
    report = pipeline.run_complete_pipeline()
    
    # Export data
    pipeline.export_findings_json()
    pipeline.export_remediation_actions()
    
    # Print summary
    print("\n" + "=" * 80)
    print("PIPELINE SUMMARY")
    print("=" * 80)
    print(json.dumps(report, indent=2, default=str))
    print("=" * 80)


if __name__ == '__main__':
    main()
