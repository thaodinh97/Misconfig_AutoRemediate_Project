#!/usr/bin/env python3
"""
Misconfig Auto-Remediation Pipeline - Main Entry Point
Execute the complete pipeline: Scan → Normalize → Triage → Remediate
"""
import sys
import logging
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

from src.pipeline import RemediationPipeline
from src.config import Config

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """
    Run the complete remediation pipeline
    """
    
    print("\n" + "=" * 100)
    print(" " * 20 + "MISCONFIG AUTO-REMEDIATION PIPELINE")
    print("=" * 100)
    print()
    print("WORKFLOW:")
    print("  1. SCAN     → Security scanners (Checkov, ScoutSuite, CloudSploit)")
    print("  2. NORMALIZE → Convert scanner outputs to standard format")
    print("  3. TRIAGE   → Analyze and make remediation decisions")
    print("  4. REMEDIATE → Execute approved remediation actions")
    print()
    print("=" * 100)
    print()
    
    # Initialize pipeline
    pipeline = RemediationPipeline(
        terraform_dir="./iac/terraform",
        output_dir="./remediation_results",
        dry_run=False,  # Set to True for testing
    )
    
    # Run complete pipeline
    try:
        report = pipeline.run_complete_pipeline()
        
        # Export results
        findings_file = pipeline.export_findings_json()
        actions_file = pipeline.export_remediation_actions()
        
        print("\n" + "=" * 100)
        print("FINAL REPORT")
        print("=" * 100)
        print()
        print(f"Execution Time: {report['pipeline_execution']['duration_seconds']:.2f} seconds")
        print()
        print("SCAN RESULTS:")
        print(f"  Total Findings: {report['scan_results']['total_findings']}")
        print(f"  By Severity: {report['scan_results']['by_severity']}")
        print(f"  By Scanner: {report['scan_results']['by_scanner']}")
        print()
        print("TRIAGE RESULTS:")
        triage = report['triage_results']
        print(f"  Auto-Remediate: {triage['auto_remediate']} ({triage['auto_remediate_percentage']:.1f}%)")
        print(f"  Manual Review: {triage['manual_review']} ({triage['manual_review_percentage']:.1f}%)")
        print(f"  Avg Confidence: {triage['avg_confidence_score']:.3f}")
        print()
        print("REMEDIATION RESULTS:")
        remediation = report['remediation_results']
        print(f"  Total Actions: {remediation['total_actions']}")
        print(f"  Success: {remediation['success']}")
        print(f"  Failed: {remediation['failed']}")
        print(f"  Success Rate: {remediation['success_rate']:.1f}%")
        print()
        print("RECOMMENDATIONS:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"  {i}. {rec}")
        print()
        print("=" * 100)
        print()
        
        if findings_file:
            print(f"✓ Findings exported to: {findings_file}")
        if actions_file:
            print(f"✓ Remediation actions exported to: {actions_file}")
        
        print()
        print("Pipeline execution completed successfully!")
        print()
        
    except Exception as e:
        logger.error(f"Pipeline failed: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
