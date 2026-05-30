#!/usr/bin/env python3
"""
Test script: End-to-end auto-notification flow
Demonstrates: CloudTrail Event → Detect → Triage → Slack Alert

This script simulates a CloudTrail configuration change event and shows
how the system automatically detects it and sends a Slack notification.
"""
import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.models import NormalizedFinding
from src.triage.notifications import notify_from_findings


def create_sample_cloudtrail_event():
    """Create a sample CloudTrail event for S3 public access change"""
    return {
        "EventID": "12345678-1234-1234-1234-123456789012",
        "EventName": "PutBucketPublicAccessBlock",
        "EventTime": datetime.now(timezone.utc).isoformat(),
        "EventSource": "s3.amazonaws.com",
        "Username": "cloud-admin@example.com",
        "Resources": [{
            "ARN": "arn:aws:s3:::my-sensitive-bucket",
            "AccountId": "123456789012",
            "Type": "AWS::S3::Bucket"
        }],
        "CloudTrailEvent": json.dumps({
            "bucketName": "my-sensitive-bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,  # ❌ Public access allowed!
                "BlockPublicPolicy": False,
                "IgnorePublicAcls": False,
                "RestrictPublicBuckets": False
            }
        })
    }


def create_sample_findings():
    """Create sample normalized findings from CloudTrail event"""
    return [
        {
            "finding_id": "f001_s3_public_access",
            "title": "S3 Bucket Public Access Detected",
            "description": "S3 bucket allows public read/write access. This bucket may contain sensitive data.",
            "resource_type": "s3_bucket",
            "resource_id": "arn:aws:s3:::my-sensitive-bucket",
            "severity": "CRITICAL",
            "scanner": "cloudtrail",
            "event_name": "PutBucketPublicAccessBlock",
            "event_source": "s3.amazonaws.com",
            "event_time": datetime.now(timezone.utc).isoformat(),
            "owner": "cloud-admin@example.com",
            "account_id": "123456789012",
            "region": "us-east-1",
            "remediation_available": True
        },
        {
            "finding_id": "f002_s3_unencrypted",
            "title": "S3 Bucket Not Encrypted",
            "description": "S3 bucket does not have default encryption enabled.",
            "resource_type": "s3_bucket",
            "resource_id": "arn:aws:s3:::my-sensitive-bucket",
            "severity": "HIGH",
            "scanner": "cloudtrail",
            "event_name": "PutBucketPublicAccessBlock",
            "event_source": "s3.amazonaws.com",
            "event_time": datetime.now(timezone.utc).isoformat(),
            "owner": "cloud-admin@example.com",
            "account_id": "123456789012",
            "region": "us-east-1",
            "remediation_available": True
        }
    ]


def create_sample_decisions():
    """Create sample triage decisions"""
    return [
        {
            "finding_id": "f001_s3_public_access",
            "severity": "CRITICAL",
            "recommendation": "manual_review",
            "confidence": 0.95,
            "reason": "Public S3 bucket requires manual review to determine if intentional or misconfiguration"
        },
        {
            "finding_id": "f002_s3_unencrypted",
            "severity": "HIGH",
            "recommendation": "manual_review",
            "confidence": 0.87,
            "reason": "Unencrypted storage requires security team review"
        }
    ]


def test_auto_notification():
    """Test the auto-notification flow"""
    print("=" * 70)
    print("🚀 CloudTrail Auto-Notification Test")
    print("=" * 70)
    
    # Check Slack webhook
    slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
    if not slack_webhook:
        print("\n⚠️  WARNING: SLACK_WEBHOOK_URL not set")
        print("   Notifications will be saved to artifacts but NOT sent to Slack")
        print("   To send real notifications, set:")
        print("   export SLACK_WEBHOOK_URL='https://hooks.slack.com/services/...'")
        dispatch = False
    else:
        print(f"\n✅ Slack webhook configured")
        dispatch = True
    
    # Create sample data
    print("\n1️⃣  Creating sample CloudTrail event...")
    ct_event = create_sample_cloudtrail_event()
    print(f"   ✓ Event: {ct_event['EventName']} on {ct_event['Resources'][0]['ARN']}")
    
    print("\n2️⃣  Processing findings...")
    findings = create_sample_findings()
    print(f"   ✓ Found {len(findings)} issues:")
    for f in findings:
        print(f"      - [{f['severity']}] {f['title']}")
    
    print("\n3️⃣  Running triage...")
    decisions = create_sample_decisions()
    print(f"   ✓ Generated {len(decisions)} decisions:")
    for d in decisions:
        print(f"      - {d['recommendation'].upper()}: {d['finding_id']}")
    
    print("\n4️⃣  Sending notifications...")
    print(f"   Dispatch to Slack: {dispatch}")
    
    # Convert findings to NormalizedFinding objects
    normalized_findings = []
    for finding in findings:
        try:
            normalized_findings.append(NormalizedFinding(**finding))
        except Exception as e:
            print(f"   ⚠️  Failed to parse finding: {e}")
            continue
    
    # Send notifications
    try:
        output_dir = PROJECT_ROOT / "artifacts" / "test_auto_notifications"
        result = notify_from_findings(
            findings=normalized_findings,
            decisions=decisions,
            dispatch=dispatch,
            output_dir=str(output_dir)
        )
        
        print(f"\n✅ Notification Result:")
        print(f"   Status: {result.get('status')}")
        print(f"   Notifications generated: {len(result.get('notifications_generated', {}))}")
        
        if result.get('dispatch_results'):
            print(f"\n📤 Dispatch Summary:")
            for channel, status in result['dispatch_results'].items():
                emoji = "✓" if status.get('sent') else "✗"
                print(f"   {emoji} {channel}: {status.get('message', 'OK')}")
        
        # Show artifact locations
        print(f"\n📁 Artifact saved to:")
        print(f"   {output_dir}")
        
        if (output_dir / "notification_bundle.json").exists():
            print(f"\n📋 Notification Preview:")
            bundle = json.loads((output_dir / "notification_bundle.json").read_text())
            for notif in bundle.get("slack_notifications", [])[:2]:
                print(f"\n   {notif.get('blocks', [{}])[0].get('text', {}).get('text', '...')[:60]}...")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


def main():
    """Main entry point"""
    print("\n" + "=" * 70)
    print("CloudTrail Auto-Notification Demo")
    print("Scenario: S3 bucket configuration changed to allow public access")
    print("=" * 70)
    
    # Test the flow
    exit_code = test_auto_notification()
    
    # Summary
    print("\n" + "=" * 70)
    if exit_code == 0:
        print("✅ Test completed successfully!")
        print("\nWhat happened:")
        print("1. CloudTrail detected S3 configuration change")
        print("2. System scanned for misconfigurations (public access, no encryption)")
        print("3. Findings were triaged (CRITICAL/HIGH severity)")
        print("4. Slack notifications were generated and dispatched")
        print("\nNext steps:")
        print("- Check #security-alerts on Slack for notifications")
        print("- Review detailed findings in artifacts/test_auto_notifications/")
        print("- Run remediation to fix the misconfiguration")
    else:
        print("❌ Test failed - check errors above")
    
    print("=" * 70 + "\n")
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
