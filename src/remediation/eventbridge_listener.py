"""
EventBridge listener for CloudTrail events.
Receives CloudTrail events from EventBridge, processes them through the pipeline,
and triggers remediation as needed.

Can be deployed as:
1. AWS Lambda function
2. Local service listening to SQS
3. Direct EventBridge rule target
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import boto3

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]


class EventBridgeCloudTrailListener:
    """
    Listens to CloudTrail events via EventBridge and processes them through the remediation pipeline.
    """
    
    def __init__(self, queue_url: Optional[str] = None, region: str = "us-east-1"):
        self.queue_url = queue_url
        self.region = region
        self.sqs_client = boto3.client('sqs', region_name=region)
        
    def lambda_handler(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """
        AWS Lambda entrypoint for EventBridge CloudTrail events.
        
        EventBridge can route CloudTrail events directly to Lambda or via SQS.
        This function processes the event and returns execution status.
        """
        logger.info(f"Received EventBridge event: {json.dumps(event, default=str)[:500]}")
        
        try:
            # Extract CloudTrail event(s) from EventBridge record
            finding_code = None
            if 'detail' in event:
                # Direct EventBridge format
                ct_event = event['detail']
                finding_code = ct_event.get('eventName', 'unknown')
            elif 'Records' in event:
                # SQS format (EventBridge -> SQS -> Lambda)
                ct_event = json.loads(event['Records'][0]['body'])
                finding_code = ct_event.get('eventName', 'unknown')
            else:
                ct_event = event
            
            logger.info(f"Processing CloudTrail event: {finding_code}")
            
            # Process event through pipeline
            result = self._process_cloudtrail_event(ct_event)
            
            logger.info(f"Event processing completed: {result}")
            return {
                'statusCode': 200,
                'body': json.dumps(result)
            }
            
        except Exception as e:
            logger.error(f"Error processing event: {e}", exc_info=True)
            return {
                'statusCode': 500,
                'body': json.dumps({'error': str(e)})
            }
    
    def _process_cloudtrail_event(self, ct_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single CloudTrail event through the full pipeline.
        
        Pipeline:
        1. Run CloudTrail scanner to detect issues
        2. Run drift detection if enabled
        3. Normalize findings
        4. Run triage engine
        5. If findings pass triage, trigger remediation
        """
        logger.info(f"Processing CloudTrail event: {ct_event.get('eventName')}")
        
        # Create temp files for processing
        temp_dir = Path("/tmp/artifacts")
        events_file = temp_dir / "cloudtrail_events.json"
        findings_file = temp_dir / "cloudtrail_findings.json"
        normalized_file = temp_dir / "cloudtrail_normalized.json"
        decisions_file = temp_dir / "cloudtrail_decisions.json"
        remediation_file = temp_dir / "cloudtrail_remediation.json"
        
        events_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Step 1: Save CloudTrail event
            events_file.write_text(json.dumps([ct_event], indent=2))
            logger.info(f"Saved CloudTrail event to {events_file}")
            
            # Step 2: Run drift detection (if terraform is available)
            result = self._run_drift_detection(events_file, findings_file)
            if result['drift_detected']:
                logger.warning(f"Drift detected: {result['change_count']} changes")
            
            # Step 3: Normalize findings
            normalized = self._normalize_findings(findings_file, normalized_file)
            logger.info(f"Normalized {len(normalized)} findings")
            
            if not normalized:
                logger.info("No findings to process")
                return {'status': 'no_findings'}
            
            # Step 4: Run triage
            decisions = self._run_triage(normalized_file, decisions_file)
            logger.info(f"Triage produced {len(decisions)} decisions")
            
            # Step 5: Trigger remediation if needed
            remediation_needed = [d for d in decisions if d.get('recommendation') == 'auto_remediate']
            if remediation_needed:
                logger.info(f"Triggering remediation for {len(remediation_needed)} findings")
                remediation_result = self._trigger_remediation(
                    findings_file, decisions_file, remediation_file
                )
                return {
                    'status': 'remediation_triggered',
                    'findings': len(normalized),
                    'decisions': len(decisions),
                    'remediation_count': len(remediation_needed),
                    'remediation_result': remediation_result
                }
            else:
                logger.info("No findings require auto-remediation")
                
                # Step 5b: Send notifications for manual review findings
                manual_review = [d for d in decisions if d.get('recommendation') == 'manual_review']
                if manual_review:
                    logger.info(f"Sending {len(manual_review)} manual review findings to notifications")
                    try:
                        from ..triage.notifications import notify_from_findings
                        notification_result = notify_from_findings(
                            findings=normalized,
                            decisions=decisions,
                            dispatch=True,
                            output_dir=Path("/tmp/artifacts/cloudtrail_notifications")
                        )
                        logger.info(f"Notifications sent: {notification_result}")
                        return {
                            'status': 'notifications_sent',
                            'findings': len(normalized),
                            'decisions': len(decisions),
                            'notifications': notification_result
                        }
                    except Exception as e:
                        logger.warning(f"Notification dispatch failed: {e}")
                
                return {
                    'status': 'findings_detected_no_remediation',
                    'findings': len(normalized),
                    'decisions': len(decisions),
                }
        
        finally:
            # Cleanup temp files
            for f in [events_file, findings_file, normalized_file, decisions_file]:
                if f.exists():
                    f.unlink()
    
    def _run_drift_detection(self, events_file: Path, output_file: Path) -> Dict[str, Any]:
        """Run CloudTrail drift detection"""
        try:
            cmd = [
                sys.executable, "-m", "src.scanners.cloudtrail_drift_detector",
                "--cloudtrail-events", str(events_file),
                "--output", str(output_file),
                "--pretty"
            ]
            
            result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
            if result.stderr:
                logger.info(f"Detector Output: {result.stderr}")
            
            if result.returncode != 0:
                logger.warning(f"Drift detection failed: {result.stderr}")
                return {'drift_detected': False, 'change_count': 0}
            
            if output_file.exists():
                data = json.loads(output_file.read_text())
                return {
                    'drift_detected': True,
                    'change_count': data.get('total_findings', 0)
                }
            return {'drift_detected': False, 'change_count': 0}
        
        except Exception as e:
            logger.warning(f"Drift detection error: {e}")
            return {'drift_detected': False, 'change_count': 0}
    
    def _normalize_findings(self, findings_file: Path, output_file: Path) -> List[Dict[str, Any]]:
        """Normalize findings using normalizer.py"""
        try:
            cmd = [
                sys.executable, str(REPO_ROOT / "normalizer.py"),
                "--input", str(findings_file),
                "--scanner", "cloudtrail",
                "--output", str(output_file),
                "--wrap"
            ]
            
            result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
            
            if result.returncode != 0:
                logger.warning(f"Normalization failed: {result.stderr}")
                return []
            
            if output_file.exists():
                data = json.loads(output_file.read_text())
                return data.get('findings', [])
            return []
        
        except Exception as e:
            logger.warning(f"Normalization error: {e}")
            return []
    
    def _run_triage(self, findings_file: Path, output_file: Path) -> List[Dict[str, Any]]:
        """Run triage engine"""
        try:
            cmd = [
                sys.executable, "-m", "src.triage.engine",
                "--input", str(findings_file),
                "--output", str(output_file),
                "--auto-remediate-threshold", "HIGH"
            ]
            
            result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
            
            if result.returncode != 0:
                logger.warning(f"Triage failed: {result.stderr}")
                return []
            
            if output_file.exists():
                data = json.loads(output_file.read_text())
                return data.get('decisions', [])
            return []
        
        except Exception as e:
            logger.warning(f"Triage error: {e}")
            return []
    
    def _trigger_remediation(
        self,
        findings_file: Path,
        decisions_file: Path,
        output_file: Path
    ) -> Dict[str, Any]:
        """Trigger hybrid remediation flow"""
        try:
            cmd = [
                sys.executable, "-m", "src.remediation.runner",
                "--flow", "hybrid-dispatch",
                "--",
                "--findings", str(findings_file),
                "--decisions", str(decisions_file),
                "--output-events", str(output_file)
            ]
            
            result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                logger.info("Remediation flow completed successfully")
                if output_file.exists():
                    return json.loads(output_file.read_text())
                return {'status': 'success'}
            else:
                logger.warning(f"Remediation flow failed: {result.stderr}")
                return {'status': 'failed', 'error': result.stderr}
        
        except Exception as e:
            logger.warning(f"Remediation error: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def listen_sqs(self, queue_url: str, max_messages: int = 10, wait_time: int = 20):
        """
        Listen for CloudTrail events from SQS queue.
        Useful for local development or persistent service deployment.
        """
        logger.info(f"Starting SQS listener on {queue_url}")
        
        while True:
            try:
                # Receive messages from queue
                response = self.sqs_client.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=max_messages,
                    WaitTimeSeconds=wait_time,
                    MessageAttributeNames=['All']
                )
                
                messages = response.get('Messages', [])
                if not messages:
                    logger.debug("No messages received, continuing...")
                    continue
                
                logger.info(f"Received {len(messages)} messages")
                
                for message in messages:
                    try:
                        # Parse the message body (should be CloudTrail event JSON)
                        body = json.loads(message['Body'])
                        
                        # Process the event
                        result = self._process_cloudtrail_event(body)
                        logger.info(f"Processed message: {result}")
                        
                        # Delete the message from queue
                        self.sqs_client.delete_message(
                            QueueUrl=queue_url,
                            ReceiptHandle=message['ReceiptHandle']
                        )
                        logger.info(f"Deleted message {message['MessageId']}")
                    
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse message body: {e}")
                        # Still delete the message to avoid infinite retry
                        self.sqs_client.delete_message(
                            QueueUrl=queue_url,
                            ReceiptHandle=message['ReceiptHandle']
                        )
                    
                    except Exception as e:
                        logger.error(f"Error processing message: {e}", exc_info=True)
                        # Don't delete on processing error - will retry
            
            except Exception as e:
                logger.error(f"SQS listener error: {e}", exc_info=True)
                # Wait before retrying
                import time
                time.sleep(5)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """AWS Lambda handler for EventBridge CloudTrail events"""
    listener = EventBridgeCloudTrailListener()
    return listener.lambda_handler(event, context)


def main():
    """CLI entrypoint"""
    parser = argparse.ArgumentParser(
        description="EventBridge listener for CloudTrail events"
    )
    parser.add_argument(
        '--mode',
        choices=['lambda', 'sqs-listener', 'process-file'],
        default='lambda',
        help='Execution mode'
    )
    parser.add_argument(
        '--queue-url',
        help='SQS queue URL for sqs-listener mode'
    )
    parser.add_argument(
        '--region',
        default='us-east-1',
        help='AWS region'
    )
    parser.add_argument(
        '--event-file',
        help='JSON file containing CloudTrail event for process-file mode'
    )
    
    args = parser.parse_args()
    
    listener = EventBridgeCloudTrailListener(queue_url=args.queue_url, region=args.region)
    
    if args.mode == 'sqs-listener':
        if not args.queue_url:
            print("Error: --queue-url required for sqs-listener mode")
            return 1
        listener.listen_sqs(args.queue_url)
    
    elif args.mode == 'process-file':
        if not args.event_file:
            print("Error: --event-file required for process-file mode")
            return 1
        
        event_data = json.loads(Path(args.event_file).read_text())
        result = listener._process_cloudtrail_event(event_data)
        print(json.dumps(result, indent=2, default=str))
    
    else:
        # Lambda mode - just print ready message (Lambda runtime will call lambda_handler)
        print("EventBridge CloudTrail Listener ready for Lambda deployment")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
