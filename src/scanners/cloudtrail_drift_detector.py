"""
CloudTrail Drift Detector - Compare CloudTrail events against Terraform state
Detects configuration drift between actual AWS resources and Infrastructure as Code.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import hcl2
import boto3

from ..models import NormalizedFinding, SeverityLevel, StatusEnum

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CloudTrailDriftDetector:
    """
    Detects configuration drift by comparing:
    1. CloudTrail events (actual changes made)
    2. Terraform state (intended configuration)
    3. Live AWS resources (current state)
    """
    
    def __init__(self, terraform_dir: str = "./iac/terraform", region: str = "us-east-1"):
        self.terraform_dir = Path(terraform_dir)
        self.region = region
        self.ec2_client = boto3.client('ec2', region_name=region)
        self.s3_client = boto3.client('s3', region_name=region)
        self.iam_client = boto3.client('iam', region_name=region)
        
    def detect_drift_from_events(self, cloudtrail_events: List[Dict[str, Any]]) -> List[NormalizedFinding]:
        """
        Analyze CloudTrail events and detect drift from Terraform state.
        
        Args:
            cloudtrail_events: List of CloudTrail events
            
        Returns:
            List of NormalizedFinding objects representing detected drift
        """
        findings: List[NormalizedFinding] = []
        
        logger.info(f"Starting drift detection for {len(cloudtrail_events)} CloudTrail events")
        
        try:
            # Load Terraform state
            tf_state = self._load_terraform_state()
            tf_config = self._load_terraform_config()
            
            logger.info(f"Loaded Terraform state with {len(tf_state.get('resources', []))} resources")
            
            # Process each CloudTrail event
            for event in cloudtrail_events:
                if 'eventName' in event:
                    event_name = event.get('eventName', '')
                    details = event 
                else:
                    event_name = event.get('EventName', '')
                    ct_event_raw = event.get('CloudTrailEvent', '{}')
                    details = json.loads(ct_event_raw) if isinstance(ct_event_raw, str) else ct_event_raw
                
                logger.debug(f"Processing CloudTrail event: {event_name}")
                
                drift_findings = self._detect_specific_drift(
                    event_name=event_name,
                    event_details=details,
                    tf_state=tf_state,
                    tf_config=tf_config
                )
                
                if drift_findings:
                    logger.info(f"Found {len(drift_findings)} drift issues for event {event_name}")
                    findings.extend(drift_findings)
                else:
                    logger.debug(f"No drift detected for event: {event_name}")
            
            logger.info(f"Drift detection complete: {len(findings)} total findings")
            
        except Exception as e:
            logger.error(f"Failed to detect drift: {e}", exc_info=True)
        
        return findings
    
    def _load_terraform_state(self) -> Dict[str, Any]:
        """Load Terraform state from S3 (configured in backend.tf) or local file"""
        try:
            # Try local file first (for development)
            local_state = self.terraform_dir / "terraform.tfstate"
            if local_state.exists():
                logger.info(f"Loading Terraform state from local file: {local_state}")
                return json.loads(local_state.read_text())
            
            logger.debug(f"Local terraform state not found at {local_state}")
            
            # Load S3 backend config from terraform backend.tf
            state_bucket = os.getenv('TERRAFORM_STATE_BUCKET') or 'test-bk-tdinh'
            state_key = os.getenv('TERRAFORM_STATE_KEY') or 'terraform.tfstate'
            state_region = os.getenv('TERRAFORM_STATE_REGION', 'us-east-1')
            
            logger.info(f"Loading Terraform state from S3: s3://{state_bucket}/{state_key} (region: {state_region})")
            
            s3 = boto3.client('s3', region_name=state_region)
            response = s3.get_object(Bucket=state_bucket, Key=state_key)
            state_data = json.loads(response['Body'].read().decode('utf-8'))
            logger.info(f"Successfully loaded terraform state from S3 with {len(state_data.get('resources', []))} resources")
            return state_data
            
        except Exception as e:
            logger.warning(f"Failed to load Terraform state: {e}")
            logger.warning("Drift detection requires Terraform state. Set TERRAFORM_STATE_BUCKET or ensure terraform.tfstate exists locally")
            return {}
    
    def _load_terraform_config(self) -> Dict[str, Any]:
        """Parse Terraform configuration files"""
        config = {}
        
        if not self.terraform_dir.exists():
            logger.warning(f"Terraform directory not found: {self.terraform_dir}")
            return config
        
        try:
            for tf_file in self.terraform_dir.glob("*.tf"):
                with open(tf_file) as f:
                    parsed = hcl2.load(f)
                    config.update(parsed)
        except Exception as e:
            logger.error(f"Failed to parse Terraform config: {e}")
        
        return config
    
    def _detect_specific_drift(
        self,
        event_name: str,
        event_details: Dict[str, Any],
        tf_state: Dict[str, Any],
        tf_config: Dict[str, Any]
    ) -> List[NormalizedFinding]:
        """Route to specific drift detection based on event type"""
        findings: List[NormalizedFinding] = []
        
        if 'SecurityGroup' in event_name:
            findings.extend(self._detect_sg_drift(event_name, event_details, tf_state))
        elif 'Bucket' in event_name:
            findings.extend(self._detect_s3_drift(event_name, event_details, tf_state))
        elif 'Role' in event_name or 'Policy' in event_name:
            findings.extend(self._detect_iam_drift(event_name, event_details, tf_state))
        elif 'Database' in event_name or 'DBInstance' in event_name:
            findings.extend(self._detect_rds_drift(event_name, event_details, tf_state))
        
        return findings
    
    def _detect_sg_drift(
        self,
        event_name: str,
        event_details: Dict[str, Any],
        tf_state: Dict[str, Any]
    ) -> List[NormalizedFinding]:
        """Detect drift in Security Group configuration"""
        findings: List[NormalizedFinding] = []
        
        sg_id = event_details.get('requestParameters', {}).get('groupId')
        logger.debug(f"Detecting SG drift for event: {event_name}, extracted sg_id: {sg_id}")
        
        if not sg_id:
            logger.debug(f"No security group ID found in event details for {event_name}")
            return findings
        
        try:
            # Get live security group
            live_sg = self._get_live_sg(sg_id)
            logger.debug(f"Got live SG {sg_id}: {len(live_sg.get('IpPermissions', []))} ingress rules")
            
            # Get intended security group from Terraform state
            intended_sg = self._get_intended_sg_from_state(sg_id, tf_state)
            
            if not intended_sg:
                logger.debug(f"No terraform config found for SG {sg_id} in state (terraform state may be empty or SG not managed by TF)")
                # If no terraform state, we can't detect drift against intended config
                return findings
            
            logger.debug(f"Got intended SG config from terraform state: {intended_sg.get('ingress', [])} rules")
            
            # Compare ingress rules
            live_ingress = {self._rule_to_key(r): r for r in live_sg.get('IpPermissions', [])}
            intended_ingress = {self._rule_to_key(r): r for r in intended_sg.get('ingress', [])}
            
            logger.debug(f"Live ingress rules: {list(live_ingress.keys())}")
            logger.debug(f"Intended ingress rules: {list(intended_ingress.keys())}")
            
            # Find rules that exist in live but not in intended (drift)
            for rule_key, rule in live_ingress.items():
                if rule_key not in intended_ingress:
                    logger.info(f"Drift detected: SG {sg_id} has unexpected rule: {rule_key}")
                    findings.append(
                        self._create_drift_finding(
                            code="AWS_SG_UNINTENDED_RULE",
                            title="Unintended Security Group Rule Detected",
                            description=f"Security group {sg_id} has rule that doesn't match Terraform config: {rule}",
                            resource_id=sg_id,
                            resource_type="security_group",
                            severity=SeverityLevel.HIGH,
                            metadata={
                                "sg_id": sg_id,
                                "rule": rule,
                                "event": event_name,
                                "drift_type": "unexpected_rule"
                            }
                        )
                    )
        
        except Exception as e:
            logger.warning(f"Failed to detect SG drift for {sg_id}: {e}", exc_info=True)
        
        return findings
    
    def _detect_s3_drift(
        self,
        event_name: str,
        event_details: Dict[str, Any],
        tf_state: Dict[str, Any]
    ) -> List[NormalizedFinding]:
        """Detect drift in S3 bucket configuration"""
        findings: List[NormalizedFinding] = []
        
        bucket_name = event_details.get('requestParameters', {}).get('bucketName')
        if not bucket_name:
            return findings
        
        try:
            # Get live bucket policy
            try:
                policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                live_policy = json.loads(policy['Policy'])
            except:
                live_policy = {}
            
            # Get intended bucket policy from Terraform state
            intended_policy = self._get_intended_policy_from_state(bucket_name, tf_state)
            
            if live_policy != intended_policy:
                findings.append(
                    self._create_drift_finding(
                        code="AWS_S3_POLICY_DRIFT",
                        title="S3 Bucket Policy Drift Detected",
                        description=f"Bucket {bucket_name} policy differs from Terraform configuration",
                        resource_id=bucket_name,
                        resource_type="s3",
                        severity=SeverityLevel.HIGH,
                        metadata={
                            "bucket": bucket_name,
                            "live_policy": live_policy,
                            "intended_policy": intended_policy,
                            "event": event_name,
                            "drift_type": "policy_change"
                        }
                    )
                )
        
        except Exception as e:
            logger.warning(f"Failed to detect S3 drift for {bucket_name}: {e}")
        
        return findings
    
    def _detect_iam_drift(
        self,
        event_name: str,
        event_details: Dict[str, Any],
        tf_state: Dict[str, Any]
    ) -> List[NormalizedFinding]:
        """Detect drift in IAM configuration"""
        findings: List[NormalizedFinding] = []
        
        role_name = event_details.get('requestParameters', {}).get('roleName')
        if not role_name:
            return findings
        
        try:
            # Get live role policies
            live_policies = self.iam_client.list_role_policies(RoleName=role_name)
            
            # Get intended policies from Terraform state
            intended_policies = self._get_intended_role_policies(role_name, tf_state)
            
            live_policy_names = set(live_policies.get('PolicyNames', []))
            intended_policy_names = set(intended_policies.keys())
            
            # Check for extra policies
            extra_policies = live_policy_names - intended_policy_names
            if extra_policies:
                findings.append(
                    self._create_drift_finding(
                        code="AWS_IAM_POLICY_DRIFT",
                        title="IAM Role Policy Drift Detected",
                        description=f"Role {role_name} has policies not defined in Terraform: {extra_policies}",
                        resource_id=role_name,
                        resource_type="iam_role",
                        severity=SeverityLevel.HIGH,
                        metadata={
                            "role": role_name,
                            "extra_policies": list(extra_policies),
                            "event": event_name,
                            "drift_type": "unexpected_policy"
                        }
                    )
                )
        
        except Exception as e:
            logger.warning(f"Failed to detect IAM drift for {role_name}: {e}")
        
        return findings
    
    def _detect_rds_drift(
        self,
        event_name: str,
        event_details: Dict[str, Any],
        tf_state: Dict[str, Any]
    ) -> List[NormalizedFinding]:
        """Detect drift in RDS database configuration"""
        findings: List[NormalizedFinding] = []
        # Implementation for RDS drift detection
        return findings
    
    def run_terraform_plan(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Run 'terraform plan' to detect drift.
        Returns: (drift_detected, plan_summary)
        """
        try:
            result = subprocess.run(
                ["terraform", "plan", "-json"],
                cwd=str(self.terraform_dir),
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                logger.error(f"Terraform plan failed: {result.stderr}")
                return False, {}
            
            # Parse plan output
            plan_lines = result.stdout.strip().split('\n')
            plan_changes = [json.loads(line) for line in plan_lines if line.strip()]
            
            # Check if there are any resource changes
            resource_changes = [p for p in plan_changes if p.get('type') == 'resource_drift']
            
            return len(resource_changes) > 0, {
                'changes': resource_changes,
                'total': len(plan_changes)
            }
        
        except Exception as e:
            logger.error(f"Failed to run terraform plan: {e}")
            return False, {}
    
    # Helper methods
    
    def _get_live_sg(self, sg_id: str) -> Dict[str, Any]:
        """Fetch live security group configuration"""
        response = self.ec2_client.describe_security_groups(GroupIds=[sg_id])
        return response['SecurityGroups'][0] if response['SecurityGroups'] else {}
    
    def _get_intended_sg_from_state(self, sg_id: str, tf_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract intended SG config from Terraform state"""
        for resource in tf_state.get('resources', []):
            if resource.get('type') == 'aws_security_group':
                for instance in resource.get('instances', []):
                    if instance.get('attributes', {}).get('id') == sg_id:
                        return instance.get('attributes', {})
        return None
    
    def _get_intended_policy_from_state(self, bucket_name: str, tf_state: Dict[str, Any]) -> Dict[str, Any]:
        """Extract intended S3 policy from Terraform state"""
        for resource in tf_state.get('resources', []):
            if resource.get('type') == 'aws_s3_bucket_policy':
                for instance in resource.get('instances', []):
                    attrs = instance.get('attributes', {})
                    if attrs.get('bucket') == bucket_name:
                        try:
                            return json.loads(attrs.get('policy', '{}'))
                        except:
                            return {}
        return {}
    
    def _get_intended_role_policies(self, role_name: str, tf_state: Dict[str, Any]) -> Dict[str, Any]:
        """Extract intended IAM role policies from Terraform state"""
        policies = {}
        for resource in tf_state.get('resources', []):
            if resource.get('type') == 'aws_iam_role_policy':
                for instance in resource.get('instances', []):
                    attrs = instance.get('attributes', {})
                    if attrs.get('role') == role_name:
                        policies[attrs.get('name')] = attrs.get('policy')
        return policies
    
    @staticmethod
    def _rule_to_key(rule: Dict[str, Any]) -> str:
        """Convert a security group rule to a comparable key"""
        from_port = rule.get('FromPort', rule.get('from_port', -1))
        to_port = rule.get('ToPort', rule.get('to_port', -1))
        protocol = rule.get('IpProtocol', rule.get('protocol', ''))
        
        cidrs = []
        if 'IpRanges' in rule:  
            cidrs += [r['CidrIp'] for r in rule.get('IpRanges', [])]
        elif 'cidr_blocks' in rule:
            cidrs += rule.get('cidr_blocks', [])
            
        if 'Ipv6Ranges' in rule:
            cidrs += [r['CidrIpv6'] for r in rule.get('Ipv6Ranges', [])]
        elif 'ipv6_cidr_blocks' in rule:
            cidrs += rule.get('ipv6_cidr_blocks', [])
        
        return f"{protocol}:{from_port}:{to_port}:{','.join(sorted(cidrs))}"
    
    @staticmethod
    def _create_drift_finding(
        code: str,
        title: str,
        description: str,
        resource_id: str,
        resource_type: str,
        severity: SeverityLevel,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> NormalizedFinding:
        """Create a drift finding"""
        return NormalizedFinding(
            finding_id=f"drift-{code}-{resource_id}",
            finding_code=code,
            scanner="cloudtrail_drift",
            provider="aws",
            severity=severity,
            title=title,
            description=description,
            resource_type=resource_type,
            resource_id=resource_id,
            status=StatusEnum.OPEN,
            remediation_available=True,
            metadata=metadata or {},
            tags={"source": "cloudtrail_drift_detector"}
        )


def main():
    """Standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description="CloudTrail drift detector")
    parser.add_argument('--terraform-dir', default='iac/terraform', help='Terraform directory')
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--cloudtrail-events', help='JSON file with CloudTrail events')
    parser.add_argument('--output', '-o', help='Output file for findings')
    parser.add_argument('--pretty', action='store_true', help='Pretty-print output')
    
    args = parser.parse_args()
    
    detector = CloudTrailDriftDetector(
        terraform_dir=args.terraform_dir,
        region=args.region
    )
    
    # Load CloudTrail events if provided
    events = []
    if args.cloudtrail_events:
        with open(args.cloudtrail_events) as f:
            data = json.load(f)
            events = data if isinstance(data, list) else data.get('Events', [])
    
    findings = detector.detect_drift_from_events(events)
    
    output = {
        'total_findings': len(findings),
        'findings': [f.dict() for f in findings]
    }
    
    json_str = json.dumps(output, indent=2 if args.pretty else None, default=str)
    
    if args.output:
        Path(args.output).write_text(json_str)
        print(f"Drift findings written to {args.output}")
    else:
        print(json_str)


if __name__ == '__main__':
    main()
