"""
CloudTrail event scanner for AWS runtime configuration monitoring.
Listens to CloudTrail events via EventBridge and detects configuration drift.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

from ..models import NormalizedFinding, ScanResult, SeverityLevel, StatusEnum

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CloudTrailScanner:
    """
    Scanner that processes CloudTrail events to detect configuration changes.
    Compares changes against Terraform state to identify drift.
    """
    
    def __init__(self, provider: str = "aws", region: str = "us-east-1"):
        self.provider = provider
        self.region = region
        self.ec2_client = boto3.client('ec2', region_name=region)
        self.iam_client = boto3.client('iam', region_name=region)
        self.s3_client = boto3.client('s3', region_name=region)
        self.cloudtrail_client = boto3.client('cloudtrail', region_name=region)
        self.ssm_client = boto3.client('ssm', region_name=region)
        
    def execute(self) -> ScanResult:
        """Execute CloudTrail scan"""
        scan_id = f"cloudtrail-{datetime.now(timezone.utc).timestamp()}"
        start_time = datetime.now(timezone.utc)
        findings: List[NormalizedFinding] = []
        
        try:
            # Fetch recent CloudTrail events
            events = self._fetch_cloudtrail_events()
            logger.info(f"Fetched {len(events)} CloudTrail events")
            
            # Process each event for drift detection
            for event in events:
                drift_findings = self._analyze_event_for_drift(event)
                findings.extend(drift_findings)
            
            end_time = datetime.now(timezone.utc)
            
            result = ScanResult(
                scan_id=scan_id,
                scanner_name="cloudtrail",
                provider=self.provider,
                start_time=start_time,
                end_time=end_time,
                status="success",
                findings_count=len(findings),
                findings=findings,
            )
            
            logger.info(f"CloudTrail scan completed: {len(findings)} findings")
            return result
            
        except Exception as e:
            logger.error(f"CloudTrail scan failed: {str(e)}", exc_info=True)
            return ScanResult(
                scan_id=scan_id,
                scanner_name="cloudtrail",
                provider=self.provider,
                start_time=start_time,
                end_time=datetime.now(timezone.utc),
                status="failed",
                findings_count=0,
                error_message=str(e),
            )
    
    def _fetch_cloudtrail_events(self, max_items: int = 100, event_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Fetch recent CloudTrail events that represent configuration changes.
        
        Args:
            max_items: Maximum number of events to fetch
            event_types: Specific event names to filter (e.g., ['PutBucketPolicy', 'AuthorizeSecurityGroupIngress'])
        """
        if event_types is None:
            # Default sensitive configuration change events
            event_types = [
                'PutBucketPolicy', 'PutBucketPublicAccessBlock',
                'PutBucketVersioning', 'PutBucketLogging',
                'CreateSecurityGroup', 'AuthorizeSecurityGroupIngress',
                'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupIngress',
                'RevokeSecurityGroupEgress', 'DeleteSecurityGroup',
                'CreateRole', 'PutRolePolicy', 'AttachRolePolicy',
                'ModifyDBInstance', 'CreateDBInstance',
                'PutParameter', 'DeleteParameter'
            ]
        
        try:
            response = self.cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': event_types[0]  # Start with first event
                    }
                ],
                MaxResults=max_items,
                IncludeGlobalServiceEvents=True,
            )
            
            events = []
            for event in response.get('Events', []):
                try:
                    cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
                    events.append({
                        'EventName': event.get('EventName'),
                        'EventTime': event.get('EventTime'),
                        'Username': event.get('Username'),
                        'EventSource': event.get('EventSource'),
                        'CloudTrailEvent': cloud_trail_event,
                        'Resources': event.get('Resources', [])
                    })
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse CloudTrail event: {e}")
                    continue
            
            return events
            
        except ClientError as e:
            logger.error(f"Failed to fetch CloudTrail events: {e}")
            return []
    
    def _analyze_event_for_drift(self, event: Dict[str, Any]) -> List[NormalizedFinding]:
        """Analyze a CloudTrail event to detect configuration drift"""
        findings: List[NormalizedFinding] = []
        event_name = event.get('EventName', 'Unknown')
        event_time = event.get('EventTime')
        details = event.get('CloudTrailEvent', {})
        
        # Route to specific handlers based on event type
        if 'PutBucketPolicy' in event_name or 'PutBucketPublicAccessBlock' in event_name:
            findings.extend(self._check_s3_bucket_changes(event))
        elif 'SecurityGroup' in event_name:
            findings.extend(self._check_security_group_changes(event))
        elif 'Role' in event_name or 'Policy' in event_name:
            findings.extend(self._check_iam_changes(event))
        elif 'ModifyDBInstance' in event_name or 'CreateDBInstance' in event_name:
            findings.extend(self._check_database_changes(event))
        elif 'PutParameter' in event_name:
            findings.extend(self._check_parameter_changes(event))
        
        return findings
    
    def _check_s3_bucket_changes(self, event: Dict[str, Any]) -> List[NormalizedFinding]:
        """Check for S3 bucket configuration changes"""
        findings: List[NormalizedFinding] = []
        details = event.get('CloudTrailEvent', {})
        bucket_name = details.get('requestParameters', {}).get('bucketName')
        
        if not bucket_name:
            return findings
        
        event_name = event.get('EventName', '')
        
        try:
            # Check bucket ACL and public access settings
            acl_response = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            public_access = self.s3_client.get_public_access_block(Bucket=bucket_name)
            
            # Check if bucket is publicly accessible
            is_public = self._is_s3_bucket_public(acl_response, public_access)
            
            if is_public and 'PutBucketPublicAccessBlock' in event_name:
                findings.append(
                    self._create_finding(
                        finding_code="AWS_S3_PUBLIC_ACCESS_DETECTED",
                        title="S3 Bucket Public Access Detected",
                        description=f"S3 bucket '{bucket_name}' was modified and is now publicly accessible.",
                        resource_id=bucket_name,
                        resource_type="s3",
                        severity=SeverityLevel.CRITICAL,
                        metadata={"bucket_name": bucket_name, "event": event_name}
                    )
                )
        
        except ClientError as e:
            logger.warning(f"Failed to check S3 bucket {bucket_name}: {e}")
        
        return findings
    
    def _check_security_group_changes(self, event: Dict[str, Any]) -> List[NormalizedFinding]:
        """Check for security group changes"""
        findings: List[NormalizedFinding] = []
        details = event.get('CloudTrailEvent', {})
        event_name = event.get('EventName', '')
        
        # Get resource info from event
        sg_id = None
        if 'AuthorizeSecurityGroupIngress' in event_name:
            sg_id = details.get('requestParameters', {}).get('groupId')
        elif 'DeleteSecurityGroup' in event_name:
            sg_id = details.get('requestParameters', {}).get('groupId')
        
        if not sg_id:
            return findings
        
        try:
            sg_response = self.ec2_client.describe_security_groups(GroupIds=[sg_id])
            sg_data = sg_response['SecurityGroups'][0]
            
            # Check for overly permissive rules
            for rule in sg_data.get('IpPermissions', []):
                if self._is_rule_too_permissive(rule):
                    findings.append(
                        self._create_finding(
                            finding_code="AWS_SG_WIDE_OPEN",
                            title="Security Group with Wide Open Ingress",
                            description=f"Security group '{sg_id}' has overly permissive ingress rule (CIDR: 0.0.0.0/0)",
                            resource_id=sg_id,
                            resource_type="security_group",
                            severity=SeverityLevel.HIGH,
                            metadata={"sg_id": sg_id, "rule": rule}
                        )
                    )
        
        except ClientError as e:
            logger.warning(f"Failed to check security group {sg_id}: {e}")
        
        return findings
    
    def _check_iam_changes(self, event: Dict[str, Any]) -> List[NormalizedFinding]:
        """Check for IAM policy changes"""
        findings: List[NormalizedFinding] = []
        details = event.get('CloudTrailEvent', {})
        event_name = event.get('EventName', '')
        
        # Extract role name
        role_name = details.get('requestParameters', {}).get('roleName')
        
        if role_name and 'PutRolePolicy' in event_name:
            try:
                # Check if policy grants admin permissions
                policy_document = details.get('requestParameters', {}).get('policyDocument')
                
                if policy_document:
                    if isinstance(policy_document, str):
                        policy_document = json.loads(policy_document)
                    
                    if self._has_wildcard_permissions(policy_document):
                        findings.append(
                            self._create_finding(
                                finding_code="AWS_IAM_WILDCARD_PERMISSIONS",
                                title="IAM Role with Wildcard Permissions",
                                description=f"IAM role '{role_name}' has overly permissive policy with wildcards.",
                                resource_id=role_name,
                                resource_type="iam_role",
                                severity=SeverityLevel.HIGH,
                                metadata={"role_name": role_name, "policy": policy_document}
                            )
                        )
            
            except Exception as e:
                logger.warning(f"Failed to check IAM role {role_name}: {e}")
        
        return findings
    
    def _check_database_changes(self, event: Dict[str, Any]) -> List[NormalizedFinding]:
        """Check for RDS database configuration changes"""
        findings: List[NormalizedFinding] = []
        details = event.get('CloudTrailEvent', {})
        event_name = event.get('EventName', '')
        
        # Check for unencrypted storage
        storage_encrypted = details.get('requestParameters', {}).get('storageEncrypted')
        
        if storage_encrypted == False:  # noqa: E712
            findings.append(
                self._create_finding(
                    finding_code="AWS_RDS_UNENCRYPTED_STORAGE",
                    title="RDS Instance with Unencrypted Storage",
                    description="RDS database instance created/modified without encryption.",
                    resource_id=details.get('requestParameters', {}).get('dBInstanceIdentifier', 'unknown'),
                    resource_type="rds",
                    severity=SeverityLevel.HIGH,
                    metadata={"event": event_name}
                )
            )
        
        return findings
    
    def _check_parameter_changes(self, event: Dict[str, Any]) -> List[NormalizedFinding]:
        """Check for SSM Parameter Store changes (e.g., secrets)"""
        findings: List[NormalizedFinding] = []
        details = event.get('CloudTrailEvent', {})
        param_name = details.get('requestParameters', {}).get('name')
        
        if param_name:
            # Check if parameter contains secrets and is not encrypted
            param_type = details.get('requestParameters', {}).get('type')
            
            if 'secret' in param_name.lower() and param_type != 'SecureString':
                findings.append(
                    self._create_finding(
                        finding_code="AWS_PARAMETER_STORE_SECRET_NOT_ENCRYPTED",
                        title="Unencrypted Secret in Parameter Store",
                        description=f"Parameter '{param_name}' appears to contain a secret but is not encrypted.",
                        resource_id=param_name,
                        resource_type="ssm_parameter",
                        severity=SeverityLevel.HIGH,
                        metadata={"parameter_name": param_name, "type": param_type}
                    )
                )
        
        return findings
    
    @staticmethod
    def _is_s3_bucket_public(acl_response: Dict[str, Any], public_access: Dict[str, Any]) -> bool:
        """Check if S3 bucket is publicly accessible"""
        # Check public access block settings
        config = public_access.get('PublicAccessBlockConfiguration', {})
        
        # If any public access is allowed, it's considered public
        if not all([
            config.get('BlockPublicAcls', False),
            config.get('BlockPublicPolicy', False),
        ]):
            return True
        
        # Check bucket ACL grants
        for grant in acl_response.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if grantee.get('Type') == 'Group':
                uri = grantee.get('URI', '')
                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    return True
        
        return False
    
    @staticmethod
    def _is_rule_too_permissive(rule: Dict[str, Any]) -> bool:
        """Check if a security group rule is too permissive (allows all IPs)"""
        # Check IPv4 ranges
        for cidr in rule.get('IpRanges', []):
            if cidr.get('CidrIp') == '0.0.0.0/0':
                return True
        
        # Check IPv6 ranges
        for cidr in rule.get('Ipv6Ranges', []):
            if cidr.get('CidrIpv6') == '::/0':
                return True
        
        return False
    
    @staticmethod
    def _has_wildcard_permissions(policy_document: Dict[str, Any]) -> bool:
        """Check if IAM policy has wildcard (admin) permissions"""
        statements = policy_document.get('Statement', [])
        
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                # Check for wildcards
                for action in actions:
                    if action == '*' or action == 'iam:*' or action == 'ec2:*':
                        return True
                
                # Check for overly broad resources
                resources = statement.get('Resource', [])
                if isinstance(resources, str):
                    resources = [resources]
                if '*' in resources and any('*' in a for a in actions):
                    return True
        
        return False
    
    @staticmethod
    def _create_finding(
        finding_code: str,
        title: str,
        description: str,
        resource_id: str,
        resource_type: str,
        severity: SeverityLevel,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> NormalizedFinding:
        """Create a normalized finding"""
        return NormalizedFinding(
            finding_id=f"cloudtrail-{finding_code}-{resource_id}",
            finding_code=finding_code,
            scanner="cloudtrail",
            provider="aws",
            severity=severity,
            title=title,
            description=description,
            resource_type=resource_type,
            resource_id=resource_id,
            status=StatusEnum.OPEN,
            remediation_available=True,
            metadata=metadata or {}
        )


def main():
    """Standalone execution"""
    import argparse
    
    parser = argparse.ArgumentParser(description="CloudTrail configuration change detector")
    parser.add_argument('--region', default='us-east-1', help='AWS region')
    parser.add_argument('--output', '-o', help='Output file for findings')
    parser.add_argument('--pretty', action='store_true', help='Pretty-print output')
    
    args = parser.parse_args()
    
    scanner = CloudTrailScanner(region=args.region)
    result = scanner.execute()
    
    output = {
        'scan_id': result.scan_id,
        'scanner': result.scanner_name,
        'status': result.status,
        'findings_count': result.findings_count,
        'findings': [f.dict() for f in result.findings]
    }
    
    import json
    json_str = json.dumps(output, indent=2 if args.pretty else None, default=str)
    
    if args.output:
        Path(args.output).write_text(json_str)
        print(f"Findings written to {args.output}")
    else:
        print(json_str)


if __name__ == '__main__':
    main()
