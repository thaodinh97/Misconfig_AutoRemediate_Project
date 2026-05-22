"""
Remediation Engine - Orchestrates remediation execution
Converts triage decisions into remediation actions
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from ..models import NormalizedFinding, TriageDecision, RemediationStatus
from .terraform_generator import TerraformGenerator
from .ansible_executor import AnsibleExecutor

logger = logging.getLogger(__name__)


class RemediationAction:
    """Represents a single remediation action"""
    
    def __init__(
        self,
        finding_id: str,
        resource_type: str,
        resource_id: str,
        action_type: str,  # 'terraform', 'ansible', 'manual'
        action_details: Dict[str, Any],
        finding: NormalizedFinding = None
    ):
        self.finding_id = finding_id
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.action_type = action_type
        self.action_details = action_details
        self.finding = finding
        self.status = RemediationStatus.PENDING
        self.created_at = datetime.utcnow()
        self.executed_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.error_message: Optional[str] = None
        self.result: Dict[str, Any] = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'finding_id': self.finding_id,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'action_type': self.action_type,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'executed_at': self.executed_at.isoformat() if self.executed_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'error_message': self.error_message,
            'result': self.result,
        }


class RemediationEngine:
    """
    Orchestrates remediation execution for security findings
    
    Workflow:
    1. TriageDecision (auto_remediate) → RemediationAction
    2. RemediationAction → Execute (Terraform/Ansible/Manual)
    3. Track execution status
    """
    
    def __init__(
        self,
        terraform_dir: str = "./iac/terraform",
        ansible_playbooks_dir: str = "./playbooks",
        dry_run: bool = False,
        approval_required: bool = False,
    ):
        self.terraform_dir = Path(terraform_dir)
        self.ansible_playbooks_dir = Path(ansible_playbooks_dir)
        self.dry_run = dry_run
        self.approval_required = approval_required
        
        self.terraform_gen = TerraformGenerator(terraform_dir)
        self.ansible_executor = AnsibleExecutor(ansible_playbooks_dir)
        
        self.actions: List[RemediationAction] = []
        self.execution_results: Dict[str, RemediationAction] = {}
    
    def plan_remediation(
        self,
        findings: List[NormalizedFinding],
        decisions: List[TriageDecision],
    ) -> List[RemediationAction]:
        """
        Convert findings + triage decisions into remediation actions
        """
        actions = []
        
        # Map decisions to findings
        decision_map = {d.finding_id: d for d in decisions}
        
        for finding in findings:
            decision = decision_map.get(finding.finding_id)
            if not decision:
                logger.warning(f"No triage decision for finding {finding.finding_id}")
                continue
            
            # Only remediate items marked for auto_remediate
            if decision.recommendation != "auto_remediate":
                logger.debug(
                    f"Skipping finding {finding.finding_id}: "
                    f"recommendation={decision.recommendation}"
                )
                continue
            
            # Convert finding to remediation action
            action = self._create_remediation_action(finding)
            if action:
                actions.append(action)
                logger.info(
                    f"Planned remediation for {finding.resource_type} "
                    f"({finding.resource_id}): {action.action_type}"
                )
        
        self.actions = actions
        return actions
    
    def _create_remediation_action(self, finding: NormalizedFinding) -> Optional[RemediationAction]:
        """Create a remediation action from a finding"""
        
        # Map resource types to remediation strategies
        remediation_map = {
            # S3 remediations
            's3': self._create_s3_remediation,
            'bucket': self._create_s3_remediation,
            
            # Security Group remediations
            'sg': self._create_sg_remediation,
            'security_group': self._create_sg_remediation,
            
            # IAM remediations
            'iam': self._create_iam_remediation,
            'role': self._create_iam_remediation,
            
            # Encryption remediations
            'encryption': self._create_encryption_remediation,
            'ebs': self._create_encryption_remediation,
            'rds': self._create_encryption_remediation,
            
            # Container remediations
            'ecr': self._create_container_remediation,
            'ecs': self._create_container_remediation,
            'container': self._create_container_remediation,
        }
        
        resource_type = finding.resource_type.lower()
        
        # Find matching remediation handler
        for key, handler in remediation_map.items():
            if key in resource_type:
                return handler(finding)
        
        # Fallback to generic remediation
        logger.warning(
            f"No specific remediation handler for resource type "
            f"{finding.resource_type}, using generic handler"
        )
        return self._create_generic_remediation(finding)
    
    def _create_s3_remediation(self, finding: NormalizedFinding) -> RemediationAction:
        """Create S3 bucket remediation action"""
        
        action_details = {
            'service': 's3',
            'resource_id': finding.resource_id,
            'actions': [],
        }
        
        # Determine specific remediation based on finding code
        if 'public' in finding.finding_code.lower() or 'acl' in finding.description.lower():
            action_details['actions'].append({
                'type': 'block_public_access',
                'config': {
                    'BlockPublicAcls': True,
                    'BlockPublicPolicy': True,
                    'IgnorePublicAcls': True,
                    'RestrictPublicBuckets': True,
                }
            })
        
        if 'encryption' in finding.finding_code.lower() or 'unencrypted' in finding.description.lower():
            action_details['actions'].append({
                'type': 'enable_encryption',
                'config': {
                    'SSEAlgorithm': 'AES256',
                }
            })
        
        if 'versioning' in finding.finding_code.lower():
            action_details['actions'].append({
                'type': 'enable_versioning',
            })
        
        if 'logging' in finding.finding_code.lower():
            action_details['actions'].append({
                'type': 'enable_logging',
            })
        
        return RemediationAction(
            finding_id=finding.finding_id,
            resource_type='s3',
            resource_id=finding.resource_id,
            action_type='terraform',
            action_details=action_details,
            finding=finding,
        )
    
    def _create_sg_remediation(self, finding: NormalizedFinding) -> RemediationAction:
        """Create Security Group remediation action"""
        
        action_details = {
            'service': 'security_group',
            'resource_id': finding.resource_id,
            'actions': [],
        }
        
        if '0.0.0.0/0' in finding.description or 'wide' in finding.description.lower():
            action_details['actions'].append({
                'type': 'restrict_ingress',
                'config': {
                    'remove_rules': 'open_ingress',
                    'add_rules': {
                        'from_port': 443,
                        'to_port': 443,
                        'protocol': 'tcp',
                        'cidr_blocks': ['YOUR_OFFICE_IP/32'],  # Placeholder
                    }
                }
            })
        
        return RemediationAction(
            finding_id=finding.finding_id,
            resource_type='sg',
            resource_id=finding.resource_id,
            action_type='terraform',
            action_details=action_details,
            finding=finding,
        )
    
    def _create_iam_remediation(self, finding: NormalizedFinding) -> RemediationAction:
        """Create IAM remediation action"""
        
        action_details = {
            'service': 'iam',
            'resource_id': finding.resource_id,
            'actions': [],
        }
        
        if 'wildcard' in finding.description.lower() or '*' in finding.description:
            action_details['actions'].append({
                'type': 'restrict_permissions',
                'config': {
                    'remove_wildcard_actions': True,
                    'apply_least_privilege': True,
                }
            })
        
        if 'root' in finding.description.lower():
            action_details['actions'].append({
                'type': 'restrict_root_access',
            })
        
        return RemediationAction(
            finding_id=finding.finding_id,
            resource_type='iam',
            resource_id=finding.resource_id,
            action_type='terraform',
            action_details=action_details,
            finding=finding,
        )
    
    def _create_encryption_remediation(self, finding: NormalizedFinding) -> RemediationAction:
        """Create encryption remediation action"""
        
        action_details = {
            'service': finding.resource_type,
            'resource_id': finding.resource_id,
            'actions': [
                {
                    'type': 'enable_encryption',
                    'config': {
                        'algorithm': 'AES256',
                        'key_rotation': True,
                    }
                }
            ],
        }
        
        return RemediationAction(
            finding_id=finding.finding_id,
            resource_type=finding.resource_type,
            resource_id=finding.resource_id,
            action_type='terraform',
            action_details=action_details,
            finding=finding,
        )
    
    def _create_container_remediation(self, finding: NormalizedFinding) -> RemediationAction:
        """Create container remediation action"""
        
        action_details = {
            'service': finding.resource_type,
            'resource_id': finding.resource_id,
            'actions': [],
        }
        
        if 'secrets' in finding.description.lower() or 'environment' in finding.description.lower():
            action_details['actions'].append({
                'type': 'remove_secrets_from_images',
                'config': {
                    'use_secrets_manager': True,
                }
            })
        
        if 'scan' in finding.description.lower():
            action_details['actions'].append({
                'type': 'enable_image_scanning',
            })
        
        return RemediationAction(
            finding_id=finding.finding_id,
            resource_type=finding.resource_type,
            resource_id=finding.resource_id,
            action_type='terraform',
            action_details=action_details,
            finding=finding,
        )
    
    def _create_generic_remediation(self, finding: NormalizedFinding) -> RemediationAction:
        """Create generic remediation action for unknown resource types"""
        
        action_details = {
            'finding_code': finding.finding_code,
            'resource_id': finding.resource_id,
            'description': finding.description,
            'manual_review_required': True,
        }
        
        return RemediationAction(
            finding_id=finding.finding_id,
            resource_type=finding.resource_type,
            resource_id=finding.resource_id,
            action_type='manual',
            action_details=action_details,
            finding=finding,
        )
    
    def execute_remediation(self, action: RemediationAction, dry_run: bool = None) -> bool:
        """Execute a single remediation action"""
        
        dry_run = dry_run if dry_run is not None else self.dry_run
        
        logger.info(f"Executing remediation action: {action.finding_id}")
        
        try:
            action.executed_at = datetime.utcnow()
            
            if action.action_type == 'terraform':
                success = self._execute_terraform(action, dry_run)
            elif action.action_type == 'ansible':
                success = self._execute_ansible(action, dry_run)
            elif action.action_type == 'manual':
                logger.info(f"Manual remediation required for {action.finding_id}")
                action.status = RemediationStatus.PENDING
                success = False
            else:
                logger.error(f"Unknown action type: {action.action_type}")
                action.status = RemediationStatus.FAILED
                success = False
            
            action.completed_at = datetime.utcnow()
            
            if success:
                action.status = RemediationStatus.SUCCESS
                logger.info(f"Remediation SUCCESS for {action.finding_id}")
            else:
                if not (action.action_type == 'manual'):
                    action.status = RemediationStatus.FAILED
            
            self.execution_results[action.finding_id] = action
            return success
            
        except Exception as e:
            logger.error(f"Remediation FAILED for {action.finding_id}: {str(e)}")
            action.status = RemediationStatus.FAILED
            action.error_message = str(e)
            action.completed_at = datetime.utcnow()
            self.execution_results[action.finding_id] = action
            return False
    
    def _execute_terraform(self, action: RemediationAction, dry_run: bool = False) -> bool:
        """Execute terraform-based remediation"""
        
        try:
            # Generate terraform code
            tf_code = self.terraform_gen.generate_remediation(action)
            
            if dry_run:
                logger.info(f"DRY RUN - Terraform code:\n{tf_code}")
                action.result = {
                    'dry_run': True,
                    'terraform_code': tf_code,
                }
                return True
            
            # Execute terraform
            # TODO: Implement actual terraform execution
            logger.info(f"Would execute terraform for {action.finding_id}")
            action.result = {
                'execution': 'pending',
                'terraform_code': tf_code,
            }
            return True
            
        except Exception as e:
            logger.error(f"Terraform execution failed: {str(e)}")
            action.error_message = str(e)
            return False
    
    def _execute_ansible(self, action: RemediationAction, dry_run: bool = False) -> bool:
        """Execute Ansible-based remediation"""
        
        try:
            # Generate playbook
            playbook = self.ansible_executor.generate_playbook(action)
            
            if dry_run:
                logger.info(f"DRY RUN - Ansible playbook:\n{playbook}")
                action.result = {
                    'dry_run': True,
                    'playbook': playbook,
                }
                return True
            
            # Execute playbook
            # TODO: Implement actual ansible execution
            logger.info(f"Would execute ansible playbook for {action.finding_id}")
            action.result = {
                'execution': 'pending',
                'playbook': playbook,
            }
            return True
            
        except Exception as e:
            logger.error(f"Ansible execution failed: {str(e)}")
            action.error_message = str(e)
            return False
    
    def execute_batch(self, dry_run: bool = None) -> Dict[str, RemediationAction]:
        """Execute all planned remediation actions"""
        
        logger.info(f"Starting batch remediation for {len(self.actions)} actions")
        
        for action in self.actions:
            if action.action_type == 'manual':
                logger.info(f"Skipping manual action: {action.finding_id}")
                continue
            
            self.execute_remediation(action, dry_run)
        
        return self.execution_results
    
    def get_summary(self) -> Dict[str, Any]:
        """Get remediation execution summary"""
        
        total = len(self.execution_results)
        success = sum(1 for a in self.execution_results.values() if a.status == RemediationStatus.SUCCESS)
        failed = sum(1 for a in self.execution_results.values() if a.status == RemediationStatus.FAILED)
        pending = sum(1 for a in self.execution_results.values() if a.status == RemediationStatus.PENDING)
        
        return {
            'total_actions': total,
            'success': success,
            'failed': failed,
            'pending': pending,
            'success_rate': (success / total * 100) if total > 0 else 0,
        }
