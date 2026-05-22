"""
Ansible Playbook Executor for Cloud Remediation
Generates and executes Ansible playbooks for remediation
"""
import logging
import yaml
import subprocess
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class AnsibleExecutor:
    """Generate and execute Ansible playbooks for remediation"""
    
    def __init__(self, playbooks_dir: str = "./playbooks"):
        self.playbooks_dir = Path(playbooks_dir)
        self.playbooks_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_playbook(self, action: 'RemediationAction') -> str:
        """Generate Ansible playbook for a remediation action"""
        
        service = action.action_details.get('service', 'unknown')
        
        if service == 's3':
            return self._generate_s3_playbook(action)
        elif service == 'security_group':
            return self._generate_sg_playbook(action)
        elif service == 'iam':
            return self._generate_iam_playbook(action)
        else:
            return self._generate_generic_playbook(action)
    
    def _generate_s3_playbook(self, action) -> str:
        """Generate S3 remediation playbook"""
        
        bucket_name = action.resource_id
        actions = action.action_details.get('actions', [])
        
        tasks = []
        
        # Block public access
        for action_item in actions:
            if action_item['type'] == 'block_public_access':
                config = action_item.get('config', {})
                tasks.append({
                    'name': f"Block public access on S3 bucket {bucket_name}",
                    'amazon.aws.s3_bucket_public_access_block':
                        {
                            'bucket': bucket_name,
                            'block_public_acls': config.get('BlockPublicAcls', True),
                            'block_public_policy': config.get('BlockPublicPolicy', True),
                            'ignore_public_acls': config.get('IgnorePublicAcls', True),
                            'restrict_public_buckets': config.get('RestrictPublicBuckets', True),
                        }
                })
        
        # Enable encryption
        for action_item in actions:
            if action_item['type'] == 'enable_encryption':
                config = action_item.get('config', {})
                tasks.append({
                    'name': f"Enable encryption on S3 bucket {bucket_name}",
                    'amazon.aws.s3_bucket_encryption':
                        {
                            'bucket': bucket_name,
                            'sse_algorithm': config.get('SSEAlgorithm', 'AES256'),
                        }
                })
        
        # Enable versioning
        for action_item in actions:
            if action_item['type'] == 'enable_versioning':
                tasks.append({
                    'name': f"Enable versioning on S3 bucket {bucket_name}",
                    'amazon.aws.s3_bucket_versioning':
                        {
                            'bucket': bucket_name,
                            'versioning_state': 'Enabled',
                        }
                })
        
        return self._build_playbook_yaml(
            name=f"S3 Bucket Remediation: {bucket_name}",
            finding_id=action.finding_id,
            tasks=tasks,
        )
    
    def _generate_sg_playbook(self, action) -> str:
        """Generate Security Group remediation playbook"""
        
        sg_id = action.resource_id
        actions = action.action_details.get('actions', [])
        
        tasks = []
        
        for action_item in actions:
            if action_item['type'] == 'restrict_ingress':
                # Revoke wide-open rules
                tasks.append({
                    'name': f"Revoke 0.0.0.0/0 ingress on {sg_id}",
                    'amazon.aws.ec2_security_group_rule':
                        {
                            'group_id': sg_id,
                            'rule_type': 'ingress',
                            'protocol': '-1',
                            'cidr_ip': '0.0.0.0/0',
                            'state': 'absent',
                        }
                })
                
                # Add restricted rule
                tasks.append({
                    'name': f"Add HTTPS ingress to {sg_id}",
                    'amazon.aws.ec2_security_group_rule':
                        {
                            'group_id': sg_id,
                            'rule_type': 'ingress',
                            'protocol': 'tcp',
                            'from_port': 443,
                            'to_port': 443,
                            'cidr_ip': '10.0.0.0/8',  # Update with actual CIDR
                            'state': 'present',
                        }
                })
        
        return self._build_playbook_yaml(
            name=f"Security Group Remediation: {sg_id}",
            finding_id=action.finding_id,
            tasks=tasks,
        )
    
    def _generate_iam_playbook(self, action) -> str:
        """Generate IAM remediation playbook"""
        
        role_name = action.resource_id
        actions = action.action_details.get('actions', [])
        
        tasks = []
        
        for action_item in actions:
            if action_item['type'] == 'restrict_permissions':
                tasks.append({
                    'name': f"Get inline policies for {role_name}",
                    'amazon.aws.iam_role_info':
                        {
                            'name': role_name,
                        },
                    'register': 'role_info'
                })
                
                tasks.append({
                    'name': f"List inline policies for {role_name}",
                    'amazon.aws.iam_role_inline_policy_info':
                        {
                            'role_name': role_name,
                        },
                    'register': 'inline_policies'
                })
                
                tasks.append({
                    'name': 'Debug inline policies',
                    'debug': {
                        'msg': 'Inline policies found',
                        'var': 'inline_policies'
                    }
                })
        
        return self._build_playbook_yaml(
            name=f"IAM Role Remediation: {role_name}",
            finding_id=action.finding_id,
            tasks=tasks,
        )
    
    def _generate_generic_playbook(self, action) -> str:
        """Generate generic remediation playbook"""
        
        tasks = [{
            'name': 'Display remediation requirements',
            'debug': {
                'msg': [
                    f"Finding ID: {action.finding_id}",
                    f"Resource Type: {action.resource_type}",
                    f"Resource ID: {action.resource_id}",
                    f"Action Type: {action.action_type}",
                    "Description: Manual remediation required",
                ]
            }
        }]
        
        return self._build_playbook_yaml(
            name=f"Manual Remediation: {action.resource_id}",
            finding_id=action.finding_id,
            tasks=tasks,
        )
    
    @staticmethod
    def _build_playbook_yaml(
        name: str,
        finding_id: str,
        tasks: List[Dict[str, Any]],
    ) -> str:
        """Build complete playbook YAML"""
        
        playbook = [
            {
                'name': name,
                'hosts': 'localhost',
                'gather_facts': False,
                'vars': {
                    'finding_id': finding_id,
                    'remediation_timestamp': datetime.utcnow().isoformat(),
                },
                'tasks': tasks,
            }
        ]
        
        return yaml.dump(playbook, default_flow_style=False, sort_keys=False)
    
    def save_playbook(self, action, playbook_content: str) -> Optional[Path]:
        """Save generated playbook to file"""
        
        # Create filename based on finding
        filename = f"remediation_{action.finding_id[:8]}.yml"
        file_path = self.playbooks_dir / filename
        
        try:
            with open(file_path, 'w') as f:
                f.write(playbook_content)
            logger.info(f"Saved Ansible playbook to {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Failed to save playbook file: {str(e)}")
            return None
    
    def execute_playbook(
        self,
        playbook_path: str,
        inventory: str = "localhost,",
        tags: Optional[List[str]] = None,
        dry_run: bool = False,
    ) -> bool:
        """Execute Ansible playbook"""
        
        try:
            cmd = [
                "ansible-playbook",
                str(playbook_path),
                "-i", inventory,
                "-v",
            ]
            
            if tags:
                cmd.extend(["--tags", ",".join(tags)])
            
            if dry_run:
                cmd.append("--check")
            
            logger.info(f"Running ansible-playbook: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                logger.info("Ansible playbook executed successfully")
                return True
            else:
                logger.error(f"Ansible playbook failed: {result.stderr}")
                return False
                
        except FileNotFoundError:
            logger.warning("Ansible not found. Skipping playbook execution.")
            return False
        except Exception as e:
            logger.error(f"Ansible execution error: {str(e)}")
            return False
