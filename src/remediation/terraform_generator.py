"""
Terraform Code Generator for Cloud Remediation
Converts remediation actions into executable Terraform code
"""
import logging
import json
from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class TerraformGenerator:
    """Generate Terraform code for remediation actions"""
    
    def __init__(self, terraform_dir: str = "./iac/terraform"):
        self.terraform_dir = Path(terraform_dir)
        self.terraform_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_remediation(self, action: 'RemediationAction') -> str:
        """Generate Terraform code for a remediation action"""
        
        service = action.action_details.get('service', 'unknown')
        
        if service == 's3':
            return self._generate_s3_remediation(action)
        elif service == 'security_group':
            return self._generate_sg_remediation(action)
        elif service == 'iam':
            return self._generate_iam_remediation(action)
        elif service in ['ebs', 'rds', 'encryption']:
            return self._generate_encryption_remediation(action)
        elif service in ['ecr', 'ecs', 'container']:
            return self._generate_container_remediation(action)
        else:
            return self._generate_generic_remediation(action)
    
    def _generate_s3_remediation(self, action) -> str:
        """Generate Terraform code for S3 bucket remediation"""
        
        bucket_name = action.resource_id
        actions = action.action_details.get('actions', [])
        
        tf_code = f"""# Auto-generated S3 remediation for finding {action.finding_id}
# Generated at: {datetime.utcnow().isoformat()}

resource "aws_s3_bucket_public_access_block" "remediate_{self._sanitize_name(bucket_name)}" {{
  bucket = "{bucket_name}"

"""
        
        for action_item in actions:
            if action_item['type'] == 'block_public_access':
                config = action_item.get('config', {})
                tf_code += f"""  block_public_acls       = {str(config.get('BlockPublicAcls', True)).lower()}
  block_public_policy     = {str(config.get('BlockPublicPolicy', True)).lower()}
  ignore_public_acls      = {str(config.get('IgnorePublicAcls', True)).lower()}
  restrict_public_buckets = {str(config.get('RestrictPublicBuckets', True)).lower()}
"""
        
        tf_code += "}\n\n"
        
        # Add encryption
        for action_item in actions:
            if action_item['type'] == 'enable_encryption':
                config = action_item.get('config', {})
                algo = config.get('SSEAlgorithm', 'AES256')
                tf_code += f"""resource "aws_s3_bucket_server_side_encryption_configuration" "remediate_{self._sanitize_name(bucket_name)}" {{
  bucket = "{bucket_name}"

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "{algo}"
    }}
  }}
}}

"""
        
        # Add versioning
        for action_item in actions:
            if action_item['type'] == 'enable_versioning':
                tf_code += f"""resource "aws_s3_bucket_versioning" "remediate_{self._sanitize_name(bucket_name)}" {{
  bucket = "{bucket_name}"

  versioning_configuration {{
    status = "Enabled"
  }}
}}

"""
        
        # Add logging
        for action_item in actions:
            if action_item['type'] == 'enable_logging':
                tf_code += f"""resource "aws_s3_bucket_logging" "remediate_{self._sanitize_name(bucket_name)}" {{
  bucket = "{bucket_name}"

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "access-logs/"
}}

# Note: You need to create log_bucket separately
"""
        
        return tf_code
    
    def _generate_sg_remediation(self, action) -> str:
        """Generate Terraform code for Security Group remediation"""
        
        sg_id = action.resource_id
        actions = action.action_details.get('actions', [])
        
        tf_code = f"""# Auto-generated Security Group remediation for finding {action.finding_id}
# Generated at: {datetime.utcnow().isoformat()}

data "aws_security_group" "remediate_{self._sanitize_name(sg_id)}" {{
  id = "{sg_id}"
}}

"""
        
        # Generate ingress rule modifications
        for action_item in actions:
            if action_item['type'] == 'restrict_ingress':
                config = action_item.get('config', {})
                
                # Remove wide-open rules
                tf_code += f"""# Revoke all 0.0.0.0/0 ingress rules
resource "aws_security_group_rule" "revoke_all_ingress_{self._sanitize_name(sg_id)}" {{
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "{sg_id}"
  
  # This is a revocation rule - it will be removed by terraform
}}

# Add restricted ingress rule
resource "aws_security_group_rule" "allow_https_{self._sanitize_name(sg_id)}" {{
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["YOUR_OFFICE_IP/32"]  # Update with actual IP
  security_group_id = "{sg_id}"
}}

"""
        
        return tf_code
    
    def _generate_iam_remediation(self, action) -> str:
        """Generate Terraform code for IAM remediation"""
        
        role_name = action.resource_id
        actions = action.action_details.get('actions', [])
        
        tf_code = f"""# Auto-generated IAM remediation for finding {action.finding_id}
# Generated at: {datetime.utcnow().isoformat()}

data "aws_iam_role" "remediate_{self._sanitize_name(role_name)}" {{
  name = "{role_name}"
}}

"""
        
        for action_item in actions:
            if action_item['type'] == 'restrict_permissions':
                tf_code += f"""# Remove wildcard permissions from role
# Note: This is a manual remediation guide - replace wildcard policies with specific permissions

# Example of a restricted policy:
resource "aws_iam_role_policy" "restricted_{self._sanitize_name(role_name)}" {{
  name   = "restricted-policy"
  role   = data.aws_iam_role.remediate_{self._sanitize_name(role_name)}.id
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "arn:aws:s3:::specific-bucket/*"
      }}
    ]
  }})
}}

# TODO: Remove existing wildcard policies
"""
        
        return tf_code
    
    def _generate_encryption_remediation(self, action) -> str:
        """Generate Terraform code for encryption remediation"""
        
        resource_type = action.resource_type
        resource_id = action.resource_id
        
        tf_code = f"""# Auto-generated {resource_type.upper()} encryption remediation
# Generated at: {datetime.utcnow().isoformat()}
# Finding ID: {action.finding_id}

"""
        
        if resource_type.lower() == 'ebs':
            tf_code += self._generate_ebs_encryption(resource_id)
        elif resource_type.lower() == 'rds':
            tf_code += self._generate_rds_encryption(resource_id)
        else:
            tf_code += self._generate_generic_encryption(resource_id)
        
        return tf_code
    
    def _generate_ebs_encryption(self, volume_id: str) -> str:
        """Generate EBS encryption remediation"""
        
        return f"""# To enable EBS encryption on existing volumes, you need to:
# 1. Create a snapshot of the volume
# 2. Create an encrypted copy of the snapshot
# 3. Create a new volume from the encrypted snapshot
# 4. Attach the new volume to the instance
# 5. Detach the old volume

resource "aws_ebs_volume" "encrypted_{self._sanitize_name(volume_id)}" {{
  # This should be copied from the original volume
  # encrypted  = true
  # size       = <original_size>
  # availability_zone = <original_az>
  
  tags = {{
    Name = "encrypted-{volume_id}"
  }}
}}

# Note: Manual steps required to migrate data
"""
    
    def _generate_rds_encryption(self, db_instance_id: str) -> str:
        """Generate RDS encryption remediation"""
        
        return f"""# RDS encryption cannot be enabled on existing instances
# You must create a new encrypted instance and migrate data

resource "aws_db_instance" "encrypted_{self._sanitize_name(db_instance_id)}" {{
  # Copy settings from: {db_instance_id}
  # storage_encrypted = true
  # kms_key_id        = aws_kms_key.rds.arn
  
  # Additional settings...
  tags = {{
    Name = "encrypted-{db_instance_id}"
  }}
}}

# Manual migration steps required:
# 1. Create snapshot of original DB
# 2. Restore from snapshot to new encrypted DB
# 3. Update application connection strings
# 4. Delete original DB
"""
    
    def _generate_generic_encryption(self, resource_id: str) -> str:
        """Generate generic encryption remediation"""
        
        return f"""# Generic encryption remediation for {resource_id}
# Review your specific resource type and implement appropriate encryption

resource "aws_kms_key" "remediation" {{
  description = "KMS key for remediation of {resource_id}"
  
  tags = {{
    ResourceId = "{resource_id}"
  }}
}}

resource "aws_kms_alias" "remediation" {{
  name          = "alias/remediation-{self._sanitize_name(resource_id)}"
  target_key_id = aws_kms_key.remediation.key_id
}}

# TODO: Apply encryption to specific resource
"""
    
    def _generate_container_remediation(self, action) -> str:
        """Generate Terraform code for container remediation"""
        
        resource_id = action.resource_id
        actions = action.action_details.get('actions', [])
        
        tf_code = f"""# Auto-generated Container remediation for finding {action.finding_id}
# Generated at: {datetime.utcnow().isoformat()}

"""
        
        for action_item in actions:
            if action_item['type'] == 'remove_secrets_from_images':
                tf_code += f"""# Remediate secrets in container images
# Use AWS Secrets Manager instead of environment variables

resource "aws_secretsmanager_secret" "container_secret" {{
  name = "container-secret-{self._sanitize_name(resource_id)}"
}}

# Update your container task definition to use Secrets Manager
# In ECS task definition:
# "secrets": [
#   {{
#     "name": "DATABASE_PASSWORD",
#     "valueFrom": "arn:aws:secretsmanager:region:account:secret:container-secret"
#   }}
# ]

"""
            elif action_item['type'] == 'enable_image_scanning':
                tf_code += f"""# Enable ECR image scanning

resource "aws_ecr_repository_image_scan_config" "scan_{self._sanitize_name(resource_id)}" {{
  repository_name = "{resource_id}"

  image_scan_on_push = true
}}

"""
        
        return tf_code
    
    def _generate_generic_remediation(self, action) -> str:
        """Generate generic remediation placeholder"""
        
        return f"""# Manual Remediation Required
# Finding ID: {action.finding_id}
# Generated at: {datetime.utcnow().isoformat()}

# Finding Code: {action.action_details.get('finding_code', 'UNKNOWN')}
# Resource: {action.resource_type}/{action.resource_id}
# Description: {action.action_details.get('description', 'No description')}

# This finding requires manual remediation. Please review the finding details
# and implement appropriate remediations using Terraform or other IaC tools.

# TODO: Implement remediation for this finding
"""
    
    @staticmethod
    def _sanitize_name(name: str) -> str:
        """Sanitize name for use in Terraform resource names"""
        # Remove special characters and convert to lowercase
        sanitized = "".join(c if c.isalnum() else "_" for c in name.lower())
        # Remove leading/trailing underscores
        sanitized = sanitized.strip("_")
        # Replace multiple underscores with single
        while "__" in sanitized:
            sanitized = sanitized.replace("__", "_")
        return sanitized
    
    def save_remediation_tf(self, action, terraform_code: str) -> Path:
        """Save generated Terraform code to file"""
        
        # Create filename based on finding
        filename = f"remediation_{action.finding_id[:8]}.tf"
        file_path = self.terraform_dir / filename
        
        try:
            with open(file_path, 'w') as f:
                f.write(terraform_code)
            logger.info(f"Saved Terraform remediation to {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Failed to save Terraform file: {str(e)}")
            return None
