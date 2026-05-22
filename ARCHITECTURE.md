# Architecture và Implementation Guide

## 🏗️ Architecture Overview

### Component Diagram

```
┌────────────────────────────────────────────────────────────────┐
│                    REMEDIATION PIPELINE                        │
└────────────────────────────────────────────────────────────────┘

┌──────────────────┐
│  ScannerRunner   │──┬─→ CheckovScanner ────┐
│  (runner.py)     │  │                      │
│                  │  ├─→ ScoutSuiteScanner ├──→ Raw Findings
│                  │  │                      │
│                  │  └─→ CloudsploitScanner ┘
└──────────────────┘
        │
        │ normalize_findings()
        ↓
┌──────────────────┐
│ NormalizedFinding│ ← Standard format
│  (models.py)     │   • finding_id
│                  │   • severity
│                  │   • resource_type
└──────────────────┘
        │
        │ triage_batch()
        ↓
┌──────────────────────────┐
│   TriageEngine           │
│   (triage/__init__.py)    │
│                          │
│  Decision Logic:         │
│  • Severity check        │
│  • Remediation available?│
│  • High-risk resource?   │
│  • False positive?       │
│                          │
│  Output:                 │
│  • recommendation        │
│  • confidence_score      │
│  • reasoning             │
└──────────────────────────┘
        │
        │ TriageDecision
        ↓
┌──────────────────────────────┐
│ RemediationEngine            │
│ (remediation/engine.py)      │
│                              │
│ plan_remediation()           │
│ ↓                            │
│ _create_*_remediation()      │
│ (s3, sg, iam, encryption)    │
│ ↓                            │
│ RemediationAction            │
│ • finding_id                 │
│ • resource_type              │
│ • action_type (terraform)    │
│ • action_details             │
└──────────────────────────────┘
        │
        │ execute_remediation()
        ├─→ _execute_terraform()
        │   ↓
        │   TerraformGenerator
        │   (remediation/terraform_generator.py)
        │   ↓
        │   Generate .tf code
        │
        └─→ _execute_ansible()
            ↓
            AnsibleExecutor
            (remediation/ansible_executor.py)
            ↓
            Generate playbook.yml
            ↓
            ansible-playbook

        ↓
    RemediationStatus
    (PENDING/SUCCESS/FAILED)

        ↓
    Report Generation
    (scan_results, decisions, actions)
```

## 📦 Core Components

### 1. BaseScanner (src/scanners/__init__.py)

**Responsible For:**
- Abstract interface cho tất cả scanners
- Lifecycle management (execute → run → normalize)
- Common utility methods

**Key Methods:**
```python
class BaseScanner(ABC):
    @abstractmethod
    def run() -> List[Dict]              # Execute scanner
    @abstractmethod
    def normalize_findings()             # Convert to NormalizedFinding
    def execute() -> ScanResult          # Full lifecycle
    @staticmethod
    def map_severity()                   # Normalize severity
```

**Subclasses:**
- CheckovScanner: Terraform/CloudFormation IaC scanning
- ScoutSuiteScanner: Multi-cloud runtime scanning
- CloudsploitScanner: AWS-specific findings

### 2. NormalizedFinding (src/models.py)

**Unified finding format:**

```python
@dataclass
NormalizedFinding:
    # Identification
    finding_id: UUID              # Unique ID
    finding_code: str             # Scanner-specific code (CK_AWS_1)
    scanner: str                  # checkov/scoutsuite/cloudsploit
    
    # Content
    severity: SeverityLevel       # CRITICAL/HIGH/MEDIUM/LOW/INFO
    title: str
    description: str
    
    # Resource Info
    resource_type: str            # s3/sg/iam/ec2/rds/ebs
    resource_id: str              # AWS ARN/ID
    resource_name: Optional[str]
    region: Optional[str]
    
    # Remediation
    remediation_available: bool
    remediation_type: str         # terraform/ansible/manual
    
    # Classification
    cis_controls: List[str]
    risk_category: str
    
    # Status
    status: StatusEnum
    remediation_status: Optional[RemediationStatus]
    
    # Timeline
    detected_at: datetime
    last_seen_at: datetime
    remediated_at: Optional[datetime]
    
    # Metadata
    metadata: Dict[str, Any]
    tags: Dict[str, str]
```

### 3. TriageEngine (src/triage/__init__.py)

**Decision Logic:**

```
Finding Input
    ↓
Check: Remediation Available?
    ├─ No  → Manual Review
    │
Check: Severity > Threshold?
    ├─ Yes → Manual Review
    │
Check: High-Risk Resource?
    ├─ Yes → Manual Review (prod/critical)
    │
Check: False Positive?
    ├─ Yes → Manual Review
    │
Default: Auto-Remediate ✓
```

**Confidence Scoring:**
- Base: 0.85
- Scanner factor: checkov(0.9) > scoutsuite(0.8) > cloudsploit(0.75)
- Severity adjustment: LOW(+0.1), CRITICAL(-0.2)
- Range: [0.5, 1.0]

### 4. RemediationEngine (src/remediation/engine.py)

**Workflow:**

```
Findings + TriageDecisions
    ↓
plan_remediation()
    ├─ Filter: recommendation == "auto_remediate"
    │
    ├─ _create_*_remediation()
    │   ├─ _create_s3_remediation()
    │   ├─ _create_sg_remediation()
    │   ├─ _create_iam_remediation()
    │   ├─ _create_encryption_remediation()
    │   ├─ _create_container_remediation()
    │   └─ _create_generic_remediation()
    │
    └─ RemediationAction[]
            ↓
execute_remediation()
    ├─ action_type == 'terraform'
    │   └─ TerraformGenerator.generate_remediation()
    │       └─ Save .tf code
    │
    ├─ action_type == 'ansible'
    │   └─ AnsibleExecutor.generate_playbook()
    │       └─ Save playbook.yml
    │
    └─ RemediationStatus
        (PENDING/IN_PROGRESS/SUCCESS/FAILED)
```

### 5. TerraformGenerator (src/remediation/terraform_generator.py)

**Generates Terraform code based on resource type:**

```
S3 Remediation:
  ├─ aws_s3_bucket_public_access_block
  ├─ aws_s3_bucket_server_side_encryption_configuration
  ├─ aws_s3_bucket_versioning
  └─ aws_s3_bucket_logging

Security Group Remediation:
  ├─ aws_security_group_rule (revoke)
  └─ aws_security_group_rule (add restricted)

IAM Remediation:
  └─ aws_iam_role_policy (replace wildcard)

Encryption Remediation:
  ├─ EBS: New encrypted volume + snapshot
  ├─ RDS: New encrypted instance + migration
  └─ KMS: aws_kms_key + aws_kms_alias

Container Remediation:
  ├─ aws_secretsmanager_secret
  └─ aws_ecr_repository_image_scan_config
```

### 6. AnsibleExecutor (src/remediation/ansible_executor.py)

**Generates Ansible playbooks:**

```yaml
name: S3 Bucket Remediation
hosts: localhost
gather_facts: false

tasks:
  - name: Block public access on bucket
    amazon.aws.s3_bucket_public_access_block:
      bucket: "{{ bucket_name }}"
      block_public_acls: true
      ...
  
  - name: Enable encryption
    amazon.aws.s3_bucket_encryption:
      bucket: "{{ bucket_name }}"
      sse_algorithm: "AES256"
      ...
```

### 7. RemediationPipeline (src/pipeline.py)

**Main orchestrator:**

```python
class RemediationPipeline:
    def run_complete_pipeline():
        1. _step_scan()         → ScanResult[]
        2. _step_triage()       → TriageDecision[]
        3. _step_remediate()    → RemediationAction[]
        4. _generate_report()   → Comprehensive report
```

## 🔄 Data Flow

### Scan Phase
```
Checkov/ScoutSuite/CloudSploit
    ↓ (raw output)
{plugin, message, severity, resource}
    ↓ (BaseScanner.execute())
    │
    ├─ run()  → raw findings
    │
    ├─ normalize_findings() → NormalizedFinding[]
    │
    └─ ScanResult(
        scan_id, scanner_name, findings[]
      )
```

### Triage Phase
```
NormalizedFinding[]
    ↓ (TriageEngine.triage_batch())
    │
    ├─ For each finding:
    │   ├─ _is_auto_remediate()
    │   ├─ _calculate_confidence()
    │   ├─ _generate_reasoning()
    │
    └─ TriageDecision[]
        {
          finding_id,
          recommendation,
          confidence_score,
          reasoning
        }
```

### Remediation Phase
```
NormalizedFinding[] + TriageDecision[]
    ↓ (RemediationEngine.plan_remediation())
    │
    ├─ Filter: auto_remediate only
    │
    ├─ For each eligible finding:
    │   ├─ _create_*_remediation()
    │   └─ RemediationAction
    │
    └─ RemediationAction[]
            ↓
    (RemediationEngine.execute_batch())
    │
    ├─ For each action:
    │   ├─ _execute_terraform()
    │   │   └─ TerraformGenerator.generate()
    │   │   └─ Save/Execute
    │   │
    │   └─ RemediationStatus
    │
    └─ execution_results{}
        {finding_id → RemediationAction}
```

## 🎯 Remediation Mapping

### S3 Findings → Terraform

| Finding | Action | Terraform Resource |
|---------|--------|------------------|
| Publicly accessible | Block public access | aws_s3_bucket_public_access_block |
| No encryption | Enable SSE | aws_s3_bucket_server_side_encryption_configuration |
| No versioning | Enable versioning | aws_s3_bucket_versioning |
| No logging | Enable logging | aws_s3_bucket_logging |

### Security Group Findings → Terraform

| Finding | Action | Terraform Resource |
|---------|--------|------------------|
| 0.0.0.0/0 ingress | Revoke + restrict | aws_security_group_rule |

### IAM Findings → Terraform

| Finding | Action | Terraform Resource |
|---------|--------|------------------|
| Wildcard actions | Restrict permissions | aws_iam_role_policy |
| Root access | Deny root | aws_iam_policy |

## 🔍 Key Classes & Methods

### RemediationAction
```python
class RemediationAction:
    finding_id: str
    resource_type: str
    resource_id: str
    action_type: str           # 'terraform', 'ansible', 'manual'
    action_details: Dict
    status: RemediationStatus
    
    def to_dict() → Dict       # Serialize for JSON
```

### TerraformGenerator
```python
def generate_remediation(action) → str          # Full TF code
def _generate_s3_remediation()
def _generate_sg_remediation()
def _generate_iam_remediation()
def _generate_encryption_remediation()
def _generate_container_remediation()
def save_remediation_tf() → Path                # Write to file
```

### AnsibleExecutor
```python
def generate_playbook(action) → str             # Full YAML
def _generate_s3_playbook()
def _generate_sg_playbook()
def _generate_iam_playbook()
def save_playbook() → Path                      # Write to file
def execute_playbook() → bool                   # Run playbook
```

## 📊 Output Schemas

### ScanResult
```json
{
  "scan_id": "uuid",
  "scanner_name": "CheckovScanner",
  "start_time": "2026-04-29T10:00:00",
  "end_time": "2026-04-29T10:05:00",
  "status": "success",
  "findings_count": 25,
  "findings": [NormalizedFinding]
}
```

### TriageDecision
```json
{
  "finding_id": "uuid",
  "recommendation": "auto_remediate",
  "confidence_score": 0.92,
  "reasoning": "Severity: HIGH; remediation available...",
  "metadata": {
    "severity": "HIGH",
    "resource_type": "s3"
  }
}
```

### RemediationAction
```json
{
  "finding_id": "uuid",
  "resource_type": "s3",
  "action_type": "terraform",
  "status": "SUCCESS",
  "created_at": "2026-04-29T10:00:00",
  "executed_at": "2026-04-29T10:05:00",
  "result": {
    "terraform_code": "..."
  }
}
```

## 🔧 Extension Points

### Adding New Scanner
```python
class MyScanner(BaseScanner):
    def run(self) -> List[Dict]:
        # Execute your scanner
        pass
    
    def normalize_findings(self, raw) -> List[NormalizedFinding]:
        # Convert to standard format
        pass
```

### Adding New Remediation Handler
```python
def _create_custom_remediation(self, finding):
    action_details = {
        'service': 'custom',
        'actions': [...]
    }
    return RemediationAction(...)
```

### Adding New Triage Rule
```python
def _is_auto_remediate(self, finding):
    # Add custom logic
    if custom_condition(finding):
        return False
    # Default behavior
    return super()._is_auto_remediate(finding)
```

## 🚀 Performance Considerations

### Parallelization Opportunities
- Scanners can run in parallel
- Triage decisions are independent
- Remediation actions can be batched

### Memory Optimization
- Stream large finding lists
- Clean up temporary files
- Use generators for large datasets

### Error Handling
- Graceful degradation (scanner failure)
- Partial results reporting
- Comprehensive logging

---

**Version**: 1.0  
**Last Updated**: 2026-04-29
