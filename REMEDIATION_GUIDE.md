# Misconfig Auto-Remediation Pipeline

Tự động phát hiện, phân loại và khắc phục sai cấu hình đám mây trên AWS.

## 📊 Quy Trình (Workflow)

```
┌─────────────────────┐
│  SECURITY SCANNERS  │  Checkov / ScoutSuite / CloudSploit
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│   NORMALIZER        │  Chuyển đổi định dạng → NormalizedFinding
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│  TRIAGE ENGINE      │  Phân tích → Quyết định: Auto/Manual/Ignore
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│ REMEDIATION ENGINE  │  Thực thi → Terraform / Ansible
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│  RESULT REPORT      │  JSON / Metrics
└─────────────────────┘
```

## 🎯 Các Thành Phần Chính

### 1. **SCANNERS** (src/scanners/)
- **CheckovScanner**: Quét IaC (Terraform, CloudFormation)
- **ScoutSuiteScanner**: Quét cấu hình AWS runtime
- **CloudsploitScanner**: Phát hiện lỗi bảo mật AWS

**Đầu ra**: Raw findings từ mỗi scanner

### 2. **NORMALIZER** (src/scanners/)
Chuyển đổi các định dạng scanner khác nhau thành `NormalizedFinding`:
```python
# Cấu trúc chuẩn
NormalizedFinding(
    finding_id: str              # UUID duy nhất
    finding_code: str            # Mã từ scanner (e.g., CK_AWS_1)
    scanner: str                 # Tên scanner
    severity: SeverityLevel      # CRITICAL/HIGH/MEDIUM/LOW/INFO
    resource_type: str           # s3, sg, iam, ec2...
    resource_id: str             # AWS resource ID
    remediation_available: bool  # Có thể tự động sửa không?
    metadata: dict               # Dữ liệu bổ sung
)
```

### 3. **TRIAGE ENGINE** (src/triage/)
**Quyết định** cho mỗi finding:
- **auto_remediate**: Tự động khắc phục (low/medium severity, remediation available)
- **manual_review**: Cần kiểm tra thủ công (high/critical, không rõ)
- **ignore**: Bỏ qua (whitelisted, false positive)

```python
TriageDecision(
    finding_id: str
    recommendation: str          # "auto_remediate" | "manual_review" | "ignore"
    confidence_score: float      # 0.0-1.0
    reasoning: str               # Lý do quyết định
)
```

### 4. **REMEDIATION ENGINE** (src/remediation/)
Thực thi các hành động khắc phục:
- **Terraform**: Tạo code TF để sửa lỗi
- **Ansible**: Tạo playbook để thực thi
- **Manual**: Hướng dẫn cho các trường hợp phức tạp

```
Finding → RemediationAction → TerraformGenerator/AnsibleExecutor → Execution
```

### 5. **PIPELINE** (src/pipeline.py)
Orchestrator chính kết nối tất cả các thành phần

## 🚀 Cách Sử Dụng

### 1. **Cài đặt Dependencies**

```bash
pip install -r requirements.txt
```

### 2. **Cấu hình Environment**

```bash
# .env file
AWS_PROFILE=default
AWS_REGION=us-east-1
ENABLE_CHECKOV=true
ENABLE_SCOUTSUITE=true
ENABLE_CLOUDSPLOIT=true
ENABLE_AUTO_REMEDIATION=false
AUTO_REMEDIATE_SEVERITY_THRESHOLD=MEDIUM
```

### 3. **Chạy Pipeline**

#### Chế độ DRY-RUN (không thực thi):
```bash
python remediate.py --dry-run
```

#### Chế độ bình thường:
```bash
python remediate.py \
  --terraform-dir ./iac/terraform \
  --output-dir ./remediation_results \
  --log-level INFO
```

### 4. **Kiểm tra Kết quả**

```bash
# Findings được normalize
cat remediation_results/findings_*.json

# Remediation actions
cat remediation_results/remediation_actions_*.json

# Pipeline report
cat remediation_results/pipeline_report_*.json
```

## 📋 Cấu Trúc Thư Mục

```
src/
├── scanners/
│   ├── __init__.py              # BaseScanner
│   ├── checkov_scanner.py       # Checkov integration
│   ├── scoutsuite_scanner.py    # ScoutSuite integration
│   ├── cloudsploit_scanner.py   # CloudSploit integration
│   └── runner.py                # ScannerRunner orchestrator
│
├── triage/
│   ├── __init__.py              # TriageEngine
│   └── engine.py                # Decision logic
│
├── remediation/
│   ├── __init__.py
│   ├── engine.py                # RemediationEngine
│   ├── terraform_generator.py   # Generate TF code
│   └── ansible_executor.py      # Generate playbooks
│
├── models.py                    # Pydantic schemas
├── config.py                    # Configuration
└── pipeline.py                  # Main pipeline

iac/terraform/
├── main.tf
├── variables.tf
├── outputs.tf
└── m*.tf                        # Misconfiguration examples
```

## 🔧 Remediation Strategy

### S3 Buckets
```
Problem: Public access, no encryption
Solution:
  - Block public access
  - Enable encryption (AES-256/KMS)
  - Enable versioning
  - Enable logging
```

### Security Groups
```
Problem: Wide-open ingress (0.0.0.0/0)
Solution:
  - Revoke 0.0.0.0/0 rules
  - Add restricted rules (e.g., office IP)
```

### IAM Roles
```
Problem: Wildcard permissions (*)
Solution:
  - Remove wildcard policies
  - Apply least privilege (specific actions/resources)
```

### Encryption
```
Problem: Unencrypted storage (EBS, RDS)
Solution:
  - Enable encryption
  - Use KMS keys
  - Enable key rotation
```

### Container Secrets
```
Problem: Secrets in environment variables
Solution:
  - Move to AWS Secrets Manager
  - Update task definitions
```

## 📊 Output Format

### Findings JSON
```json
{
  "total": 25,
  "findings": [
    {
      "finding_id": "uuid",
      "finding_code": "CK_AWS_1",
      "scanner": "checkov",
      "severity": "HIGH",
      "resource_type": "s3",
      "resource_id": "my-bucket",
      "description": "S3 bucket is publicly accessible",
      "remediation_available": true,
      "metadata": {}
    }
  ]
}
```

### Triage Decisions
```json
{
  "total_decisions": 25,
  "decisions": [
    {
      "finding_id": "uuid",
      "recommendation": "auto_remediate",
      "confidence_score": 0.92,
      "reasoning": "Severity: HIGH; remediation available; not high-risk resource"
    }
  ]
}
```

### Remediation Actions
```json
{
  "total": 10,
  "actions": [
    {
      "finding_id": "uuid",
      "resource_type": "s3",
      "action_type": "terraform",
      "status": "SUCCESS"
    }
  ]
}
```

## 🎓 Ví Dụ Cụ Thể

### Sửa S3 bucket không được mã hóa

**Finding:**
```
Finding: M4_Unencrypted Storage
Resource: s3/my-bucket
Description: S3 bucket does not have encryption enabled
```

**Triage Decision:**
```
Recommendation: auto_remediate
Confidence: 0.95
Reasoning: Low severity; encryption available; not production
```

**Remediation Action:**
```terraform
resource "aws_s3_bucket_server_side_encryption_configuration" "remediate_my_bucket" {
  bucket = "my-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```

## ⚙️ Tuning Parameters

### Triage Configuration
```python
{
    'auto_remediate_threshold': 'MEDIUM',  # Không tự động sửa CRITICAL/HIGH
    'high_risk_resources': ['prod', 'production', 'critical'],
    'manual_review_severity': 'HIGH',
    'remediation_blacklist': [],  # Findings không được phép sửa
}
```

### Remediation Settings
```env
ENABLE_AUTO_REMEDIATION=false           # Bật/tắt tự động sửa
AUTO_REMEDIATE_SEVERITY_THRESHOLD=MEDIUM
DRY_RUN=true                            # Test mode
APPROVAL_REQUIRED=true                  # Cần phê duyệt
```

## 📈 Pipeline Metrics

**Scan Results:**
- Số findings theo severity
- Phân bổ theo scanner
- Thời gian scan

**Triage Results:**
- % auto-remediate vs manual review
- Confidence score trung bình

**Remediation Results:**
- Thành công vs thất bại
- Success rate
- Thời gian execution

## ❌ Troubleshooting

### Checkov không tìm thấy
```bash
pip install checkov
# hoặc
brew install checkov  # macOS
```

### ScoutSuite không chạy
```bash
pip install scoutsuite
scout aws
```

### CloudSploit không tìm thấy
```bash
npm install -g cloudsploit
# hoặc
npx cloudsploit scan --cloud aws
```

### Lỗi AWS credentials
```bash
aws configure
export AWS_PROFILE=my-profile
```

## 🔒 Security Notes

1. **Dry-run mặc định**: Hãy chạy `--dry-run` trước để xem kế hoạch
2. **Manual approval**: Bật APPROVAL_REQUIRED cho production
3. **Credentials**: Sử dụng AWS IAM roles, không hardcode credentials
4. **Audit logging**: Tất cả remediation được ghi lại trong logs
5. **Rollback plan**: Giữ snapshot/backup trước khi thực thi

## 📝 Logs

```bash
# Verbose logging
python remediate.py --log-level DEBUG

# Output location
remediation_results/
├── scans/
│   ├── checkov_*.json
│   ├── scoutsuite_*.json
│   └── cloudsploit_*.json
├── playbooks/
│   └── remediation_*.yml
├── findings_*.json
├── remediation_actions_*.json
└── pipeline_report_*.json
```

## 🚦 Status Codes

```python
# Finding Status
OPEN = "OPEN"
ACKNOWLEDGED = "ACKNOWLEDGED"
IN_PROGRESS = "IN_PROGRESS"
REMEDIATED = "REMEDIATED"
FALSE_POSITIVE = "FALSE_POSITIVE"
WONT_FIX = "WONT_FIX"

# Remediation Status
PENDING = "PENDING"
IN_PROGRESS = "IN_PROGRESS"
SUCCESS = "SUCCESS"
FAILED = "FAILED"
ROLLED_BACK = "ROLLED_BACK"
```

## 🔗 Liên Kết Hữu Ích

- [Checkov Docs](https://www.checkov.io/)
- [ScoutSuite Docs](https://github.com/nccgroup/ScoutSuite)
- [CloudSploit Docs](https://github.com/aquasecurity/cloudsploit)
- [AWS CLI](https://aws.amazon.com/cli/)
- [Terraform](https://www.terraform.io/)

## 📄 License

MIT License

## 👥 Contributing

Đóng góp ý tưởng và improvements!

---

**Tạo bởi**: Misconfig Auto-Remediation Team  
**Cập nhật lần cuối**: 2026-04-29
