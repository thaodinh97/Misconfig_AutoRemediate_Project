# 🚀 Quick Start Guide

## Installation & Setup (5 min)

### 1. Clone & Install

```bash
cd e:/Misconfig_AutoRemediate_Project
pip install -r requirements.txt
```

### 2. Configure AWS

```bash
aws configure
# or
export AWS_PROFILE=your-profile
export AWS_REGION=us-east-1
```

### 3. Install Scanners

```bash
# Checkov (Terraform)
pip install checkov

# ScoutSuite (Multi-cloud)
pip install scoutsuite

# CloudSploit (AWS)
npm install -g cloudsploit
```

---

## Running the Pipeline

### Dry-Run Mode (Safe - No Changes)

```bash
python remediate.py --dry-run
```

**Output:**
```
[STEP 1/4] SCANNING for misconfigurations...
  - Running Checkov...
    ✓ Checkov: 12 findings
  - Running ScoutSuite...
    ✓ ScoutSuite: 8 findings
  - Running CloudSploit...
    ✓ CloudSploit: 5 findings
  Total: 25 findings collected

[STEP 2/4] Normalized 25 findings

[STEP 3/4] TRIAGING findings...
  Triage Results:
    - Auto-remediate: 18
    - Manual review: 7
    - Avg confidence: 0.89

[STEP 4/4] REMEDIATING...
  Planning remediation actions...
    - 18 remediation actions planned
  DRY RUN MODE - Remediation actions not executed

PIPELINE SUMMARY
================
Total Findings: 25
  Critical: 2
  High: 8
  Medium: 12
  Low: 3

Auto-Remediate: 18 (72%)
Manual Review: 7 (28%)

Recommendations:
  1. Address 10 high-severity findings immediately
  2. Review and approve 7 findings for remediation
  3. Review S3 bucket policies and access controls
  4. Audit security group ingress/egress rules
  5. Review IAM policies and apply least privilege principle
```

### Full Execution (Production)

```bash
python remediate.py \
  --terraform-dir ./iac/terraform \
  --output-dir ./remediation_results \
  --log-level INFO
```

---

## Understanding the Output

### 📊 Findings JSON

```bash
cat remediation_results/findings_*.json | jq '.'
```

**Example finding:**
```json
{
  "finding_id": "a1b2c3d4-e5f6-4a5b-9c8d-7e6f5a4b3c2d",
  "finding_code": "CK_AWS_63",
  "scanner": "checkov",
  "severity": "HIGH",
  "title": "S3 Bucket does not have encryption enabled",
  "description": "Bucket: my-bucket - Not encrypted",
  "resource_type": "s3",
  "resource_id": "my-bucket",
  "remediation_available": true,
  "remediation_type": "terraform",
  "metadata": {
    "file_path": "iac/terraform/m4_unencrypted_storage.tf",
    "check_id": "CK_AWS_63"
  }
}
```

### 🎯 Triage Decisions

```bash
cat remediation_results/remediation_actions_*.json | jq '.actions[0]'
```

**Decision example:**
```json
{
  "finding_id": "a1b2c3d4-e5f6-4a5b-9c8d-7e6f5a4b3c2d",
  "recommendation": "auto_remediate",
  "confidence_score": 0.92,
  "reasoning": "Severity: HIGH; Resource: s3/my-bucket; Scanner: checkov; Available: Yes; Decision: Automatically remediate based on severity and availability",
  "metadata": {
    "severity": "HIGH",
    "resource_type": "s3",
    "resource_id": "my-bucket",
    "remediation_available": true,
    "scanner": "checkov"
  }
}
```

### ⚙️ Remediation Actions

```bash
cat remediation_results/remediation_actions_*.json | jq '.actions[0]'
```

**Action example:**
```json
{
  "finding_id": "a1b2c3d4-e5f6-4a5b-9c8d-7e6f5a4b3c2d",
  "resource_type": "s3",
  "resource_id": "my-bucket",
  "action_type": "terraform",
  "status": "SUCCESS",
  "created_at": "2026-04-29T10:05:30.123456",
  "executed_at": "2026-04-29T10:05:35.234567",
  "completed_at": "2026-04-29T10:05:40.345678",
  "result": {
    "terraform_code": "resource \"aws_s3_bucket_public_access_block\" ..."
  }
}
```

### 📈 Pipeline Report

```bash
cat remediation_results/pipeline_report_*.json | jq '.'
```

---

## Common Scenarios

### Scenario 1: Review S3 Findings

```bash
# Extract S3 findings only
cat remediation_results/findings_*.json | \
  jq '.findings[] | select(.resource_type=="s3")'
```

### Scenario 2: Check High-Severity Issues

```bash
# Critical and High findings
cat remediation_results/findings_*.json | \
  jq '.findings[] | select(.severity=="CRITICAL" or .severity=="HIGH")'
```

### Scenario 3: Manual Review Required

```bash
# Get decisions for manual review
cat remediation_results/remediation_actions_*.json | \
  jq '.actions[] | select(.recommendation=="manual_review")'
```

### Scenario 4: Remediation Failures

```bash
# Check which remediation actions failed
cat remediation_results/remediation_actions_*.json | \
  jq '.actions[] | select(.status=="FAILED")'
```

---

## Configuration Examples

### Config 1: Conservative (Manual Review Most)

```env
AUTO_REMEDIATE_SEVERITY_THRESHOLD=CRITICAL
```
- Only auto-remediate CRITICAL severity
- Everything else: manual review

### Config 2: Aggressive (Auto-Remediate Most)

```env
AUTO_REMEDIATE_SEVERITY_THRESHOLD=LOW
```
- Auto-remediate LOW, MEDIUM, HIGH
- Only CRITICAL: manual review

### Config 3: Production-Safe

```env
AUTO_REMEDIATE_SEVERITY_THRESHOLD=MEDIUM
ENABLE_AUTO_REMEDIATION=false
```
- Plan remediations but don't execute
- Manual approval required before execution

---

## Troubleshooting

### Issue: "Checkov not found"
```bash
pip install checkov
which checkov
```

### Issue: "AWS credentials not configured"
```bash
aws configure
# or
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
```

### Issue: "No findings detected"
```bash
# Check Terraform files exist
ls -la ./iac/terraform/

# Run scanners individually
checkov -d ./iac/terraform
scout aws
```

### Issue: "Permission denied on remediation"
```bash
# Check AWS IAM permissions
aws iam get-user
aws iam list-attached-user-policies --user-name <your-user>
```

---

## Workflow Examples

### Example 1: Scan Only
```bash
python remediate.py --dry-run --log-level DEBUG | head -100
```

### Example 2: Scan + Triage Only
```bash
# View triage decisions without remediation
python remediate.py --dry-run
cat remediation_results/remediation_actions_*.json | jq '.[] | .recommendation' | sort | uniq -c
```

### Example 3: Full Pipeline with Logging
```bash
python remediate.py \
  --terraform-dir ./iac/terraform \
  --output-dir ./remediation_results \
  --log-level DEBUG 2>&1 | tee pipeline.log
```

---

## Next Steps

1. **Read Documentation**
   - [REMEDIATION_GUIDE.md](REMEDIATION_GUIDE.md) - Complete guide
   - [ARCHITECTURE.md](ARCHITECTURE.md) - Technical details

2. **Test with Dry-Run**
   ```bash
   python remediate.py --dry-run
   ```

3. **Review Findings**
   ```bash
   cat remediation_results/findings_*.json | jq '.' | less
   ```

4. **Approve & Execute**
   ```bash
   python remediate.py
   ```

5. **Monitor Results**
   ```bash
   cat remediation_results/pipeline_report_*.json | jq '.recommendations'
   ```

---

## Key Files

| File | Purpose |
|------|---------|
| `remediate.py` | Main entry point |
| `src/pipeline.py` | Pipeline orchestrator |
| `src/scanners/` | Security scanners |
| `src/triage/__init__.py` | Decision engine |
| `src/remediation/` | Remediation execution |
| `iac/terraform/` | Infrastructure as Code |
| `remediation_results/` | Output files |

---

## Support & Debugging

### Enable Debug Logging
```bash
export LOGLEVEL=DEBUG
python remediate.py --log-level DEBUG
```

### Check Logs
```bash
# View in real-time
tail -f remediation_results/*.json

# Search for errors
grep -i "error" remediation_results/*.json
```

### Validate Configuration
```python
from src.config import Config
print(f"AWS Region: {Config.AWS_REGION}")
print(f"Checkov Enabled: {Config.ENABLE_CHECKOV}")
```

---

**Happy Remediating! 🎉**
