# CloudTrail Integration Guide

## Tổng Quan

Hệ thống đã được tích hợp với AWS CloudTrail để phát hiện các thay đổi cấu hình thời gian thực trên AWS infrastructure và tự động remediate nếu phát hiện drift.

**Kiến trúc:**
```
AWS CloudTrail Events
        ↓
  EventBridge (Real-time)
        ↓
  SQS / Lambda
        ↓
CloudTrail Scanner → Drift Detector → Normalizer
        ↓
  Triage Engine
        ↓
Auto-Remediation (nếu cần)
```

## 1. Cài Đặt AWS Infrastructure

### 1.1 Enable CloudTrail

```bash
aws cloudtrail create-trail \
  --name misconfig-trail \
  --s3-bucket-name misconfig-cloudtrail-logs \
  --region us-east-1

aws cloudtrail start-logging --trail-name misconfig-trail
```

### 1.2 Tạo EventBridge Rule để capture CloudTrail events

```bash
# Tạo SQS queue để nhận events
aws sqs create-queue \
  --queue-name cloudtrail-events-queue \
  --region us-east-1

# Lấy queue ARN
QUEUE_ARN=$(aws sqs get-queue-attributes \
  --queue-url https://sqs.us-east-1.amazonaws.com/ACCOUNT_ID/cloudtrail-events-queue \
  --attribute-names QueueArn \
  --query 'Attributes.QueueArn' \
  --output text)

# Tạo EventBridge rule
aws events put-rule \
  --name cloudtrail-configuration-changes \
  --event-pattern '{
    "source": ["aws.cloudtrail"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventName": [
        "PutBucketPolicy",
        "PutBucketPublicAccessBlock",
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "PutRolePolicy",
        "AttachRolePolicy",
        "ModifyDBInstance",
        "CreateDBInstance",
        "PutParameter"
      ]
    }
  }' \
  --region us-east-1

# Target: SQS Queue
aws events put-targets \
  --rule cloudtrail-configuration-changes \
  --targets "Id"="1","Arn"="$QUEUE_ARN" \
  --region us-east-1
```

### 1.3 (Optional) Cấu hình Lambda Function

Nếu muốn xử lý events trong Lambda thay vì SQS:

```bash
# Tạo Lambda execution role
aws iam create-role \
  --role-name cloudtrail-remediation-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "lambda.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  }'

# Thêm IAM permissions
aws iam attach-role-policy \
  --role-name cloudtrail-remediation-role \
  --policy-arn arn:aws:iam::aws:policy/AWSLambdaFullAccess

aws iam attach-role-policy \
  --role-name cloudtrail-remediation-role \
  --policy-arn arn:aws:iam::aws:policy/EC2FullAccess

# Tạo Lambda function từ eventbridge_listener.py
zip lambda_function.zip src/remediation/eventbridge_listener.py

aws lambda create-function \
  --function-name cloudtrail-remediation \
  --runtime python3.11 \
  --role arn:aws:iam::ACCOUNT_ID:role/cloudtrail-remediation-role \
  --handler src/remediation/eventbridge_listener.lambda_handler \
  --zip-file fileb://lambda_function.zip
```

## 2. Cách Sử Dụng

### 2.1 Chạy CloudTrail Scanner Standalone

```bash
# Quét những configuration changes gần đây
python -m src.scanners.cloudtrail_scanner \
  --region us-east-1 \
  --output findings.json \
  --pretty

# Output:
# {
#   "scan_id": "cloudtrail-1234567890",
#   "scanner": "cloudtrail",
#   "status": "success",
#   "findings_count": 5,
#   "findings": [...]
# }
```

### 2.2 Chạy Drift Detection

```bash
# Phát hiện drift so với Terraform state
python -m src.scanners.cloudtrail_drift_detector \
  --terraform-dir iac/terraform \
  --region us-east-1 \
  --cloudtrail-events cloudtrail_events.json \
  --output drift_findings.json
```

### 2.3 Normalize CloudTrail Events

```bash
# Chuyển đổi CloudTrail events sang định dạng chuẩn
python normalizer.py \
  --input cloudtrail_events.json \
  --scanner cloudtrail \
  --output normalized_findings.json \
  --wrap
```

### 2.4 Chạy Full Pipeline với CloudTrail

```bash
# Quét với tất cả scanners bao gồm CloudTrail
python -m src.scanners.runner \
  --cloudtrail \
  --checkov \
  --tfsec \
  --region us-east-1 \
  --output-dir ./scan_results

# Kế tiếp: Triage
python -m src.triage.engine \
  --input ./scan_results/normalized_findings.json \
  --output ./scan_results/decisions.json

# Cuối cùng: Remediation (nếu cần)
python -m src.remediation.runner \
  --flow hybrid-dispatch \
  -- \
  --findings ./scan_results/normalized_findings.json \
  --decisions ./scan_results/decisions.json
```

### 2.5 SQS Listener (Deployment)

```bash
# Chạy persistent listener để xử lý events từ SQS
python -m src.remediation.eventbridge_listener \
  --mode sqs-listener \
  --queue-url https://sqs.us-east-1.amazonaws.com/ACCOUNT_ID/cloudtrail-events-queue \
  --region us-east-1

# Output:
# INFO     2024-05-28 10:15:30 - CloudTrail Listener started on queue...
# INFO     2024-05-28 10:15:45 - Received CloudTrail event: PutBucketPolicy
# INFO     2024-05-28 10:15:46 - Drift detected: 1 changes
# INFO     2024-05-28 10:15:50 - Remediation triggered
```

## 3. Configuration

### 3.1 Environment Variables

```bash
# AWS
export AWS_REGION=us-east-1
export AWS_PROFILE=default
export AWS_ACCOUNT_ID=123456789012

# CloudTrail
export CLOUDTRAIL_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/ACCOUNT_ID/queue
export CLOUDTRAIL_ENABLED=true

# Terraform
export TERRAFORM_DIR=./iac/terraform
export TF_STATE_BUCKET=my-terraform-state
```

### 3.2 Triage Configuration

```bash
# config/triage.yaml
cloudtrail_auto_remediate_threshold: HIGH  # CRITICAL, HIGH, MEDIUM, LOW
high_risk_resources:
  - prod
  - production
  - critical
```

## 4. Monitored Events

CloudTrail scanner phát hiện các sự kiện sau:

### S3 Bucket Changes
- `PutBucketPolicy` - Thay đổi bucket policy
- `PutBucketPublicAccessBlock` - Thay đổi public access settings
- `PutBucketVersioning` - Kích hoạt/vô hiệu hóa versioning
- `PutBucketLogging` - Thay đổi logging settings

### Security Group Changes
- `AuthorizeSecurityGroupIngress` - Thêm ingress rule
- `AuthorizeSecurityGroupEgress` - Thêm egress rule
- `RevokeSecurityGroupIngress` - Xóa ingress rule
- `RevokeSecurityGroupEgress` - Xóa egress rule
- `DeleteSecurityGroup` - Xóa security group

### IAM Policy Changes
- `PutRolePolicy` - Cập nhật inline policy
- `AttachRolePolicy` - Gắn managed policy
- `DetachRolePolicy` - Gỡ bỏ managed policy
- `CreateRole` - Tạo role mới

### Database Changes
- `ModifyDBInstance` - Thay đổi RDS configuration
- `CreateDBInstance` - Tạo RDS instance mới

### Parameter Store Changes
- `PutParameter` - Cập nhật/tạo parameter

## 5. Drift Detection

Drift detector so sánh:

1. **Live Configuration** (AWS CLI describe-* calls)
2. **Intended Configuration** (Terraform state)
3. **CloudTrail Events** (Recent changes)

### Ví dụ Drift Detection Output

```json
{
  "total_findings": 2,
  "findings": [
    {
      "finding_id": "drift-AWS_SG_UNINTENDED_RULE-sg-12345",
      "finding_code": "AWS_SG_UNINTENDED_RULE",
      "scanner": "cloudtrail_drift",
      "severity": "HIGH",
      "title": "Unintended Security Group Rule Detected",
      "description": "Security group sg-12345 has rule that doesn't match Terraform config",
      "resource_id": "sg-12345",
      "resource_type": "security_group",
      "metadata": {
        "sg_id": "sg-12345",
        "rule": {
          "IpProtocol": "tcp",
          "FromPort": 22,
          "ToPort": 22,
          "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        },
        "drift_type": "unexpected_rule"
      }
    }
  ]
}
```

## 6. Remediation Actions

Khi phát hiện drift/misconfiguration, hệ thống có thể:

1. **Auto-Fix** (Custodian policies)
   - Xóa overly permissive security group rules
   - Kích hoạt bucket encryption
   - Gắn proper IAM policies

2. **Pull Request** (IaC PR)
   - Tạo PR để update Terraform code
   - Reconcile config drift

3. **Slack Notification**
   - Gửi alert tới team
   - Manual review required

4. **OPA Ticket**
   - Tạo ticket trong OPA system
   - Track remediation progress

## 7. Monitoring & Logging

### Logs

```bash
# CloudTrail Scanner logs
tail -f artifacts/cloudtrail_scanner.log

# EventBridge Listener logs
tail -f logs/eventbridge_listener.log

# Remediation logs
tail -f logs/remediation.log
```

### Metrics

```bash
# Xem remediation metrics
python -m src.remediation.metrics \
  --input artifacts/remediation/remediation_metrics.json

# Output:
# Total Findings: 15
# Remediated: 12 (80%)
# Failed: 2 (13%)
# Pending: 1 (7%)
# Average Time: 4.2 minutes
```

## 8. Troubleshooting

### Issue: "No findings detected"

```bash
# Kiểm tra CloudTrail events
aws cloudtrail lookup-events \
  --region us-east-1 \
  --max-results 10 \
  --output table

# Kiểm tra EventBridge rule
aws events describe-rule \
  --name cloudtrail-configuration-changes

# Kiểm tra SQS messages
aws sqs receive-message \
  --queue-url https://sqs.us-east-1.amazonaws.com/ACCOUNT_ID/queue
```

### Issue: "Drift detection failed"

```bash
# Kiểm tra Terraform state
terraform -chdir=iac/terraform state list

# Validate Terraform config
terraform -chdir=iac/terraform validate

# Kiểm tra AWS credentials
aws sts get-caller-identity
```

### Issue: "Remediation failed"

```bash
# Kiểm tra IAM permissions
aws iam get-user

# Kiểm tra security group status
aws ec2 describe-security-groups \
  --group-ids sg-12345

# Check remediation logs
cat artifacts/remediation/runtime_events.json | grep -i error
```

## 9. Best Practices

1. **Regular Testing**
   - Test drift detection thường xuyên
   - Validate remediation actions trong staging trước

2. **High-Risk Resource Protection**
   - Đánh dấu production resources
   - Require manual approval trước remediation

3. **Monitoring**
   - Theo dõi CloudTrail logs
   - Set up CloudWatch alarms cho critical changes

4. **Documentation**
   - Document approved changes
   - Keep audit trail của tất cả remediations

5. **Backup**
   - Backup Terraform state định kỳ
   - Test disaster recovery procedures

## 10. API Reference

### CloudTrailScanner

```python
from src.scanners.cloudtrail_scanner import CloudTrailScanner

scanner = CloudTrailScanner(provider="aws", region="us-east-1")
result = scanner.execute()

# result properties:
# - scan_id: str
# - scanner_name: str
# - status: str (success/failed)
# - findings_count: int
# - findings: List[NormalizedFinding]
# - error_message: Optional[str]
```

### CloudTrailDriftDetector

```python
from src.scanners.cloudtrail_drift_detector import CloudTrailDriftDetector

detector = CloudTrailDriftDetector(
    terraform_dir="iac/terraform",
    region="us-east-1"
)

findings = detector.detect_drift_from_events(cloudtrail_events)
drift_detected, plan = detector.run_terraform_plan()
```

### EventBridgeCloudTrailListener

```python
from src.remediation.eventbridge_listener import EventBridgeCloudTrailListener

listener = EventBridgeCloudTrailListener(
    queue_url="https://sqs...",
    region="us-east-1"
)

# For Lambda
result = listener.lambda_handler(event, context)

# For SQS polling
listener.listen_sqs(queue_url)

# For file processing
result = listener._process_cloudtrail_event(ct_event)
```

## Tham Khảo Thêm

- [AWS CloudTrail Documentation](https://docs.aws.amazon.com/cloudtrail/)
- [AWS EventBridge Documentation](https://docs.aws.amazon.com/eventbridge/)
- [Project Architecture](05_Misconfig_AutoRemediate.md)
- [Remediation Guide](docs/REMEDIATION.md)
