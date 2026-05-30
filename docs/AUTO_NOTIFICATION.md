# Auto-Notification on CloudTrail Config Changes

## 🎯 **Hiện Tại (Trước)**

Project **có** Slack integration nhưng:
- ❌ Chỉ manual trigger (phải chạy command)
- ❌ Không auto-detect khi có config change
- ❌ Không tích hợp vào CloudTrail pipeline

## ✅ **Mới (Sau)**

**Tự động phát hiện + gửi Slack alert** khi AWS config thay đổi:

```
CloudTrail Event (config change)
    ↓
EventBridge Listener
    ├→ CloudTrail Scanner (phát hiện issue)
    ├→ Drift Detector (so sánh vs Terraform)
    ├→ Normalizer (chuẩn hóa findings)
    ├→ Triage Engine (phân loại severity)
    └→ ✅ Auto-Notify (gửi Slack ngay)
```

## 📦 **Thành Phần Mới**

### 1. `auto_notify.py` - Auto-notification Service
```python
AutoNotificationService
├─ process_new_findings() - Process findings & send Slack
├─ watch_and_notify() - Continuous monitoring mode
└─ _filter_new_findings() - Avoid duplicate notifications
```

### 2. `notify_from_findings()` API - Programmatic Notifications
```python
from src.triage.notifications import notify_from_findings

result = notify_from_findings(
    findings=findings_list,
    decisions=decisions_list,
    dispatch=True,  # Send Slack
    output_dir="artifacts/auto_notifications"
)
```

### 3. Enhanced EventBridge Listener
- Tự động gửi notification cho manual review findings
- Khi không cần auto-remediate

## 🚀 **Cách Sử Dụng**

### **Option 1: Auto-notification khi CloudTrail events**

EventBridge tự động trigger Lambda → Notifications gửi Slack:

```bash
# Setup environment
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK"
export DEFAULT_SECURITY_OWNER="security-team@example.com"

# Deploy Lambda function
# → Tự động nhận events từ EventBridge
# → Process CloudTrail config changes
# → Gửi Slack alert cho manual review findings
```

### **Option 2: One-shot notification (CLI)**

```bash
# Chạy scanner, triage, rồi gửi Slack
python -m src.scanners.runner --cloudtrail --region us-east-1
python -m src.triage.engine --input ./scan_results/findings.json
python -m src.triage.auto_notify notify \
    --findings ./scan_results/findings.json \
    --decisions ./triage_results/decisions.json \
    --dispatch-live

# Output:
# INFO     2024-05-28 10:15:50 - Processing 5 findings for notification
# INFO     2024-05-28 10:15:51 - Slack notification sent to @security-team
```

### **Option 3: Continuous watcher (Development)**

```bash
# Run in terminal, watches for new findings continuously
python -m src.triage.auto_notify watch \
    --findings ./scan_results/findings.json \
    --decisions ./triage_results/decisions.json \
    --poll-interval 5 \
    --dispatch-live

# Output:
# INFO     2024-05-28 10:15:00 - Starting auto-notification service
# INFO     2024-05-28 10:15:10 - Finding changes detected, processing...
# INFO     2024-05-28 10:15:11 - Slack notification sent
```

## 📊 **Slack Alert Format**

```
🔴 [HIGH] Manual review required

Finding: S3 Bucket Public Access Detected
Owner: cloud-owner@example.com
Resource: s3/my-bucket
Event: PutBucketPublicAccessBlock
Source: cloudtrail

Manual review required to determine if intentional or misconfiguration.
```

## ⚙️ **Configuration**

### Environment Variables

```bash
# Slack
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."

# Optional: Teams (alternative to Slack)
export TEAMS_WEBHOOK_URL="https://outlook.webhook.office.com/..."

# Default owner (when not specified in finding metadata)
export DEFAULT_SECURITY_OWNER="security-team@example.com"

# Notification behavior
export AUTO_NOTIFY_ON_HIGH_RISK=true
export AUTO_NOTIFY_SEVERITY_THRESHOLD="HIGH"  # CRITICAL, HIGH, MEDIUM
```

### Notification Levels

- 🔴 **CRITICAL** → Slack alert + JIRA ticket + SMS (nếu configured)
- 🟠 **HIGH** → Slack alert + JIRA ticket
- 🟡 **MEDIUM** → Slack alert (notification only)
- 🟢 **LOW** → Artifact saved (no notification)

## 📋 **Integration Flow**

### Manual Review Finding:
```
Finding Severity: HIGH
Recommendation: manual_review
    ↓
auto_notify detects this
    ↓
Builds Slack message:
- Finding title
- Owner
- Resource
- Severity
- Recommendation
    ↓
Sends to Slack webhook
    ↓
Team gets alerted in #security-alerts
```

### Auto-Remediate Finding:
```
Finding Severity: MEDIUM
Recommendation: auto_remediate
    ↓
EventBridge Listener runs remediation
    ↓
✅ After remediation succeeds:
   Send confirmation Slack message
```

## 🔌 **API Examples**

### Use in Custom Code

```python
from src.scanners.cloudtrail_scanner import CloudTrailScanner
from src.triage.engine import TriageEngine
from src.triage.auto_notify import AutoNotificationService

# Scan CloudTrail
scanner = CloudTrailScanner()
scan_result = scanner.execute()

# Triage findings
engine = TriageEngine()
findings = scan_result.findings
decisions = engine.triage(findings)

# Auto-notify
service = AutoNotificationService()
result = service.process_new_findings(
    findings=[f.dict() for f in findings],
    decisions=decisions,
    auto_dispatch=True
)

print(f"Sent {result['findings_count']} notifications")
```

### Use in Lambda

```python
from src.remediation.eventbridge_listener import EventBridgeCloudTrailListener

def lambda_handler(event, context):
    # Automatically processes CloudTrail event
    # and sends Slack notifications
    listener = EventBridgeCloudTrailListener()
    return listener.lambda_handler(event, context)
```

## 📝 **Slack Message Examples**

### Critical Finding Alert
```
🔴 CRITICAL Manual Review Required

Finding: AWS IAM Wildcard Permissions Detected
Owner: cloud-owner@example.com
Resource Type: iam_role
Resource ID: lambda-execution-role
Source: cloudtrail/checkov

Description: IAM role has overly permissive policy with wildcards (Action: *)

Action Required:
Review the policy and remove wildcards
Link: https://jira.example.com/SEC-123
```

### High Risk Finding
```
🟠 HIGH Manual Review Required

Finding: Security Group with Wide Open Ingress
Owner: platform-team@example.com
Resource Type: security_group
Resource ID: sg-0123456789abc
Source: cloudtrail

Event: AuthorizeSecurityGroupIngress
User: platform-admin@example.com
Time: 2024-05-28 10:15:00 UTC

Details: Rules allow 0.0.0.0/0 to port 22
```

## 🚨 **Alert Channels**

Notifications can be sent to:

1. **Slack** (primary) - Real-time alerts in #security-alerts
2. **Teams** - For organizations using Microsoft Teams
3. **JIRA** - Automatic ticket creation for HIGH/CRITICAL findings
4. **ServiceNow** - Integration with incident management
5. **Email** - Fallback for critical findings

## ✨ **Features**

- ✅ Auto-detects config changes via CloudTrail
- ✅ Sends Slack alerts immediately
- ✅ Deduplicates notifications (no spam)
- ✅ Includes finding context (owner, resource, severity)
- ✅ Continuous monitoring mode (watch)
- ✅ One-shot notification mode (CLI)
- ✅ Programmable API for custom integrations
- ✅ Multi-channel dispatch (Slack, Teams, JIRA, ServiceNow)

## 🔄 **Full Pipeline Example**

```bash
# 1. Setup AWS (one-time)
aws cloudtrail create-trail --name misconfig-trail --s3-bucket misconfig-logs
aws events put-rule --name cloudtrail-config-changes --event-pattern '...'

# 2. Deploy Lambda (one-time)
zip lambda.zip -r src/
aws lambda create-function --function-name cloudtrail-remediation \
    --handler src.remediation.eventbridge_listener.lambda_handler

# 3. Enable Slack webhook (one-time)
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."

# 4. Now: Any AWS config change triggers:
#    CloudTrail Event (user makes change)
#        ↓
#    EventBridge → Lambda (automatic)
#        ↓
#    Process: scan + triage + notify
#        ↓
#    Slack message in #security-alerts
```

## 📚 **Related Documents**

- [CLOUDTRAIL_INTEGRATION.md](CLOUDTRAIL_INTEGRATION.md) - Full CloudTrail setup
- [REMEDIATION.md](REMEDIATION.md) - Remediation flows
- [SIEM.md](SIEM.md) - Elasticsearch/Kibana dashboards
