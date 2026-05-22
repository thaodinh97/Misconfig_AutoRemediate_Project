from src.models import NormalizedFinding
from src.triage.notifications import build_notifications


def test_build_notifications_creates_owner_alerts_and_high_risk_tickets(monkeypatch):
    monkeypatch.setenv("DEFAULT_SECURITY_OWNER", "sec-owner@example.com")

    findings = [
        NormalizedFinding(
            finding_id="f-1",
            finding_code="CKV_AWS_20",
            scanner="checkov",
            provider="aws",
            severity="CRITICAL",
            title="Critical bucket finding",
            description="Critical issue",
            resource_type="terraform_resource",
            resource_id="aws_s3_bucket.demo",
            metadata={"asset_owner": "cloud-owner@example.com"},
        ),
        NormalizedFinding(
            finding_id="f-2",
            finding_code="CKV_AWS_8",
            scanner="checkov",
            provider="aws",
            severity="LOW",
            title="Low severity finding",
            description="Low issue",
            resource_type="terraform_resource",
            resource_id="aws_security_group.demo",
        ),
    ]
    decisions = [
        {"finding_id": "f-1", "recommendation": "manual_review", "reasoning": "high risk"},
        {"finding_id": "f-2", "recommendation": "manual_review", "reasoning": "needs owner ack"},
        {"finding_id": "f-3", "recommendation": "auto_remediate", "reasoning": "ignored here"},
    ]

    bundle = build_notifications(findings, decisions)

    assert len(bundle["owner_notifications"]) == 2
    assert bundle["owner_notifications"][0]["owner"] == "cloud-owner@example.com"
    assert len(bundle["jira_tickets"]) == 1
    assert len(bundle["servicenow_incidents"]) == 1
    assert len(bundle["chat_notifications"]) == 1
    assert bundle["jira_tickets"][0]["priority"] == "Highest"
    assert bundle["servicenow_incidents"][0]["caller_id"] == "cloud-owner@example.com"
