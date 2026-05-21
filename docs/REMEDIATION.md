# Remediation Flows

Tài liệu này chốt 4 phần còn lại của capstone sau khi scan, triage, và 3 dashboard Kibana đã hoàn thành:

1. export dashboard artifacts
2. runtime remediation flow
3. IaC fix / PR-prep flow
4. remediation metrics + audit publish vào Elasticsearch

## 1) Export dashboard artifacts

```bash
cd /home/deployer/Desktop/Misconfig_AutoRemediate_Project
./.venv/bin/python scripts/export_kibana_dashboards.py
```

Artifacts:

- `artifacts/kibana/misconfig_dashboards.ndjson`
- `artifacts/kibana/dashboard_manifest.json`

## 2) Runtime remediation flow

Executor:

```bash
./.venv/bin/python -m src.remediation.runtime_executor \
  --findings ./scan_results/openstack_findings.json \
  --decisions ./triage_results/openstack_decisions.json \
  --approve-all-manual \
  --simulate-success \
  --pipeline-source openstack-runtime-demo \
  --branch feat/normalize \
  --commit-sha "$(git rev-parse --short HEAD)"
```

Artifacts:

- `artifacts/remediation/runtime_events.json`
- `artifacts/remediation/findings_after_runtime.json`

Ghi chú:

- `--simulate-success` dùng cho demo/audit trail mà không thay đổi cloud thật.
- Để chạy thật trên OpenStack lab, bỏ `--simulate-success` và thêm `--execute`.
- Flow hiện hỗ trợ:
  - `OPENSTACK_SWIFT_PUBLIC_READ`
  - `OPENSTACK_SG_WIDE_OPEN`
  - `OPENSTACK_PROJECT_ADMIN_ASSIGNMENT`

## 3) IaC fix / PR-prep flow

Generator:

```bash
./.venv/bin/python -m src.remediation.iac_pr_prepare \
  --findings ./scan_results/findings.json \
  --decisions ./triage_results/decisions.json \
  --terraform-dir ./iac/terraform \
  --output-dir ./artifacts/iac_pr \
  --run-label checkov_pr_bundle \
  --pipeline-source iac-pr-demo \
  --branch feat/normalize \
  --commit-sha "$(git rev-parse --short HEAD)"
```

Artifacts:

- `artifacts/iac_pr/checkov_pr_bundle/terraform_fix.patch`
- `artifacts/iac_pr/checkov_pr_bundle/PR_BODY.md`
- `artifacts/iac_pr/checkov_pr_bundle/summary.json`
- `artifacts/iac_pr/checkov_pr_bundle/iac_pr_events.json`
- `artifacts/iac_pr/checkov_pr_bundle/fixed_tree/`

Flow này hiện auto-generate patch cho:

- `m1_public_s3.tf`
- `m2_wide_open_sg.tf`
- `m4_unencrypted_storage.tf`

Unsupported findings vẫn được liệt kê ở:

- `artifacts/iac_pr/checkov_pr_bundle/unsupported_findings.json`

## 4) Metrics và audit publish vào Elasticsearch

Gộp snapshot hybrid:

```bash
./.venv/bin/python scripts/merge_json_collections.py \
  --inputs ./scan_results/findings.json ./scan_results/openstack_findings.json \
  --output ./artifacts/remediation/findings_hybrid.json

./.venv/bin/python scripts/merge_json_collections.py \
  --inputs ./triage_results/decisions.json ./triage_results/openstack_decisions.json \
  --collection-key decisions \
  --output ./artifacts/remediation/decisions_hybrid.json
```

Build KPI snapshot:

```bash
./.venv/bin/python -m src.remediation.metrics \
  --findings ./artifacts/remediation/findings_hybrid.json \
  --decisions ./artifacts/remediation/decisions_hybrid.json \
  --remediation-events ./artifacts/remediation/runtime_events.json \
  --remediation-events ./artifacts/iac_pr/checkov_pr_bundle/iac_pr_events.json \
  --pipeline-source capstone-demo \
  --branch feat/normalize \
  --commit-sha "$(git rev-parse --short HEAD)" \
  --output ./artifacts/remediation/remediation_metrics.json
```

Publish remediation events và metrics:

```bash
./.venv/bin/python -m src.siem.publisher \
  --remediation-events ./artifacts/remediation/runtime_events.json \
  --remediation-events ./artifacts/iac_pr/checkov_pr_bundle/iac_pr_events.json \
  --metrics ./artifacts/remediation/remediation_metrics.json \
  --pipeline-source capstone-demo \
  --branch feat/normalize \
  --commit-sha "$(git rev-parse --short HEAD)"
```

Indices:

- `misconfig-remediation-*`
- `misconfig-metrics-*`

## Expected deliverables

Khi nộp bài, phần remediation/reporting giờ có thể lấy trực tiếp từ các thư mục sau:

- `artifacts/kibana/`
- `artifacts/remediation/`
- `artifacts/iac_pr/`

## Honest limitations

- `MTTR` hiện phản ánh timestamp demo giữa `detected_at` và thời điểm chạy remediation, chưa phải production MTTR.
- `Compliance score` hiện là proxy qua `cis_findings_before/after`, chưa phải benchmark score đầy đủ.
- IaC flow hiện là `PR-prep artifact`, chưa tự push branch hay mở PR trên GitHub API.
