# Testing Guide

Repo này đã có test suite tối thiểu cho các phần bị trừ điểm trong rubric:

- `tfsec` normalization
- `Trivy` misconfiguration + secret normalization
- triage owner/ticket notification artifacts
- container secret CI guard

## 1) Cài test dependencies

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/pip install -r requirements-dev.txt
```

## 2) Chạy unit tests

```bash
./.venv/bin/python -m pytest tests
```

## 3) Scope hiện tại

- `tests/test_tfsec_scanner.py`
- `tests/test_trivy_scanner.py`
- `tests/test_notifications.py`
- `tests/test_scan_container_secrets.py`

## 4) CI coverage

Hai workflow chính đều chạy `pytest` trước scanner/remediation:

- `.github/workflows/scan_and_remediate.yml`
- `.github/workflows/iac_scan.yml`

Điều này giúp fail sớm nếu:

- schema normalize của scanner mới bị lệch
- triage notification artifacts đổi format
- rule block container secret bị regression
