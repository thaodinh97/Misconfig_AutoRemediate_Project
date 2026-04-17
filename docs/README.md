# Hybrid Cloud Lab Quickstart

Mục tiêu hiện tại: triển khai Cloud B (OpenStack) với 3 misconfiguration tối thiểu để chạy chung pipeline với AWS.

## 1) Prerequisites

- Ubuntu control plane đã cài `python-openstackclient`.
- Có file `openrc` từ OpenStack all-in-one.
- Đã đăng nhập OpenStack API thành công.

```bash
source ~/openrc
openstack token issue
```

## 2) Deploy 3 Misconfigurations on OpenStack (Cloud B)

Từ root repo:

```bash
chmod +x openstack/deploy_misconfig_openstack.sh
source ~/openrc
PROJECT_PREFIX=threat-demo DEMO_PASSWORD='ChangeMe123!' ./openstack/deploy_misconfig_openstack.sh
```

Script sẽ tạo:

- M1: Swift container public read (`.r:*,.rlistings`)
- M2: Security group mở `22/tcp`, `3389/tcp`, `all` từ `0.0.0.0/0`
- M3: User được gán role `admin` trên project demo

## 3) Verify

```bash
openstack container show threat-demo-m1-public-container -f yaml
openstack security group rule list threat-demo-m2-wide-open-sg
openstack role assignment list --project threat-demo-m3-overpriv-project --user threat-demo-m3-overpriv-user --names
```

## 4) Cleanup

```bash
chmod +x openstack/cleanup_misconfig_openstack.sh
source ~/openrc
PROJECT_PREFIX=threat-demo ./openstack/cleanup_misconfig_openstack.sh
```

## 5) Notes

- Chỉ chạy trong lab, không chạy trên môi trường production.
- Nếu bạn đổi tên tài nguyên, set lại env vars: `PUBLIC_CONTAINER`, `WIDE_OPEN_SG`, `DEMO_PROJECT`, `DEMO_USER`, `DEMO_ROLE`.
