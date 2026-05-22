# Automated Terraform Remediation Proposal

- Suggested branch: `autofix/20260521-164804`
- Files changed: `4`
- Supported findings addressed: `17`
- Findings still manual: `70`

## Included fixes

- `CKV_AWS_54` on `aws_s3_bucket_public_access_block.m1_public_access` from `/m1_public_s3.tf`
- `CKV_AWS_55` on `aws_s3_bucket_public_access_block.m1_public_access` from `/m1_public_s3.tf`
- `CKV_AWS_53` on `aws_s3_bucket_public_access_block.m1_public_access` from `/m1_public_s3.tf`
- `CKV_AWS_56` on `aws_s3_bucket_public_access_block.m1_public_access` from `/m1_public_s3.tf`
- `CKV_AWS_54` on `aws_s3_bucket_public_access_block.m1_policy_public_access` from `/m1_public_s3.tf`
- `CKV_AWS_55` on `aws_s3_bucket_public_access_block.m1_policy_public_access` from `/m1_public_s3.tf`
- `CKV_AWS_53` on `aws_s3_bucket_public_access_block.m1_policy_public_access` from `/m1_public_s3.tf`
- `CKV_AWS_56` on `aws_s3_bucket_public_access_block.m1_policy_public_access` from `/m1_public_s3.tf`
- `CKV_AWS_70` on `aws_s3_bucket_policy.m1_public_policy` from `/m1_public_s3.tf`
- `CKV_AWS_20` on `aws_s3_bucket.m1_public_bucket` from `/m1_public_s3.tf`
- `CKV2_AWS_65` on `aws_s3_bucket_ownership_controls.m1_ownership` from `/m1_public_s3.tf`
- `CKV_AWS_277` on `aws_security_group.m2_wide_open_sg` from `/m2_wide_open_sg.tf`
- `CKV_AWS_25` on `aws_security_group.m2_wide_open_sg` from `/m2_wide_open_sg.tf`
- `CKV_AWS_24` on `aws_security_group.m2_wide_open_sg` from `/m2_wide_open_sg.tf`
- `CKV_AWS_260` on `aws_security_group.m2_wide_open_sg` from `/m2_wide_open_sg.tf`
- `CKV_AWS_3` on `aws_ebs_volume.m4_unencrypted_volume` from `/m4_unencrypted_storage.tf`
- `CKV_AWS_16` on `aws_db_instance.m4_unencrypted_rds` from `/m4_unencrypted_storage.tf`

## Remaining manual follow-up

- `CKV_AWS_144` on `aws_s3_bucket.m1_public_bucket` (`/m1_public_s3.tf`)
- `CKV_AWS_144` on `aws_s3_bucket.m1_policy_public_bucket` (`/m1_public_s3.tf`)
- `CKV2_AWS_62` on `aws_s3_bucket.m1_public_bucket` (`/m1_public_s3.tf`)
- `CKV2_AWS_62` on `aws_s3_bucket.m1_policy_public_bucket` (`/m1_public_s3.tf`)
- `CKV2_AWS_61` on `aws_s3_bucket.m1_public_bucket` (`/m1_public_s3.tf`)
- `CKV2_AWS_61` on `aws_s3_bucket.m1_policy_public_bucket` (`/m1_public_s3.tf`)
- `CKV_AWS_21` on `aws_s3_bucket.m1_public_bucket` (`/m1_public_s3.tf`)
- `CKV_AWS_21` on `aws_s3_bucket.m1_policy_public_bucket` (`/m1_public_s3.tf`)
- `CKV_AWS_145` on `aws_s3_bucket.m1_public_bucket` (`/m1_public_s3.tf`)
- `CKV_AWS_145` on `aws_s3_bucket.m1_policy_public_bucket` (`/m1_public_s3.tf`)
- `CKV_AWS_18` on `aws_s3_bucket.m1_public_bucket` (`/m1_public_s3.tf`)
- `CKV_AWS_18` on `aws_s3_bucket.m1_policy_public_bucket` (`/m1_public_s3.tf`)
- `CKV2_AWS_6` on `aws_s3_bucket.m1_public_bucket` (`/m1_public_s3.tf`)
- `CKV2_AWS_6` on `aws_s3_bucket.m1_policy_public_bucket` (`/m1_public_s3.tf`)
- `CKV_AWS_130` on `aws_subnet.m2_public_subnet` (`/m2_wide_open_sg.tf`)
- `CKV_AWS_382` on `aws_security_group.m2_wide_open_sg` (`/m2_wide_open_sg.tf`)
- `CKV_AWS_23` on `aws_security_group.m2_wide_open_sg` (`/m2_wide_open_sg.tf`)
- `CKV_AWS_126` on `aws_instance.m2_exposed_instance` (`/m2_wide_open_sg.tf`)
- `CKV_AWS_79` on `aws_instance.m2_exposed_instance` (`/m2_wide_open_sg.tf`)
- `CKV_AWS_8` on `aws_instance.m2_exposed_instance` (`/m2_wide_open_sg.tf`)

## Validation

- Review generated patch and run `terraform fmt -recursive`.
- Run `terraform validate` in `iac/terraform`.
- Re-run Checkov before merging.
