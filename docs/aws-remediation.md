# AWS Remediation — Cloud Misconfigurations

## Objective
Remediate the highest-priority cloud misconfigurations found by Prowler
(baseline: 71 FAIL) and verify each fix directly via the AWS API.

## Remediations applied

| # | Finding | Action | Verification |
|---|---------|--------|--------------|
| 1 | Security group with SSH (22) open to 0.0.0.0/0 | Deleted the security group | `describe-security-groups` returns `InvalidGroup.NotFound` |
| 2 | IAM user without MFA holding active access keys | Deleted both access keys | `list-access-keys` returns empty |
| 3 | No account-level S3 public access block | Enabled all 4 block settings | `get-public-access-block` → all `true` |
| 4 | EBS volumes not encrypted by default | Enabled default EBS encryption | `get-ebs-encryption-by-default` → `true` |
| 5 | IMDSv1 allowed (SSRF credential theft risk) | Enforced IMDSv2 by default | `get-instance-metadata-defaults` → `HttpTokens: required` |

## Commands used

```bash
# 1. Delete open security group
aws ec2 delete-security-group --group-id <sg-id> --region us-east-2

# 2. Delete access keys of non-MFA user
aws iam delete-access-key --user-name <user> --access-key-id <key-id>

# 3. Enable account-level S3 Block Public Access
aws s3control put-public-access-block --account-id <account> \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# 4. Enable default EBS encryption
aws ec2 enable-ebs-encryption-by-default --region us-east-2

# 5. Enforce IMDSv2 by default
aws ec2 modify-instance-metadata-defaults --http-tokens required --region us-east-2
```

## Result
All 5 high-priority misconfigurations remediated and verified. These are
standard CIS Benchmark controls and represent the first fixes a cloud
security engineer applies to harden an AWS account.

## Note
A full Prowler rescan was not re-run in CloudShell due to its ~1 GB storage
limit (Prowler's dependencies exceed it). Instead, each remediation was
verified directly against the AWS API, which confirms the exact fixes applied.