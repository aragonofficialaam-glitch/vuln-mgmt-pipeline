# AWS Intentional Misconfiguration Scan

| Field | Value |
|---|---|
| Scan date (UTC) | 2026-10-06 |
| Tool | Prowler 5.44.0, isolated virtual environment in AWS CloudShell |
| Scope | Lab member account `<MEMBER_ACCOUNT_ID>`, region `us-east-2` + global services |
| Flags | `--scan-unused-services` (includes resources not attached to workloads) |
| Result | 71 FAIL (previous baseline: 43 FAIL, without `--scan-unused-services`) |

## Intentional misconfigurations introduced

All resources are tagged `Project=vuln-mgmt-pipeline` and `Purpose=intentional-misconfig`.

| # | Misconfiguration | How it was made safe | Outcome |
|---|---|---|---|
| 1 | Security group allowing SSH (TCP 22) from `0.0.0.0/0` | Not attached to any instance | **Detected** |
| 2 | IAM user with console password and no MFA | — | **Blocked by SCP** (explicit deny on `iam:CreateLoginProfile`) |
| 3 | IAM user with two active access keys | User has no attached, inline or group policies; secret keys were discarded and never displayed | **Detected** |

## Findings caused by the misconfigurations

| Severity | Check | Resource |
|---|---|---|
| High | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22` | Lab security group |
| Low | `ec2_securitygroup_not_used` | Lab security group |
| High | `iam_user_hardware_mfa_enabled` | `vulnlab-no-mfa-user` |
| Medium | `iam_user_two_active_access_key` | `vulnlab-no-mfa-user` |

**Detection rate: 2 of 2 creatable misconfigurations detected (4 findings).**

### Expected findings that did not appear
- **Console user without MFA:** not applicable; the SCP prevented the console password from being created.
- **Unused access keys:** Prowler only flags keys after a configurable inactivity period (default 45 days), so newly created keys do not qualify yet.

## Preventive control observed

Creating a console password for an IAM user failed with an **explicit deny from an organization-level Service Control Policy**, even though the caller holds `AdministratorAccess`. In AWS policy evaluation an explicit deny always wins, so this misconfiguration cannot exist in the account regardless of IAM permissions.

## Methodology lesson: scope consistency

FAIL count increased from 43 to 71, but only **4 findings** were caused by the introduced misconfigurations. About **24** came from enabling `--scan-unused-services`, which brought pre-existing AWS default resources into scope (default VPC, subnets, network ACL, default security group, account-level EBS/S3/IMDS settings).

**Comparing scans with different scanner configurations produces misleading trends.** From this point on, every Prowler scan uses `--scan-unused-services`, and this scan is the official baseline for measuring remediation.

## No-cost remediation candidates (Week 3)
- Account-level S3 Block Public Access
- EBS encryption by default (AWS-managed key)
- IMDSv2 required by default for new instances
- EBS snapshot block public access
- Delete the intentional security group and access keys