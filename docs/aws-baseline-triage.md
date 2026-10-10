# AWS Baseline Scan — Triage & Risk Decisions

| Field | Value |
|---|---|
| Scan date (UTC) | 2026-10-06 |
| Tool | Prowler 5.44.0 (executed from AWS CloudShell, temporary session credentials) |
| Scope | Lab member account `<MEMBER_ACCOUNT_ID>`, region `us-east-2` + global services |
| Checks executed | 655 (77 applicable to existing resources) |
| Result | 34 PASS / 43 FAIL — 1 Critical, 4 High, 30 Medium, 8 Low |

## Context

This is a **newly created AWS account with no workloads deployed**. The goal of this
baseline is to measure the default security posture *before* any intentional
misconfiguration is introduced, so later scans can be compared against it.

Key observation: **a new AWS account is not secure by default.** Most failures are
missing *detective* controls (audit logging, configuration history, CIS alarms),
not exploitable weaknesses.

### Account structure discovered during triage
- The account is a **member of an AWS Organization**; the management account is owned by the project author.
- Console and CloudShell access uses the role `AccountFullAccessRole`, assumed by the
  AWS service principal `account-access.amazonaws.com`, with **temporary credentials** and passkey MFA.
- No long-lived access keys exist. No IAM users exist.

## Critical & High findings — decisions

| Severity | Check | Affected resource | Decision | Justification |
|---|---|---|---|---|
| Critical | `iam_aws_attached_policy_no_administrative_privileges` | `AdministratorAccess` attached to `AccountFullAccessRole` | **Risk accepted** | Single administrator; phishing-resistant MFA (passkey); temporary credentials only; role is AWS-managed and is the only access path to the account. |
| High | `iam_role_cross_service_confused_deputy_prevention` | `role/managed/AccountFullAccessRole` | **Risk accepted (vendor-managed)** | Trust policy only allows an AWS service principal. Role lives under the `/managed/` path and is maintained by AWS; modifying it risks losing account access. |
| High | `cloudtrail_multi_region_enabled` | Account-level | **Risk accepted** | Lab account with no workloads; trail storage has recurring cost. Compensating control: CloudTrail Event history (90 days, enabled by default, no cost). |
| High | `config_delegated_admin_and_org_aggregator_all_regions` | Organization-level | **Risk accepted** | AWS Config incurs per-item recording cost; no production resources to track. |
| High | `iam_root_credentials_management_enabled` | Organization-level | **Remediation candidate** | No-cost control available from the management account. To be evaluated. |

## Root-cause grouping (Medium)

15 of the 30 Medium findings are missing CIS CloudWatch metric-filter alarms
(e.g. root login, IAM policy changes). They share **one root cause**: no CloudTrail
trail delivering logs to CloudWatch. Counting them as 15 independent issues would
overstate the remediation effort; they are tracked as a single risk tied to the
CloudTrail decision above.

## Lesson learned

The only Critical finding was the administrator role used to operate the account.
Tool severity alone would have ranked it as the top priority, but with context
(single admin, MFA, temporary credentials, no data) the real risk is low.
**This is the core argument for risk-based prioritization** implemented later in this project.

## Production considerations
- Run Prowler under a dedicated **read-only role** (`SecurityAudit` + `ViewOnlyAccess`) instead of an administrator role.
- Enable an organization-wide CloudTrail trail and AWS Config aggregator.
- Use **Service Control Policies** to restrict usage to approved regions.
- Install scanning tools in an isolated virtual environment to avoid dependency conflicts with pre-installed tooling.