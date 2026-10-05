# Meridian App Sec Hardening — Prevention + Detection + Automated Response

A self-directed security engineering project built around a realistic healthcare-breach scenario: a six-week AWS compromise caused by a secret committed to Git and a stale IAM account nobody disabled. The project builds the two layers that would have stopped it — a CI pipeline that blocks insecure code before it ships, and an AWS detection-and-response system that disables a compromised identity in seconds instead of weeks.

![Status](https://img.shields.io/badge/status-complete-brightgreen) ![Platform](https://img.shields.io/badge/platform-AWS-orange) ![Pipeline](https://img.shields.io/badge/CI-TruffleHog%20%7C%20Bandit%20%7C%20pip--audit-blue)

---

## The Scenario

A Python FastAPI healthcare application on AWS gets breached. The attacker doesn't break in — they find AWS credentials that a developer committed to Git six months earlier and never rotated. From there, they use a former contractor's IAM account, which was never deactivated, to run reconnaissance (`ListBuckets`, `DescribeInstances`, `ListUsers`) for three weeks, then access patient records for two more. Nobody notices. An external party reports the breach six weeks after it started.

Two separate failures made this possible:

- **Application security failure** — no secrets scanning, no dependency scanning, no static analysis in the pipeline. The leaked credential sat in Git history, visible to anyone with repo access, for six months.
- **Cloud security failure** — no threat detection, no automated response, no centralized security posture view. Six weeks of CloudTrail evidence sat unmonitored.

This project builds the fix for both.

> 📸 **Screenshot spot — breach narrative diagram:** optional, but a simple timeline graphic (credential committed → contractor leaves → account never disabled → recon → data access → external discovery) is a strong visual anchor at the top of the repo.

---

## Part 1 — Application Security: Shifting Left

Three free, open-source tools run in GitHub Actions on every push and pull request. All three must pass before code can merge.

| Tool | Catches | Blocks on |
|---|---|---|
| **TruffleHog** | Secrets committed to Git — the exact failure mode in the breach scenario | Any detected secret |
| **Bandit** | Insecure Python patterns — hardcoded credentials, unsafe deserialization, SQL injection patterns | High-severity findings |
| **pip-audit** | Known CVEs in `requirements.txt` dependencies | Critical CVEs |

**Pipeline flow:** secret scan → SAST → dependency scan → deploy (only if all three pass).

> 📸 **Screenshot — pipeline blocking a secret:** commit a fake AWS key pattern (`AKIA` + 16 dummy characters, never a real key) and show the TruffleHog job failing red in the Actions tab.
>
> 📸 **Screenshot — Bandit findings report:** show at least one real finding, plus the same finding after it's fixed, to show before/after.
>
> 📸 **Screenshot — pip-audit catching a CVE:** temporarily pin a known-vulnerable package version in `requirements.txt`, show it flagged, then show the clean scan after reverting.
>
> 📸 **Screenshot — full green pipeline run:** all three jobs passing on a normal commit.

---

## Part 2 — Cloud Security: Detect and Respond

Even with a clean pipeline, credentials can leak through other channels and misconfigurations happen. This layer catches what application security misses.

**Architecture:**

```
GuardDuty (threat detection on CloudTrail/VPC/DNS logs)
        ↓ high-severity finding
EventBridge (rule matches severity ≥ 7)
        ↓
Lambda (disables the compromised IAM user's access keys,
         attaches a DenyAll policy)
        ↓
SNS (emails the security team)
```

Security Hub sits alongside this as a single dashboard, aggregating findings and running CIS AWS Foundations Benchmark compliance checks.

| Component | What it does |
|---|---|
| **GuardDuty** | Managed threat detection — no rules to write, flags anomalous API activity automatically |
| **Security Hub** | Central dashboard, CIS Benchmark compliance scoring |
| **EventBridge** | Routes high-severity findings to the response Lambda |
| **Lambda** | Deactivates the compromised user's access keys and attaches a DenyAll inline policy |
| **SNS** | Emails the security team the moment the account is disabled |
| **IAM Access Analyzer** | Continuously reviews external access to account resources |
| **IAM password policy** | 14+ char minimum, mixed case/number/symbol, 90-day expiry, 24-password reuse prevention |

> 📸 **Screenshot — Security Hub dashboard:** CIS Benchmark score, before and after remediating failing controls.
>
> 📸 **Screenshot — GuardDuty console:** showing the detector enabled and active in the target region.
>
> 📸 **Screenshot — EventBridge rule:** the production rule (`*-high-severity-response` or equivalent), showing it's enabled, its event pattern (severity ≥ 7 GuardDuty findings), and its Lambda target.
>
> 📸 **Screenshot — Lambda function overview:** showing the function, its trigger, and its execution role permissions (scoped narrowly — not admin).
>
> 📸 **Screenshot — CloudWatch log of a successful run:** showing the Lambda receiving a finding, identifying the user, deactivating the key, and attaching the deny policy, start to finish, with a timestamp delta under a few seconds.
>
> 📸 **Screenshot — SNS email:** the actual alert received, showing user, finding type, severity, and the action taken. (Redact your personal email address before screenshotting.)
>
> 📸 **Screenshot — IAM before/after:** the compromised test user's access key shown Active beforehand, then Inactive with the DenyAll policy attached afterward.
>
> 📸 **Screenshot — IAM Access Analyzer findings:** even a "0 findings, no external access" screenshot is useful evidence the control is active.

---

## A Note on the Detection Trigger

GuardDuty's reconnaissance-detection finding types (like `Recon:IAMUser/UserPermissions`) are anomaly-based — they compare new activity against a learned baseline of normal behavior for that identity. A brand-new lab account has no baseline, so this finding type will not reliably fire from a short burst of manual API calls, even when those calls are the exact pattern the finding is designed to catch.

To validate the response chain without waiting on an unpredictable detection window, I built a second EventBridge rule with a custom event source and fed it a hand-built, schema-accurate GuardDuty finding payload via `aws events put-events`. This exercises the identical downstream path — EventBridge → Lambda → SNS — that a genuine GuardDuty finding would trigger; only the origin of the event differs. The production GuardDuty detection rule is unaffected and runs independently.

This is a standard way to test event-driven automation without depending on an external system producing output on demand, and it's disclosed here rather than left implied.

---

## Tech Stack

- **Cloud:** AWS (GuardDuty, Security Hub, EventBridge, Lambda, SNS, IAM Access Analyzer, CloudTrail)
- **Application:** Python, FastAPI
- **CI/CD:** GitHub Actions
- **Security tools:** TruffleHog, Bandit, pip-audit

## What This Demonstrates

- Implementing shift-left application security in a CI pipeline with real, enforced merge gates
- Designing a detection-to-automated-response chain for compromised cloud credentials
- Reading and improving a CIS Benchmark compliance score with named, specific fixes
- Testing event-driven security automation independently of an upstream detection system, and disclosing that test boundary clearly
- Mapping every technical control back to a specific, named root cause from a real-style incident

---

## Repo Structure

```
├── README.md
├── app/                        # FastAPI application
│   └── requirements.txt
├── .github/workflows/
│   └── security-pipeline.yml   # TruffleHog → Bandit → pip-audit
├── lambda/
│   └── disable_compromised_user.py
├── docs/
│   └── incident-response-runbook.md
└── screenshots/
    ├── pipeline-blocked-secret.png
    ├── bandit-findings.png
    ├── pip-audit-cve.png
    ├── pipeline-passing.png
    ├── security-hub-score.png
    ├── guardduty-enabled.png
    ├── eventbridge-rule.png
    ├── lambda-overview.png
    ├── cloudwatch-log.png
    ├── sns-alert-email.png
    ├── iam-before-after.png
    └── access-analyzer-findings.png
```

Drop screenshots into `screenshots/` with the names above and they'll render automatically wherever this README references them on GitHub.
