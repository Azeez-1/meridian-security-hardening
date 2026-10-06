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

---

## Part 1 — Application Security: Shifting Left

Three free, open-source tools run in GitHub Actions on every push and pull request to `main`.

| Tool | Catches | Blocks on |
|---|---|---|
| **TruffleHog** | Secrets committed to Git — the exact failure mode in the breach scenario | Any detected secret |
| **Bandit** | Insecure Python patterns — hardcoded credentials, unsafe deserialization, SQL injection patterns | HIGH-severity findings (MEDIUM findings print as a non-blocking report) |
| **pip-audit** | Known vulnerabilities in `requirements.txt` dependencies | Any known vulnerability |

**Pipeline flow:** secret scan → SAST → dependency scan. The jobs run in order, so a failure skips the jobs after it.

**Merge gate:** the `protect-main` repository ruleset requires all three checks to pass and blocks direct pushes to `main`. Code reaches `main` only through a pull request that passes the pipeline.

The nine application and pipeline fixes made during the hardening are logged in [REMEDIATION.md](REMEDIATION.md).

### Secret detection

A pull request that contains a fake AWS key pair fails the TruffleHog job. Bandit and pip-audit skip, and the merge button is disabled.

![Pull request blocked by TruffleHog](screenshots/pipeline-blocked-secret.png)

*The test pull request. TruffleHog fails, the later jobs skip, and the required checks block the merge.*

![TruffleHog job log](screenshots/pipeline-blocked-secret-log.png)

*The TruffleHog job log for the same run.*

GitHub push protection adds a second layer in front of the pipeline. It blocked the push itself before CI ran.

![GitHub push protection blocking a push](screenshots/push-protection-blocked.png)

*GitHub push protection rejecting the push that contained the test secrets.*

### Static analysis (Bandit)

![Bandit findings before the fix](screenshots/bandit-findings-before.png)

*Before: Bandit scans the vulnerable baseline and reports findings in the legacy admin check, including a hardcoded token.*

![Bandit findings after the fix](screenshots/bandit-findings-after.png)

*After: the same scan on the remediated code.*

### Dependency scanning

![pip-audit flagging a vulnerable package](screenshots/pip-audit-cve.png)

*A deliberately vulnerable pin (`python-multipart==0.0.6`) fails the pip-audit job with eight known vulnerabilities. The current pin, `0.0.32`, sits above every listed fix version.*

### Full pipeline and merge gate

![All three jobs passing](screenshots/pipeline-passing.png)

*All three jobs passing on a normal commit.*

![protect-main ruleset](screenshots/branch-ruleset.png)

*The `protect-main` ruleset that requires the three checks.*

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
| **Lambda** | Deactivates the compromised user's access keys and attaches a `SecurityIncidentDenyAll` inline policy |
| **SNS** | Emails the security team the moment the account is disabled |
| **IAM Access Analyzer** | Continuously reviews external access to account resources |
| **IAM password policy** | 14+ char minimum, mixed case/number/symbol, 90-day expiry, 24-password reuse prevention |

### Detection and posture

![GuardDuty enabled](screenshots/guardduty-enabled.png)

*GuardDuty enabled and active in `eu-west-2`.*

![Security Hub CIS score](screenshots/security-hub-score.png)

*Security Hub CIS AWS Foundations Benchmark results after remediation. The named fixes: a multi-region CloudTrail trail and the full IAM password policy control set. IAM.6 (hardware MFA for root) still fails by design, because the account uses virtual MFA.*

![IAM Access Analyzer](screenshots/access-analyzer-findings.png)

*IAM Access Analyzer active with no external-access findings.*

### Response chain

![EventBridge rule, view 1](screenshots/eventbridge-rule1.png)

![EventBridge rule, view 2](screenshots/eventbridge-rule2.png)

*The production rule: enabled, matching GuardDuty findings with severity ≥ 7, and targeting the response Lambda.*

![Lambda function overview](screenshots/lambda-overview.png)

![Lambda execution role permissions](screenshots/lambda-permissions.png)

*The response Lambda and its narrowly scoped execution role. It can list and deactivate access keys, attach an inline policy, and publish to one SNS topic. It is not an admin role.*

### End-to-end test

The test user starts with active access keys and no deny policy:

![Test user access keys before the response](screenshots/iam-before.png)

![Test user permissions before the response](screenshots/iam-permissions-before.png)

A schema-accurate finding goes into EventBridge (see [the note below](#a-note-on-the-detection-trigger)):

![Demo trigger sent to EventBridge](screenshots/demo-trigger.png)

The Lambda receives the event, identifies the user, deactivates the keys, and attaches the deny policy. The run finishes in under two seconds:

![CloudWatch log of the Lambda run](screenshots/cloudwatch-log.png)

The security team receives the alert:

![SNS alert email](screenshots/sns-alert-email.png)

The test user ends with inactive keys and the `SecurityIncidentDenyAll` policy attached:

![Test user access keys after the response](screenshots/iam-after.png)

![Test user permissions after the response](screenshots/iam-permissions-after.png)

---

## A Note on the Detection Trigger

GuardDuty's reconnaissance-detection finding types (like `Recon:IAMUser/UserPermissions`) are anomaly-based — they compare new activity against a learned baseline of normal behavior for that identity. A brand-new lab account has no baseline, so this finding type will not reliably fire from a short burst of manual API calls, even when those calls are the exact pattern the finding is designed to catch.

To validate the response chain without waiting on an unpredictable detection window, I built a second EventBridge rule with a custom event source and fed it a hand-built, schema-accurate GuardDuty finding payload via `aws events put-events`. This exercises the identical downstream path — EventBridge → Lambda → SNS — that a genuine GuardDuty finding would trigger; only the origin of the event differs. The production GuardDuty detection rule is unaffected and runs independently.

This is a standard way to test event-driven automation without depending on an external system producing output on demand, and it's disclosed here rather than left implied.

---

## Limitations and Next Steps

- **IAM users only.** If a finding names an IAM role session, the Lambda fails with `NoSuchEntity` and cannot contain it. Next step: revoke the role's active sessions.
- **One failure stops the key loop.** A single `try` block wraps the access-key loop, so one failed deactivation skips the remaining keys. Next step: handle each key separately.
- **No break-glass exclusion.** The role's IAM permissions cover every IAM user. Next step: skip users tagged `break-glass` so a false positive cannot lock out the last administrator.
- **Broad rule.** The production rule matches every GuardDuty finding with severity ≥ 7. Findings with no IAM username make the Lambda send an alert and change nothing.
- **Demo rule risk.** Anyone with `events:PutEvents` on the default event bus can forge a finding for the demo rule. Delete the demo rule after testing. EventBridge reserves the `aws.` source prefix, so nobody can forge an event for the production rule.

The [incident response runbook](docs/incident-response-runbook.md) covers one scenario for each half of the project.

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
├── REMEDIATION.md
├── app/                        # FastAPI application
│   ├── main.py
│   └── requirements.txt
├── test/
│   └── test_main.py
├── .github/workflows/
│   └── security-pipeline.yml   # TruffleHog → Bandit → pip-audit
├── lambda/
│   └── disable_compromised_user.py
├── eventbridge/
│   ├── guardduty-high-severity-pattern.json
│   └── demo-trigger-pattern.json
├── iam-policies/
│   └── lambda-execution-role-policy.json
├── docs/
│   └── incident-response-runbook.md
└── screenshots/
```
