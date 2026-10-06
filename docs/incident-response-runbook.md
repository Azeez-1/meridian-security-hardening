# Incident Response Runbook — Meridian Security Hardening

Two scenarios, matching the two halves of this project. Each one covers: what triggers it, what to check first, how to resolve it, and how to confirm it's actually resolved.

---

## Scenario 1 — Application Security: A Pipeline Security Gate Blocks a Deployment

### Trigger

A GitHub Actions run on `.github/workflows/security-pipeline.yml` fails at one of three jobs: `secret-scanning` (TruffleHog), `sast-scanning` (Bandit), or `dependency-scanning` (pip-audit). The pull request shows a red X and cannot merge.

### Step 1 — Identify which job failed and why

1. Open the failed workflow run in the Actions tab.
2. Open the specific failing job (not just the overall run).
3. Read the job's log output in full — each tool's failure message names the exact file, line, or package involved.

### Step 2 — Resolve by job type

**If TruffleHog failed (secret detected):**

1. Identify the exact commit and file the secret was introduced in, from the TruffleHog output.
2. Treat the secret as compromised the moment it touched Git history, even if the commit is later deleted — Git history is permanent and was already pushed.
3. Rotate the credential at its source (AWS IAM, third-party API provider, etc.) before doing anything else. Do not just remove it from the file.
4. Remove the secret from the current code and replace it with an environment variable or secrets manager reference.
5. If the secret sits in more than one commit, use a history-rewriting tool (e.g. `git filter-repo`) to purge it from all commits.
6. The `protect-main` ruleset blocks direct pushes to `main`. A repository admin must disable the ruleset, force-push, and then enable the ruleset again.
7. Notify collaborators to re-clone.
8. Re-run the pipeline to confirm TruffleHog now passes.

**If Bandit failed (SAST finding, HIGH severity):**

1. Open the Bandit findings report in the job log.
2. Identify the specific rule ID and line number flagged.
3. Evaluate whether the finding is a true positive. If it is a false positive, document why in a PR comment and use a scoped `# nosec` suppression on that line only — never disable the Bandit step itself.
4. If it's a true positive, fix the underlying pattern (e.g. replace a hardcoded credential, parameterize a SQL query, replace an unsafe deserialization call).
5. Re-run the pipeline to confirm the HIGH-severity step now passes. MEDIUM-severity findings are informational and do not block merge, but should still be reviewed.

**If pip-audit failed (CVE in a dependency):**

1. Identify the flagged package and the advisory ID (a CVE ID or a PYSEC ID) from the job log.
2. Read the `Fix Versions` column in the `pip-audit` output. If one package has several advisories with different fix versions, use the highest one.
3. Update `app/requirements.txt` to the patched version, pinned exactly (not a floor like `>=`).
4. If no patched version exists yet, evaluate whether the vulnerable code path is actually reachable in this application. If it is, treat this as a release blocker until a fix or mitigation is in place. If it is not reachable, document the exception and the reasoning in the PR.
5. Re-run the pipeline to confirm the scan passes.

### Step 3 — Confirm resolution

1. All three jobs show green on the pull request.
2. The fix is described in the PR description, not just the commit message, so the audit trail is self-explanatory later.

---

## Scenario 2 — Cloud Security: The Automated Response Disables an IAM User

### Trigger

A GuardDuty finding at severity ≥ 7 matches the EventBridge rule, which invokes the response Lambda. The security team receives an SNS email stating a user's access keys were deactivated and a DenyAll policy was attached.

### Step 1 — Read the alert

1. Open the SNS email.
2. Note the IAM username, the GuardDuty finding type, the severity, and the exact actions taken (which access keys were deactivated).

### Step 2 — Confirm the automated action actually landed

1. Open IAM, locate the named user, open Security credentials.
2. Confirm the access key(s) show Inactive.
3. Open Permissions.
4. Confirm the inline policy `SecurityIncidentDenyAll` is attached.
5. Open the Lambda function's CloudWatch logs for the matching timestamp.
6. Find the log lines for the run. Match the timestamp to the SNS email.
7. Confirm the log contains a `Received event:` line and a `SECURITY ACTION TAKEN` line.
8. Confirm the `User:` line shows the correct IAM username.
9. Confirm the `Finding:` line shows the expected finding type and severity.
10. Confirm the `Actions:` line lists every deactivated access key ID.
11. Confirm the `Actions:` line lists `Attached DenyAll inline policy`. This is the log wording. The IAM policy name is `SecurityIncidentDenyAll`.
12. Confirm no entry on the `Actions:` line begins with `Error`.
13. Do not use the `END` or `REPORT` line as proof of success. Lambda reports a normal finish even when an action failed.

If any of these did not happen — key still active, policy missing, or error text on the `Actions:` line — treat this as a Lambda failure, not just a security incident, and escalate both in parallel. The automated response not firing is itself the more urgent problem, since it means the account may still be exposed.

**Special case — the Lambda took no action.** The SNS subject reads `Meridian Security: Lambda triggered, no user identified`. The event contained no IAM username, so the Lambda changed nothing. The EventBridge rule matches every GuardDuty finding with severity 7 or higher, including findings about EC2 instances and roles. Treat the finding as an open incident. Contain the affected resource by hand.

**Special case — the `Actions:` line shows `NoSuchEntity`.** The principal in the finding is not an IAM user. It is probably an IAM role session. The Lambda cannot contain a role. Open IAM, open Roles, open the role, and choose Revoke active sessions.

### Step 3 — Investigate the underlying finding

1. Open the finding in GuardDuty (or Security Hub, if aggregated there).
2. Review the finding detail: source IP, API calls made, time window, resource(s) touched.
3. Check CloudTrail for the full activity history of this user/access key across the relevant time window, not just the activity that triggered the finding — the finding is a starting point, not the full picture.
4. Determine whether this is a genuine compromise, an overly broad detection rule, or legitimate but unusual activity (e.g. a developer running an unfamiliar script).

### Step 4 — Contain and remediate

1. If genuine compromise is confirmed: the automated response has already contained it (keys deactivated, deny policy attached). Next, determine how the credential was obtained (check Git history, check for any local `.env` or config file exposure, check if the credential was shared insecurely) and close that specific exposure path.
2. If this was a legitimate user mistakenly caught by the rule: reactivate the access key, remove the `SecurityIncidentDenyAll` inline policy, and consider whether the detection rule or GuardDuty's sensitivity needs tuning to reduce false positives — but don't widen it so much that it stops catching real recon activity.
3. In a confirmed compromise, search CloudTrail for IAM changes the user made before the response fired (e.g. `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `CreateRole`, `AttachUserPolicy`). Delete every identity and credential the attacker created. The DenyAll policy blocks the compromised user. It does not remove backdoors the attacker already planted.
4. Document the incident: what triggered it, what was found, what action was taken, and the final disposition (confirmed compromise vs. false positive).

### Step 5 — Confirm resolution

1. The user's access is either properly restored (false positive) or the user remains disabled pending full investigation (confirmed compromise).
2. The incident is logged with a timestamp, finding type, and resolution — this, together with the CloudTrail history, is the audit evidence regulators (UK GDPR / NHS DSPT, SOC 2, ISO 27001, depending on context) expect to see.

---

## A Note on the Demo/Test Trigger

This project also includes a demo-only EventBridge rule (`meridian-demo-trigger`) that accepts a hand-built, schema-accurate finding payload via `aws events put-events`, used to validate the response chain without waiting on GuardDuty's organic detection timing (see the [README](../README.md#a-note-on-the-detection-trigger) for why). In a real incident, only the production GuardDuty-sourced rule should ever invoke this Lambda. If a demo/test rule is still present in an AWS account being used for anything beyond the portfolio build, it should be disabled or deleted once testing is complete, so it can't be triggered accidentally or maliciously outside its intended purpose.

The risk is real. Anyone with `events:PutEvents` permission on the default event bus can forge a finding with the custom source and make this Lambda disable any IAM user, including an administrator. EventBridge reserves the `aws.` source prefix, so nobody can forge an event for the production rule.
