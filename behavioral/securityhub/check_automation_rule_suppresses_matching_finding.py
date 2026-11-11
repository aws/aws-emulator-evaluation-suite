"""automation-rule-suppresses-matching-finding."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "automation-rule-suppresses-matching-finding"
GROUP = "event-propagation"
SERVICES = ["securityhub"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """An enabled automation rule automatically suppresses newly imported findings that match its
    criteria, and leaves a non-matching finding imported in the same batch untouched."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(ctx, sh)
    account_id = _account_id(ctx)
    product_arn = _default_product_arn(ctx, account_id)
    marker_title = ctx.unique_name("sim2real-auto-title-")

    rule_arn = sh.create_automation_rule(
        RuleName=ctx.unique_name("sim2real-auto-rule-"),
        RuleStatus="ENABLED",
        RuleOrder=1,
        Description="sim2real behavioral test automation rule",
        Criteria={"Title": [{"Value": marker_title, "Comparison": "EQUALS"}]},
        Actions=[
            {"Type": "FINDING_FIELDS_UPDATE", "FindingFieldsUpdate": {"Workflow": {"Status": "SUPPRESSED"}}}
        ],
    )["RuleArn"]
    ctx.on_cleanup(lambda: sh.batch_delete_automation_rules(AutomationRulesArns=[rule_arn]))

    finding_id = ctx.unique_name("sim2real-auto-finding-")
    finding = _make_finding(account_id, product_arn, finding_id, marker_title)

    # Twin control imported in the SAME batch, at the SAME instant, but its title does not match
    # the rule's criteria. Without this, a target that suppresses every newly imported finding
    # regardless of criteria would still pass.
    control_id = ctx.unique_name("sim2real-auto-control-")
    control_title = ctx.unique_name("sim2real-auto-nomatch-")
    control = _make_finding(account_id, product_arn, control_id, control_title)

    _import_with_retry(sh, [finding, control])
    identifier = {"Id": finding_id, "ProductArn": product_arn}
    control_identifier = {"Id": control_id, "ProductArn": product_arn}
    ctx.on_cleanup(lambda: sh.batch_update_findings(FindingIdentifiers=[identifier], Workflow={"Status": "RESOLVED"}))
    ctx.on_cleanup(
        lambda: sh.batch_update_findings(FindingIdentifiers=[control_identifier], Workflow={"Status": "RESOLVED"})
    )

    status = _poll_until(
        lambda: _first_or_none(sh, finding_id),
        lambda f: f is not None and f["Workflow"]["Status"] == "SUPPRESSED",
        timeout_s=180,
        interval_s=5,
    )["Workflow"]["Status"]
    assert status == "SUPPRESSED", f"expected matching finding's Workflow.Status == 'SUPPRESSED', got {status!r}"

    control_found = _poll_until(
        lambda: _first_or_none(sh, control_id),
        lambda f: f is not None,
        timeout_s=60,
        interval_s=5,
    )
    control_status = control_found["Workflow"]["Status"]
    assert control_status == "NEW", (
        "non-matching finding imported in the same batch was not left untouched: expected "
        f"Workflow.Status == 'NEW', got {control_status!r}"
    )


def _first_or_none(sh, finding_id):
    findings = sh.get_findings(Filters={"Id": [{"Value": finding_id, "Comparison": "EQUALS"}]})["Findings"]
    return findings[0] if findings else None


def _ensure_hub_enabled(ctx, sh):
    """Enable Security Hub for this check. When this call is what turned the hub on, cleanup
    turns it back off, so the account's hub subscription ends in the state it started in."""
    from botocore.exceptions import ClientError

    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise
        return
    ctx.on_cleanup(sh.disable_security_hub)


def _import_with_retry(sh, findings, *, timeout_s=60.0, interval_s=5.0):
    """BatchImportFindings against the default product ARN answers AccessDeniedException for a
    short while after enable_security_hub first activates the hub (resource-policy propagation);
    retry until that clears."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sh.batch_import_findings(Findings=findings)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _default_product_arn(ctx, account_id):
    return f"arn:aws:securityhub:{ctx.region}:{account_id}:product/{account_id}/default"


def _now_iso():
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _make_finding(account_id, product_arn, finding_id, title, severity_label="LOW", **overrides):
    now = _now_iso()
    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": product_arn,
        "GeneratorId": "sim2real-behavioral-test",
        "AwsAccountId": account_id,
        "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
        "CreatedAt": now,
        "UpdatedAt": now,
        "Title": title,
        "Description": "sim2real behavioral fidelity test finding",
        "Severity": {"Label": severity_label},
        "Resources": [{"Type": "Other", "Id": f"sim2real:{finding_id}"}],
    }
    finding.update(overrides)
    return finding


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
