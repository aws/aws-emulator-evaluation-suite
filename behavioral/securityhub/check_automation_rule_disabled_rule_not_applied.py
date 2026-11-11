"""automation-rule-disabled-rule-not-applied."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "automation-rule-disabled-rule-not-applied"
GROUP = "state"
SERVICES = ["securityhub"]


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """A DISABLED automation rule never fires: its matching finding's workflow status stays NEW, while
    an enabled twin rule on a second finding of the same wiring applies the same action within the
    same window, so the absence is a withheld action, not a missing delivery path."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(sh)
    account_id = _account_id(ctx)
    product_arn = _default_product_arn(ctx, account_id)
    disabled_title = ctx.unique_name("sim2real-autodis-title-")
    control_title = ctx.unique_name("sim2real-autodis-control-title-")
    action = [{"Type": "FINDING_FIELDS_UPDATE", "FindingFieldsUpdate": {"Workflow": {"Status": "SUPPRESSED"}}}]
    check_tag = {"sim2real-check": CHECK}

    disabled_rule_arn = sh.create_automation_rule(
        RuleName=ctx.unique_name("sim2real-autodis-rule-"),
        RuleStatus="DISABLED",
        RuleOrder=1,
        Description="sim2real behavioral test disabled automation rule",
        Criteria={"Title": [{"Value": disabled_title, "Comparison": "EQUALS"}]},
        Actions=action,
        Tags=check_tag,
    )["RuleArn"]
    ctx.on_cleanup(lambda: sh.batch_delete_automation_rules(AutomationRulesArns=[disabled_rule_arn]))

    control_rule_arn = sh.create_automation_rule(
        RuleName=ctx.unique_name("sim2real-autodis-control-rule-"),
        RuleStatus="ENABLED",
        RuleOrder=1,
        Description="sim2real behavioral test enabled twin control rule",
        Criteria={"Title": [{"Value": control_title, "Comparison": "EQUALS"}]},
        Actions=action,
        Tags=check_tag,
    )["RuleArn"]
    ctx.on_cleanup(lambda: sh.batch_delete_automation_rules(AutomationRulesArns=[control_rule_arn]))

    disabled_finding_id = ctx.unique_name("sim2real-autodis-finding-")
    control_finding_id = ctx.unique_name("sim2real-autodis-control-finding-")
    disabled_identifier = {"Id": disabled_finding_id, "ProductArn": product_arn}
    control_identifier = {"Id": control_finding_id, "ProductArn": product_arn}
    import_resp = sh.batch_import_findings(
        Findings=[
            _make_finding(account_id, product_arn, disabled_finding_id, disabled_title),
            _make_finding(account_id, product_arn, control_finding_id, control_title),
        ]
    )
    assert import_resp["FailedCount"] == 0, (
        f"batch_import_findings failed for {import_resp['FailedCount']} finding(s): "
        f"{import_resp['FailedFindings']}"
    )
    ctx.on_cleanup(
        lambda: sh.batch_update_findings(FindingIdentifiers=[disabled_identifier], Workflow={"Status": "RESOLVED"})
    )
    ctx.on_cleanup(
        lambda: sh.batch_update_findings(FindingIdentifiers=[control_identifier], Workflow={"Status": "RESOLVED"})
    )

    def _status(finding_id):
        matches = sh.get_findings(Filters={"Id": [{"Value": finding_id, "Comparison": "EQUALS"}]})["Findings"]
        return matches[0]["Workflow"]["Status"] if matches else None

    # Sample both findings on the same wiring at the same instants -- this single bounded window
    # also absorbs each finding's own indexing latency after import, so no separate up-front wait
    # competes with it for budget. Once the enabled twin control has demonstrably applied its
    # identical action, hold the window open at least as long again past that point -- that is
    # the evidence that the disabled rule's absence is a withheld action, not a target with no
    # delivery path at all.
    disabled_seen = set()
    control_latency_s = None
    started = time.monotonic()
    hard_deadline = started + 200
    deadline = hard_deadline
    while time.monotonic() < deadline:
        disabled_status = _status(disabled_finding_id)
        if disabled_status is not None:
            disabled_seen.add(disabled_status)
        if control_latency_s is None and _status(control_finding_id) == "SUPPRESSED":
            control_latency_s = time.monotonic() - started
            deadline = min(hard_deadline, time.monotonic() + max(2 * control_latency_s, 20))
        time.sleep(5)

    assert disabled_seen, (
        "disabled-rule finding never became visible via get_findings within 200s -- cannot "
        "assert a workflow status that was never observed"
    )
    assert control_latency_s is not None, (
        "enabled twin control rule never applied its action within 200s -- cannot distinguish a "
        "withheld action from a target with no automation-rule delivery path at all"
    )
    assert disabled_seen == {"NEW"}, (
        f"disabled automation rule action applied: observed workflow statuses {disabled_seen} "
        f"(enabled twin control fired after {control_latency_s:.1f}s on the same wiring)"
    )


def _ensure_hub_enabled(sh):
    from botocore.exceptions import ClientError

    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
