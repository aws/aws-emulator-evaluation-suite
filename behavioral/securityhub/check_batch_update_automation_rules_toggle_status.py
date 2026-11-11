"""batch-update-automation-rules-toggle-status."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-update-automation-rules-toggle-status"
GROUP = "state"
SERVICES = ["securityhub"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """BatchUpdateAutomationRules toggles RuleStatus ENABLED<->DISABLED and BatchGetAutomationRules reflects it."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(sh)
    rule_arn = sh.create_automation_rule(
        RuleName=ctx.unique_name("sim2real-toggle-rule-"),
        RuleStatus="ENABLED",
        RuleOrder=1,
        Description="sim2real behavioral test toggle rule",
        Criteria={"Title": [{"Value": ctx.unique_name("sim2real-never-matches-"), "Comparison": "EQUALS"}]},
        Actions=[
            {"Type": "FINDING_FIELDS_UPDATE", "FindingFieldsUpdate": {"Workflow": {"Status": "SUPPRESSED"}}}
        ],
        Tags={"sim2real:managed": "true"},
    )["RuleArn"]
    ctx.on_cleanup(lambda: sh.batch_delete_automation_rules(AutomationRulesArns=[rule_arn]))

    got = sh.batch_get_automation_rules(AutomationRulesArns=[rule_arn])["Rules"][0]
    assert got["RuleStatus"] == "ENABLED", f"expected freshly created rule RuleStatus ENABLED, got {got['RuleStatus']!r}"

    resp = sh.batch_update_automation_rules(
        UpdateAutomationRulesRequestItems=[{"RuleArn": rule_arn, "RuleStatus": "DISABLED"}]
    )
    assert resp["UnprocessedAutomationRules"] == [], (
        f"expected ENABLED->DISABLED update to be processed with no failures, "
        f"got UnprocessedAutomationRules={resp['UnprocessedAutomationRules']!r}"
    )
    got2 = sh.batch_get_automation_rules(AutomationRulesArns=[rule_arn])["Rules"][0]
    assert got2["RuleStatus"] == "DISABLED", f"expected RuleStatus DISABLED after toggle, got {got2['RuleStatus']!r}"

    resp2 = sh.batch_update_automation_rules(
        UpdateAutomationRulesRequestItems=[{"RuleArn": rule_arn, "RuleStatus": "ENABLED"}]
    )
    assert resp2["UnprocessedAutomationRules"] == [], (
        f"expected DISABLED->ENABLED update to be processed with no failures, "
        f"got UnprocessedAutomationRules={resp2['UnprocessedAutomationRules']!r}"
    )
    got3 = sh.batch_get_automation_rules(AutomationRulesArns=[rule_arn])["Rules"][0]
    assert got3["RuleStatus"] == "ENABLED", f"expected RuleStatus ENABLED after toggling back, got {got3['RuleStatus']!r}"


def _ensure_hub_enabled(sh):
    from botocore.exceptions import ClientError

    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
