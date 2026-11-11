"""update-receipt-rule-full-replace-resets-unspecified-fields."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-receipt-rule-full-replace-resets-unspecified-fields"
GROUP = "state-machine"
SERVICES = ["ses"]


def _require_receipt_region(ctx):
    """SES email receiving (receipt rules) is region-limited; fail elsewhere."""
    if ctx.region not in ("us-east-1", "us-west-2", "eu-west-1"):
        raise AssertionError(f"SES email receiving (receipt rules) is unavailable in {ctx.region}")


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateReceiptRule is a full replace, not a merge: updating a fully configured rule with only
    Name resets Enabled, TlsPolicy, ScanEnabled, Recipients and Actions to their defaults.

    Reference: https://docs.aws.amazon.com/ses/latest/APIReference/API_UpdateReceiptRule.html
    """
    ses = ctx.client("ses")
    _require_receipt_region(ctx)

    rule_set = ctx.unique_name("sim2real-behav-ruleset-fullreplace-")
    ses.create_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set))

    rule_name = "rich"
    ses.create_receipt_rule(
        RuleSetName=rule_set,
        Rule={
            "Name": rule_name,
            "Enabled": True,
            "TlsPolicy": "Require",
            "ScanEnabled": True,
            "Recipients": ["probe@example.com"],
            "Actions": [{"StopAction": {"Scope": "RuleSet"}}],
        },
    )
    ctx.on_cleanup(lambda: ses.delete_receipt_rule(RuleSetName=rule_set, RuleName=rule_name))

    before = ses.describe_receipt_rule(RuleSetName=rule_set, RuleName=rule_name)["Rule"]
    assert before["Enabled"] is True, f"precondition: expected Enabled True, got {before!r}"
    assert before["TlsPolicy"] == "Require", f"precondition: expected TlsPolicy Require, got {before!r}"
    assert before["ScanEnabled"] is True, f"precondition: expected ScanEnabled True, got {before!r}"
    assert before.get("Recipients") == ["probe@example.com"], f"precondition: expected one recipient, got {before!r}"
    assert len(before.get("Actions") or []) == 1, f"precondition: expected one action, got {before!r}"

    ses.update_receipt_rule(RuleSetName=rule_set, Rule={"Name": rule_name})

    after = ses.describe_receipt_rule(RuleSetName=rule_set, RuleName=rule_name)["Rule"]
    assert after["Name"] == rule_name, f"expected Name {rule_name!r} unchanged, got {after['Name']!r}"
    assert after["Enabled"] is False, (
        f"UpdateReceiptRule omitted Enabled; expected it to reset to the schema default False, "
        f"got {after['Enabled']!r} -- the prior True value must not be retained"
    )
    assert after["TlsPolicy"] == "Optional", (
        f"UpdateReceiptRule omitted TlsPolicy; expected it to reset to the default 'Optional', "
        f"got {after['TlsPolicy']!r} -- the prior 'Require' value must not be retained"
    )
    assert after["ScanEnabled"] is False, (
        f"UpdateReceiptRule omitted ScanEnabled; expected it to reset to the schema default False, "
        f"got {after['ScanEnabled']!r} -- the prior True value must not be retained"
    )
    assert after.get("Recipients", []) == [], (
        f"UpdateReceiptRule omitted Recipients; expected none to remain, got {after.get('Recipients')!r} "
        f"-- the prior ['probe@example.com'] value must not be retained"
    )
    assert after.get("Actions", []) == [], (
        f"UpdateReceiptRule omitted Actions; expected none to remain, got {after.get('Actions')!r} "
        f"-- the prior StopAction must not be retained"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
