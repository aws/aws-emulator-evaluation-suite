"""receipt-rule-empty-recipients-list-vs-absent-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "receipt-rule-empty-recipients-list-vs-absent-persists"
GROUP = "representation"
SERVICES = ["ses"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeReceiptRule returns an explicit empty Recipients list as an empty list, while a rule
    created without Recipients has no Recipients key at all."""
    ses = ctx.client("ses")
    rule_set_name = ctx.unique_name("sim2real-ses-rs-")
    ses.create_receipt_rule_set(RuleSetName=rule_set_name)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set_name))

    ses.create_receipt_rule(
        RuleSetName=rule_set_name,
        Rule={
            "Name": "rule-explicit-empty",
            "Enabled": True,
            "Recipients": [],
            "Actions": [{"StopAction": {"Scope": "RuleSet"}}],
        },
    )
    ses.create_receipt_rule(
        RuleSetName=rule_set_name,
        Rule={
            "Name": "rule-omitted",
            "Enabled": True,
            "Actions": [{"StopAction": {"Scope": "RuleSet"}}],
        },
    )

    explicit = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName="rule-explicit-empty")["Rule"]
    omitted = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName="rule-omitted")["Rule"]

    recipients_explicit = explicit.get("Recipients")
    recipients_omitted = omitted.get("Recipients")
    assert recipients_explicit == [], recipients_explicit
    assert recipients_omitted is None, recipients_omitted
    assert "Recipients" not in omitted, omitted
    assert recipients_explicit != recipients_omitted, (recipients_explicit, recipients_omitted)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
