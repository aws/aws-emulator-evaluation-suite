"""receipt-rule-describe-update-and-position."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-rule-describe-update-and-position"
GROUP = 'receipt-rules'
SERVICES = ['ses']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeReceiptRule reflects defaults; UpdateReceiptRule mutates in place;
    SetReceiptRulePosition moves a rule."""
    ses = ctx.client("ses")
    rule_set_name = ctx.unique_name("sim2real-behav-ses-ruleset-upd-")
    ses.create_receipt_rule_set(RuleSetName=rule_set_name)
    ctx.on_cleanup(
        lambda: _quiet(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set_name))
    )

    rule_a = ctx.unique_name("sim2real-behav-rule-a-")
    rule_b = ctx.unique_name("sim2real-behav-rule-b-")
    ses.create_receipt_rule(
        RuleSetName=rule_set_name,
        Rule={"Name": rule_a, "Enabled": True, "Recipients": ["a@example.com"], "Actions": []},
    )
    ses.create_receipt_rule(
        RuleSetName=rule_set_name, Rule={"Name": rule_b, "Enabled": True, "Actions": []}
    )

    rule = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName=rule_a)["Rule"]
    assert rule["Name"] == rule_a, f"expected Name {rule_a!r}, got {rule['Name']!r}"
    assert rule["Enabled"] is True, f"expected Enabled True, got {rule['Enabled']!r}"
    assert rule["Recipients"] == ["a@example.com"], (
        f"expected Recipients ['a@example.com'], got {rule['Recipients']!r}"
    )
    # Unspecified TlsPolicy defaults to Optional, and ScanEnabled defaults to False.
    assert rule["TlsPolicy"] == "Optional", f"expected default TlsPolicy Optional, got {rule!r}"
    assert rule["ScanEnabled"] is False, f"expected default ScanEnabled False, got {rule!r}"

    ses.update_receipt_rule(
        RuleSetName=rule_set_name,
        Rule={
            "Name": rule_a,
            "Enabled": False,
            "TlsPolicy": "Require",
            "ScanEnabled": True,
            "Recipients": ["b@example.com"],
            "Actions": [],
        },
    )
    rule2 = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName=rule_a)["Rule"]
    assert rule2["Enabled"] is False, f"expected Enabled False after update, got {rule2['Enabled']!r}"
    assert rule2["TlsPolicy"] == "Require", f"expected TlsPolicy Require after update, got {rule2['TlsPolicy']!r}"
    assert rule2["ScanEnabled"] is True, f"expected ScanEnabled True after update, got {rule2['ScanEnabled']!r}"
    assert rule2["Recipients"] == ["b@example.com"], (
        f"expected Recipients ['b@example.com'] after update, got {rule2['Recipients']!r}"
    )

    # Update must not change ordering: still [rule_b, rule_a] from the prepend rule.
    order_after_update = [
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set_name)["Rules"]
    ]
    assert order_after_update == [rule_b, rule_a], (
        f"expected order [{rule_b}, {rule_a}] unchanged by update, got {order_after_update}"
    )

    # SetReceiptRulePosition with no After moves the rule to the top.
    ses.set_receipt_rule_position(RuleSetName=rule_set_name, RuleName=rule_a)
    order_no_after = [
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set_name)["Rules"]
    ]
    assert order_no_after == [rule_a, rule_b], (
        f"expected order [{rule_a}, {rule_b}] after position with no After, got {order_no_after}"
    )

    # ...and with After it lands immediately behind the named rule.
    ses.set_receipt_rule_position(RuleSetName=rule_set_name, RuleName=rule_a, After=rule_b)
    order_with_after = [
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set_name)["Rules"]
    ]
    assert order_with_after == [rule_b, rule_a], (
        f"expected order [{rule_b}, {rule_a}] after position After={rule_b}, got {order_with_after}"
    )


def _quiet(fn):
    """Best-effort teardown call — the resource may already be gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RuleSetDoesNotExist":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
