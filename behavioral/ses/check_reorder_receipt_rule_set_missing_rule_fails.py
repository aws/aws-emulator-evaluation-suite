"""reorder-receipt-rule-set-missing-rule-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reorder-receipt-rule-set-missing-rule-fails"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises.

    An unexpected success raises, so a target that accepts what AWS refuses fails loudly
    instead of reading as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _require_receipt_region(ctx):
    """SES email receiving (receipt rules) is region-limited; fails outside those regions."""
    if ctx.region not in ("us-east-1", "us-west-2", "eu-west-1"):
        raise AssertionError(f"SES email receiving (receipt rules) is unavailable in {ctx.region}")


def _track_receipt_rule_set(ctx, ses, name):
    """Register teardown for a receipt rule set: deactivate the active set first (an active
    rule set cannot be deleted), then delete this one."""
    def _teardown():
        active_set = (ses.describe_active_receipt_rule_set().get("Metadata") or {}).get("Name")
        if active_set == name:  # never deactivate a set this check did not create
            ses.set_active_receipt_rule_set()
        ses.delete_receipt_rule_set(RuleSetName=name)

    ctx.on_cleanup(_teardown)
    return name


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ses-active-receipt-rule-set")
def run(ctx) -> None:
    """ReorderReceiptRuleSet must reject an incomplete RuleNames list that omits an existing rule (validation boundary)."""
    ses = ctx.client("ses")
    _require_receipt_region(ctx)
    set_name = ctx.unique_name("sim2real-behav-ruleset-reorder-")
    ses.create_receipt_rule_set(RuleSetName=set_name)
    _track_receipt_rule_set(ctx, ses, set_name)

    rule1, rule2 = "rule-a", "rule-b"
    ses.create_receipt_rule(
        RuleSetName=set_name,
        Rule={"Name": rule1, "Enabled": True, "Actions": [{"StopAction": {"Scope": "RuleSet"}}]},
    )
    ses.create_receipt_rule(
        RuleSetName=set_name,
        Rule={"Name": rule2, "Enabled": True, "Actions": [{"StopAction": {"Scope": "RuleSet"}}]},
        After=rule1,
    )

    # Omitting rule2 from the reorder list is invalid: every existing rule must be listed
    # exactly once. Real SES answers with a parameter-validation error (not RuleDoesNotExist).
    err = _err(
        lambda: ses.reorder_receipt_rule_set(RuleSetName=set_name, RuleNames=[rule1])
    )
    assert err == ("InvalidParameterValue", f"Positions for rules not found: {rule2}"), (
        f"expected InvalidParameterValue for incomplete reorder list, got {err!r}"
    )

    # The rejected reorder must not have partially applied.
    order_before = [
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=set_name)["Rules"]
    ]
    assert order_before == [rule1, rule2], (
        f"a rejected reorder mutated the rule set: {order_before}"
    )

    # A complete, valid reorder must succeed.
    ses.reorder_receipt_rule_set(RuleSetName=set_name, RuleNames=[rule2, rule1])
    desc = ses.describe_receipt_rule_set(RuleSetName=set_name)
    order = [r["Name"] for r in desc["Rules"]]
    assert order == [rule2, rule1], f"expected reordered [{rule2}, {rule1}], got {order}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
