"""reorder-receipt-rule-set-duplicate-and-unknown-rule-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reorder-receipt-rule-set-duplicate-and-unknown-rule-rejected"
GROUP = "overly-permissive"
SERVICES = ["ses"]


def _require_receipt_region(ctx):
    """SES email receiving (receipt rules) is region-limited; fail elsewhere."""
    if ctx.region not in ("us-east-1", "us-west-2", "eu-west-1"):
        raise AssertionError(f"SES email receiving (receipt rules) is unavailable in {ctx.region}")


def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it must raise."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a rejection, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ReorderReceiptRuleSet refuses a duplicated rule name (InvalidParameterValue) and an unknown
    one (RuleDoesNotExist) without mutating the rule set; an exact permutation then applies.

    Reference: https://docs.aws.amazon.com/ses/latest/APIReference/API_ReorderReceiptRuleSet.html
    """
    ses = ctx.client("ses")
    _require_receipt_region(ctx)

    rule_set = ctx.unique_name("sim2real-behav-ruleset-reorderdup-")
    ses.create_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set))

    first, second = "first", "rich"
    ses.create_receipt_rule(
        RuleSetName=rule_set,
        Rule={"Name": first, "Enabled": True, "Actions": [{"StopAction": {"Scope": "RuleSet"}}]},
    )
    ses.create_receipt_rule(
        RuleSetName=rule_set,
        Rule={"Name": second, "Enabled": True, "Actions": [{"StopAction": {"Scope": "RuleSet"}}]},
        After=first,
    )
    baseline = [r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]]
    assert baseline == [first, second], f"precondition: expected [{first}, {second}], got {baseline}"

    # A name listed twice is InvalidParameterValue, not RuleDoesNotExist and not success.
    dup_err = _err(
        lambda: ses.reorder_receipt_rule_set(RuleSetName=rule_set, RuleNames=[second, second])
    )
    expected_dup = ("InvalidParameterValue", f"Multiple positions found for rule: {second}")
    assert dup_err == expected_dup, (
        f"expected {expected_dup!r} for a reorder list naming {second!r} twice, got {dup_err!r}"
    )
    after_dup = [r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]]
    assert after_dup == baseline, f"a rejected duplicate-name reorder must not mutate the rule set: {after_dup}"

    # A name the rule set has never seen is RuleDoesNotExist, a different error type from the
    # duplicate case above, even though both lists are "the wrong set of names".
    ghost_err = _err(
        lambda: ses.reorder_receipt_rule_set(RuleSetName=rule_set, RuleNames=[first, second, "ghost"])
    )
    expected_ghost = ("RuleDoesNotExist", "Rule does not exist: ghost")
    assert ghost_err == expected_ghost, (
        f"expected {expected_ghost!r} for a reorder list naming the unknown rule 'ghost', got {ghost_err!r}"
    )
    after_ghost = [r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]]
    assert after_ghost == baseline, f"a rejected unknown-rule reorder must not mutate the rule set: {after_ghost}"

    # A complete, exact permutation (every existing rule named exactly once, no extras) succeeds.
    ses.reorder_receipt_rule_set(RuleSetName=rule_set, RuleNames=[second, first])
    final = [r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]]
    assert final == [second, first], f"expected the identical valid permutation to apply, got {final}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
