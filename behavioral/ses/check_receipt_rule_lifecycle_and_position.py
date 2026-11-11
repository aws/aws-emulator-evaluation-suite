"""receipt-rule-lifecycle-and-position."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-rule-lifecycle-and-position"
GROUP = 'receipt-rules'
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
    """SES email receiving (receipt rules) is region-limited; skip elsewhere."""
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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ses-active-receipt-rule-set")
def run(ctx) -> None:
    """CreateReceiptRule inserts rules in order; SetReceiptRulePosition/DeleteReceiptRule mutate that order."""
    ses = ctx.client("ses")
    _require_receipt_region(ctx)
    set_name = ctx.unique_name("sim2real-behav-ruleset-rules-")
    ses.create_receipt_rule_set(RuleSetName=set_name)
    _track_receipt_rule_set(ctx, ses, set_name)

    rule1 = "rule-1"
    rule2 = "rule-2"
    ses.create_receipt_rule(
        RuleSetName=set_name,
        Rule={"Name": rule1, "Enabled": True, "Actions": [{"StopAction": {"Scope": "RuleSet"}}]},
    )
    ses.create_receipt_rule(
        RuleSetName=set_name,
        Rule={"Name": rule2, "Enabled": True, "Actions": [{"StopAction": {"Scope": "RuleSet"}}]},
        After=rule1,
    )

    desc = ses.describe_receipt_rule_set(RuleSetName=set_name)
    order = [r["Name"] for r in desc["Rules"]]
    assert order == [rule1, rule2], f"expected insertion order [{rule1}, {rule2}], got {order}"

    ses.set_receipt_rule_position(RuleSetName=set_name, RuleName=rule2)
    desc2 = ses.describe_receipt_rule_set(RuleSetName=set_name)
    order2 = [r["Name"] for r in desc2["Rules"]]
    assert order2 == [rule2, rule1], f"expected [{rule2}, {rule1}] after moving to front, got {order2}"

    ses.delete_receipt_rule(RuleSetName=set_name, RuleName=rule1)
    desc3 = ses.describe_receipt_rule_set(RuleSetName=set_name)
    order3 = [r["Name"] for r in desc3["Rules"]]
    assert order3 == [rule2], f"expected only [{rule2}] left after delete, got {order3}"

    # A rule created without `After` is inserted at the HEAD of the rule set.
    rule3 = "rule-3"
    ses.create_receipt_rule(
        RuleSetName=set_name,
        Rule={"Name": rule3, "Enabled": True, "Actions": [{"StopAction": {"Scope": "RuleSet"}}]},
    )
    desc4 = ses.describe_receipt_rule_set(RuleSetName=set_name)
    order4 = [r["Name"] for r in desc4["Rules"]]
    assert order4 == [rule3, rule2], (
        f"expected a rule created without After to be prepended, got {order4}"
    )

    err = _err(lambda: ses.describe_receipt_rule(RuleSetName=set_name, RuleName=rule1))
    assert err == ("RuleDoesNotExist", f"Rule does not exist: {rule1}"), (
        f"expected RuleDoesNotExist naming {rule1!r}, got {err!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
