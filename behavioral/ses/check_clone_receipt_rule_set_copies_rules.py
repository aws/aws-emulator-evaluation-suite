"""clone-receipt-rule-set-copies-rules."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "clone-receipt-rule-set-copies-rules"
GROUP = 'receipt-rules'
SERVICES = ['ses']

def _err(fn):
    """Call fn() and return the (Error.Code, Error.Message) of the ClientError it raises. An
    unexpected success raises, so a target that accepts a call AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
    """CloneReceiptRuleSet deep-copies rules into a new, non-active rule set and rejects name conflicts."""
    ses = ctx.client("ses")
    _require_receipt_region(ctx)
    clone = ctx.unique_name("sim2real-behav-ruleset-clone-")
    original = ctx.unique_name("sim2real-behav-ruleset-src-")
    ses.create_receipt_rule_set(RuleSetName=original)
    _track_receipt_rule_set(ctx, ses, original)
    # CreateReceiptRule without `After` inserts at the HEAD of the rule set, so build
    # the deterministic order [clone-rule-1, clone-rule-2] explicitly.
    ses.create_receipt_rule(
        RuleSetName=original,
        Rule={
            "Name": "clone-rule-1",
            "Enabled": True,
            "Actions": [{"StopAction": {"Scope": "RuleSet"}}],
        },
    )
    ses.create_receipt_rule(
        RuleSetName=original,
        Rule={
            "Name": "clone-rule-2",
            "Enabled": True,
            "Actions": [{"StopAction": {"Scope": "RuleSet"}}],
        },
        After="clone-rule-1",
    )
    assert [r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=original)["Rules"]] == [
        "clone-rule-1",
        "clone-rule-2",
    ], "precondition: original rule set order not as constructed"

    ses.clone_receipt_rule_set(RuleSetName=clone, OriginalRuleSetName=original)
    _track_receipt_rule_set(ctx, ses, clone)

    cloned = ses.describe_receipt_rule_set(RuleSetName=clone)
    assert [r["Name"] for r in cloned["Rules"]] == ["clone-rule-1", "clone-rule-2"], (
        f"clone did not preserve rule order/content: {cloned['Rules']}"
    )

    # A clone is never automatically activated.
    active = ses.describe_active_receipt_rule_set()
    assert active.get("Metadata", {}).get("Name") != clone, "clone was unexpectedly made active"

    # Mutating the clone must not affect the original (deep copy, not alias).
    ses.delete_receipt_rule(RuleSetName=clone, RuleName="clone-rule-1")
    original_rules = [r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=original)["Rules"]]
    assert original_rules == ["clone-rule-1", "clone-rule-2"], (
        f"mutating the clone changed the original rule set: {original_rules}"
    )

    # Cloning onto an existing name conflicts.
    err = _err(
        lambda: ses.clone_receipt_rule_set(RuleSetName=clone, OriginalRuleSetName=original)
    )
    assert err == ("AlreadyExists", f"Rule set already exists: {clone}"), (
        f"expected AlreadyExists cloning onto an existing name, got {err!r}"
    )

    # The rejected clone-onto-existing-name call must not have mutated the existing target.
    unchanged = [r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=clone)["Rules"]]
    assert unchanged == ["clone-rule-2"], (
        f"a rejected clone onto an existing name must not modify that rule set: {unchanged}"
    )

    # Cloning from a non-existent original is a different error.
    clone2 = ctx.unique_name("sim2real-behav-ruleset-clone2-")
    ghost = ctx.unique_name("sim2real-behav-ruleset-ghost-")
    err_src = _err(
        lambda: ses.clone_receipt_rule_set(RuleSetName=clone2, OriginalRuleSetName=ghost)
    )
    assert err_src == ("RuleSetDoesNotExist", f"Rule set does not exist: {ghost}"), (
        f"expected RuleSetDoesNotExist cloning from an unknown original, got {err_src!r}"
    )

    # The rejected clone must not have created the target as a side effect.
    err_target = _err(lambda: ses.describe_receipt_rule_set(RuleSetName=clone2))
    assert err_target == ("RuleSetDoesNotExist", f"Rule set does not exist: {clone2}"), (
        f"clone target must not exist after a rejected clone, got {err_target!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
