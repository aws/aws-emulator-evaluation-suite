"""delete-receipt-rule-missing-rule-is-noop."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-receipt-rule-missing-rule-is-noop"
GROUP = 'receipt-rules'
SERVICES = ['ses']

def _unexpected_success_err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of a ClientError. An unexpected
    SUCCESS raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ses-active-receipt-rule-set")
def run(ctx) -> None:
    """DeleteReceiptRule tolerates an absent rule (no-op) but an absent rule set is RuleSetDoesNotExist; DescribeReceiptRule on an absent rule is RuleDoesNotExist."""
    ses = ctx.client("ses")
    _require_receipt_region(ctx)
    set_name = ctx.unique_name("sim2real-behav-ruleset-noop-")
    ses.create_receipt_rule_set(RuleSetName=set_name)
    _track_receipt_rule_set(ctx, ses, set_name)

    # Positive control: DescribeReceiptRule succeeds on a rule that actually exists, so the
    # RuleDoesNotExist assertion below cannot be satisfied by a target that answers
    # RuleDoesNotExist to every describe regardless of whether the rule exists.
    real_rule = ctx.unique_name("sim2real-behav-real-rule-")
    ses.create_receipt_rule(
        RuleSetName=set_name,
        Rule={"Name": real_rule, "Enabled": True, "Actions": []},
    )
    described = ses.describe_receipt_rule(RuleSetName=set_name, RuleName=real_rule)["Rule"]
    assert described["Name"] == real_rule, (
        f"expected DescribeReceiptRule to return the created rule {real_rule!r}, got {described!r}"
    )

    # Does not raise even though "missing-rule" was never created.
    try:
        ses.delete_receipt_rule(RuleSetName=set_name, RuleName="missing-rule")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        raise AssertionError(
            f"expected DeleteReceiptRule to no-op on a missing rule in an existing set, got {code!r}"
        ) from exc

    absent_set = ctx.unique_name("sim2real-behav-ruleset-absent-")
    err = _unexpected_success_err(
        lambda: ses.delete_receipt_rule(RuleSetName=absent_set, RuleName="x")
    )
    assert err == ("RuleSetDoesNotExist", f"Rule set does not exist: {absent_set}"), (
        f"expected RuleSetDoesNotExist deleting a rule from an absent set, got {err!r}"
    )

    # DescribeReceiptRule on an absent rule is, by contrast, an error.
    err2 = _unexpected_success_err(
        lambda: ses.describe_receipt_rule(RuleSetName=set_name, RuleName="missing-rule")
    )
    assert err2 == ("RuleDoesNotExist", "Rule does not exist: missing-rule"), (
        f"expected RuleDoesNotExist describing an absent rule, got {err2!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
