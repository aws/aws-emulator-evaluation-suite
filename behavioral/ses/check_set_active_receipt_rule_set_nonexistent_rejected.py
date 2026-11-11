"""set-active-receipt-rule-set-nonexistent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-active-receipt-rule-set-nonexistent-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    """Activating (or describing) a receipt rule set that does not exist must fail with
    RuleSetDoesNotExist — proven against a positive control so the rejection is specific to the
    absent name, not evidence that every call to these operations is refused."""
    ses = ctx.client("ses")
    _require_receipt_region(ctx)

    # Positive control: a real rule set can be created, activated, and read back at an
    # independent operation from the one that mutated it.
    live_name = ctx.unique_name("sim2real-behav-ruleset-live-")
    ses.create_receipt_rule_set(RuleSetName=live_name)
    _track_receipt_rule_set(ctx, ses, live_name)
    ses.set_active_receipt_rule_set(RuleSetName=live_name)
    active = ses.describe_active_receipt_rule_set()
    assert active.get("Metadata", {}).get("Name") == live_name, (
        f"expected the live rule set {live_name!r} to be active, got {active.get('Metadata')}"
    )
    described = ses.describe_receipt_rule_set(RuleSetName=live_name)
    assert described.get("Metadata", {}).get("Name") == live_name, (
        f"expected DescribeReceiptRuleSet to find the live rule set {live_name!r}, got "
        f"{described.get('Metadata')}"
    )

    absent_name = ctx.unique_name("sim2real-behav-ruleset-absent-")
    err = _err(lambda: ses.set_active_receipt_rule_set(RuleSetName=absent_name))
    assert err == ("RuleSetDoesNotExist", f"Rule set does not exist: {absent_name}"), (
        f"expected RuleSetDoesNotExist activating an absent rule set, got {err!r}"
    )
    # Effect-absent: the rejected activation must not have disturbed the live active set.
    still_active = ses.describe_active_receipt_rule_set()
    assert still_active.get("Metadata", {}).get("Name") == live_name, (
        f"rejected activation of {absent_name!r} changed the active rule set to "
        f"{still_active.get('Metadata')}"
    )

    err2 = _err(lambda: ses.describe_receipt_rule_set(RuleSetName=absent_name))
    assert err2 == ("RuleSetDoesNotExist", f"Rule set does not exist: {absent_name}"), (
        f"expected RuleSetDoesNotExist describing an absent rule set, got {err2!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
