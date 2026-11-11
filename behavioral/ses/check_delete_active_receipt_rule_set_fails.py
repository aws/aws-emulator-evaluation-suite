"""delete-active-receipt-rule-set-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-active-receipt-rule-set-fails"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised. Raises
    if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _require_receipt_region(ctx):
    """SES email receiving (receipt rules) is region-limited; skip elsewhere."""
    if ctx.region not in ("us-east-1", "us-west-2", "eu-west-1"):
        raise AssertionError(f"SES email receiving (receipt rules) is unavailable in {ctx.region}")


def _active_rule_set_name(ses):
    """The account's active receipt rule set name, or None when no set is active."""
    return (ses.describe_active_receipt_rule_set().get("Metadata") or {}).get("Name")


def _restore_active(ses, prior):
    """Put the account's active receipt rule set back to the one found at the start."""
    if prior is None:
        ses.set_active_receipt_rule_set()
    else:
        ses.set_active_receipt_rule_set(RuleSetName=prior)


def _track_receipt_rule_set(ctx, ses, name, prior):
    """Register teardown for a receipt rule set: restore the account's original active set
    (an active rule set cannot be deleted), then delete this one if it is still there."""
    def _teardown():
        _restore_active(ses, prior)
        try:
            ses.delete_receipt_rule_set(RuleSetName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "RuleSetDoesNotExist":
                raise

    ctx.on_cleanup(_teardown)
    return name


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ses-active-receipt-rule-set")
def run(ctx) -> None:
    """DeleteReceiptRuleSet must reject deleting the currently-active rule set (state-conflict boundary)."""
    ses = ctx.client("ses")
    _require_receipt_region(ctx)
    name = ctx.unique_name("sim2real-behav-ruleset-active-")
    prior = _active_rule_set_name(ses)
    ses.create_receipt_rule_set(RuleSetName=name)
    _track_receipt_rule_set(ctx, ses, name, prior)
    ses.set_active_receipt_rule_set(RuleSetName=name)

    try:
        err, msg = _err(lambda: ses.delete_receipt_rule_set(RuleSetName=name))
        assert err == "CannotDelete", (
            f"expected CannotDelete deleting the active rule set, got {err!r}: {msg!r}"
        )
        assert msg == f"Cannot delete active rule set: {name}", (
            f"expected the CannotDelete refusal to name the active rule set {name!r}, got {msg!r}"
        )
        # It must still exist and still be active after the rejected delete.
        active = ses.describe_active_receipt_rule_set()
        active_name = active.get("Metadata", {}).get("Name")
        assert active_name == name, (
            f"expected the active rule set to remain {name!r} after a rejected delete, "
            f"got {active_name!r}"
        )
    finally:
        _restore_active(ses, prior)

    # Once it is no longer the active set, deletion must succeed.
    ses.delete_receipt_rule_set(RuleSetName=name)

    # Gone: a specific not-found code, via an independent read of the rule set itself.
    gone_msg = f"Rule set does not exist: {name}"
    describe_code, describe_msg = _err(lambda: ses.describe_receipt_rule_set(RuleSetName=name))
    assert describe_code == "RuleSetDoesNotExist", (
        f"expected RuleSetDoesNotExist describing the deleted rule set {name!r}, got {describe_code!r}"
    )
    assert describe_msg == gone_msg, (
        f"expected {gone_msg!r} describing the deleted rule set, got {describe_msg!r}"
    )

    # Unusable: a mutation naming the dead id is also rejected.
    activate_code, activate_msg = _err(lambda: ses.set_active_receipt_rule_set(RuleSetName=name))
    assert activate_code == "RuleSetDoesNotExist", (
        f"expected RuleSetDoesNotExist activating the deleted rule set {name!r}, got {activate_code!r}"
    )
    assert activate_msg == gone_msg, (
        f"expected {gone_msg!r} activating the deleted rule set, got {activate_msg!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
