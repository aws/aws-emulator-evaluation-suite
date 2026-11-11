"""receipt-rule-set-active-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-rule-set-active-lifecycle"
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
    """SES email receiving (receipt rules) is region-limited; fail loudly outside those regions."""
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
    """SetActiveReceiptRuleSet designates a single account-wide active set; omitting the name deactivates all."""
    ses = ctx.client("ses")
    _require_receipt_region(ctx)
    set_a = ctx.unique_name("sim2real-behav-ruleset-a-")
    set_b = ctx.unique_name("sim2real-behav-ruleset-b-")
    ses.create_receipt_rule_set(RuleSetName=set_a)
    _track_receipt_rule_set(ctx, ses, set_a)
    ses.create_receipt_rule_set(RuleSetName=set_b)
    _track_receipt_rule_set(ctx, ses, set_b)

    ses.set_active_receipt_rule_set(RuleSetName=set_a)
    active = ses.describe_active_receipt_rule_set()
    assert active.get("Metadata", {}).get("Name") == set_a, (
        f"expected active rule set {set_a!r}, got {active.get('Metadata')}"
    )

    ses.set_active_receipt_rule_set(RuleSetName=set_b)
    active2 = ses.describe_active_receipt_rule_set()
    assert active2.get("Metadata", {}).get("Name") == set_b, "active rule set did not switch to set_b"

    ses.set_active_receipt_rule_set()
    active3 = ses.describe_active_receipt_rule_set()
    assert not active3.get("Metadata"), f"expected no active rule set after deactivation, got {active3}"

    # Activating a rule set that does not exist must be rejected.
    ghost = ctx.unique_name("sim2real-behav-ruleset-ghost-")
    err = _err(lambda: ses.set_active_receipt_rule_set(RuleSetName=ghost))
    assert err == ("RuleSetDoesNotExist", f"Rule set does not exist: {ghost}"), (
        f"expected RuleSetDoesNotExist activating an unknown rule set, got {err!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
