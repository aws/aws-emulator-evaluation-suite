"""clone-receipt-rule-set-source-must-exist."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "clone-receipt-rule-set-source-must-exist"
GROUP = 'overly-permissive'
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ses-active-receipt-rule-set")
def run(ctx) -> None:
    """CloneReceiptRuleSet from an absent original must fail with RuleSetDoesNotExist, not create an
    empty clone; the identical call must succeed once the original is created, so the rejection is
    proven to be about the missing original and not a blanket refusal."""
    ses = ctx.client("ses")
    _require_receipt_region(ctx)
    clone_name = ctx.unique_name("sim2real-behav-ruleset-badclone-")
    original = ctx.unique_name("sim2real-behav-ruleset-absent-")

    # Break: the original does not exist yet.
    err = _err(
        lambda: ses.clone_receipt_rule_set(
            RuleSetName=clone_name, OriginalRuleSetName=original
        )
    )
    assert err == ("RuleSetDoesNotExist", f"Rule set does not exist: {original}"), (
        f"expected RuleSetDoesNotExist cloning from an absent original, got {err!r}"
    )

    # The clone target must not have been created as a side effect.
    err2 = _err(lambda: ses.describe_receipt_rule_set(RuleSetName=clone_name))
    assert err2 == ("RuleSetDoesNotExist", f"Rule set does not exist: {clone_name}"), (
        f"clone target must not exist after a rejected clone, got {err2!r}"
    )

    # Restore: create the original, then the identical call must now succeed — proving the
    # earlier rejection was about the missing original, not a blanket refusal to clone.
    ses.create_receipt_rule_set(RuleSetName=original)

    def _teardown():
        active_set = (ses.describe_active_receipt_rule_set().get("Metadata") or {}).get("Name")
        if active_set in (clone_name, original):  # never deactivate a set this check did not create
            ses.set_active_receipt_rule_set()
        for name in (clone_name, original):
            try:
                ses.delete_receipt_rule_set(RuleSetName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "RuleSetDoesNotExist":
                    raise

    ctx.on_cleanup(_teardown)

    ses.clone_receipt_rule_set(RuleSetName=clone_name, OriginalRuleSetName=original)

    cloned = ses.describe_receipt_rule_set(RuleSetName=clone_name)
    assert cloned.get("Metadata", {}).get("Name") == clone_name, (
        f"identical clone call after creating the original did not produce the clone: {cloned}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
