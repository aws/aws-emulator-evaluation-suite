"""receipt-rule-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-rule-duplicate-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises. An
    unexpected SUCCESS raises."""
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ses-active-receipt-rule-set")
def run(ctx) -> None:
    """Two rules with the same name in one rule set must be refused with AlreadyExists."""
    ses = ctx.client("ses")
    _require_receipt_region(ctx)
    set_name = ctx.unique_name("sim2real-behav-ruleset-dupname-")
    ses.create_receipt_rule_set(RuleSetName=set_name)
    _track_receipt_rule_set(ctx, ses, set_name)

    rule_name = ctx.unique_name("rule-")
    ses.create_receipt_rule(
        RuleSetName=set_name,
        Rule={
            "Name": rule_name,
            "Enabled": True,
            "Actions": [{"StopAction": {"Scope": "RuleSet"}}],
        },
    )
    err, msg = _err(
        lambda: ses.create_receipt_rule(
            RuleSetName=set_name,
            Rule={
                "Name": rule_name,
                "Enabled": True,
                "Actions": [{"StopAction": {"Scope": "RuleSet"}}],
            },
        )
    )
    assert err == "AlreadyExists", (
        f"expected AlreadyExists for a duplicate rule name, got {err!r}: {msg!r}"
    )
    expected_msg = f"Rule already exists: {rule_name}"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"
    assert len(ses.describe_receipt_rule_set(RuleSetName=set_name)["Rules"]) == 1, (
        "a rejected duplicate rule must not have been added"
    )

    # Restore leg: the name is taken by *state*, not malformed by construction — free it
    # and demand the identical call now succeeds.
    ses.delete_receipt_rule(RuleSetName=set_name, RuleName=rule_name)
    ses.create_receipt_rule(
        RuleSetName=set_name,
        Rule={
            "Name": rule_name,
            "Enabled": True,
            "Actions": [{"StopAction": {"Scope": "RuleSet"}}],
        },
    )
    names_after_restore = [
        r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=set_name)["Rules"]
    ]
    assert names_after_restore == [rule_name], (
        f"after freeing the name, the identical create call must succeed, got rules {names_after_restore!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
