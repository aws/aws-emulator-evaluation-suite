"""receipt-rule-create-after-nonexistent-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-rule-create-after-nonexistent-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise if it succeeds."""
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
    """CreateReceiptRule with a nonexistent 'After' rule fails with RuleDoesNotExist and inserts
    nothing, while 'After' naming an existing rule succeeds, so the refusal is specific."""
    ses = ctx.client("ses")
    _require_receipt_region(ctx)
    set_name = ctx.unique_name("sim2real-behav-ruleset-after-")
    ses.create_receipt_rule_set(RuleSetName=set_name)
    _track_receipt_rule_set(ctx, ses, set_name)

    err, msg = _err(
        lambda: ses.create_receipt_rule(
            RuleSetName=set_name,
            Rule={
                "Name": ctx.unique_name("rule-"),
                "Enabled": True,
                "Actions": [{"StopAction": {"Scope": "RuleSet"}}],
            },
            After="does-not-exist-rule",
        )
    )
    assert err == "RuleDoesNotExist", (
        f"expected RuleDoesNotExist for a non-existent After rule, got {err!r}: {msg!r}"
    )
    expected_msg = "Rule does not exist: does-not-exist-rule"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    assert ses.describe_receipt_rule_set(RuleSetName=set_name)["Rules"] == [], (
        "a rejected CreateReceiptRule must not have inserted a rule"
    )

    first_name = ctx.unique_name("rule-first-")
    ses.create_receipt_rule(
        RuleSetName=set_name,
        Rule={
            "Name": first_name,
            "Enabled": True,
            "Actions": [{"StopAction": {"Scope": "RuleSet"}}],
        },
    )
    second_name = ctx.unique_name("rule-second-")
    ses.create_receipt_rule(
        RuleSetName=set_name,
        Rule={
            "Name": second_name,
            "Enabled": True,
            "Actions": [{"StopAction": {"Scope": "RuleSet"}}],
        },
        After=first_name,
    )
    names = [r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=set_name)["Rules"]]
    assert names == [first_name, second_name], (
        f"positive-control CreateReceiptRule with a real After reference did not take effect, got {names}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
