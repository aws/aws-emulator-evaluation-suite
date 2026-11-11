"""create-action-target-duplicate-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-action-target-duplicate-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["securityhub"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """CreateActionTarget with an Id that already exists is rejected with ResourceConflictException."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(sh)
    action_id = _action_id(ctx, "dup")
    arn = sh.create_action_target(
        Name="sim2real-dup-orig", Description="sim2real behavioral fidelity test action target", Id=action_id
    )["ActionTargetArn"]
    ctx.on_cleanup(lambda: sh.delete_action_target(ActionTargetArn=arn))

    code, message = _error(
        lambda: sh.create_action_target(Name="sim2real-dup-attempt", Description="duplicate attempt", Id=action_id)
    )
    assert code == "ResourceConflictException", f"expected ResourceConflictException, got {code}"
    expected = f"Action with Id: {action_id} already exists"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: still exactly one action target for this Id.
    listed = sh.describe_action_targets(ActionTargetArns=[arn])["ActionTargets"]
    assert len(listed) == 1, f"expected exactly one action target for {action_id!r}, got {listed}"
    assert listed[0]["Name"] == "sim2real-dup-orig", f"expected the original Name to survive, got {listed[0]['Name']!r}"

    # Positive control: a distinct Id still succeeds, and is independently visible.
    other_id = _action_id(ctx, "ctl")
    other_arn = sh.create_action_target(
        Name="sim2real-dup-ctl", Description="sim2real behavioral fidelity test action target 2",
        Id=other_id,
    )["ActionTargetArn"]
    ctx.on_cleanup(lambda: sh.delete_action_target(ActionTargetArn=other_arn))
    assert other_arn != arn, f"expected a distinct ActionTargetArn, got the same one {other_arn!r}"

    listed_other = sh.describe_action_targets(ActionTargetArns=[other_arn])["ActionTargets"]
    assert len(listed_other) == 1 and listed_other[0]["Name"] == "sim2real-dup-ctl", (
        f"expected the distinct-Id action target to be independently visible, got {listed_other}"
    )


def _action_id(ctx, tag):
    # CreateActionTarget's Id must be at most 20 alphanumeric characters.
    # "sim2real" (8) + 12 hex fills the 20-char limit exactly, so `tag` cannot be embedded.
    raw = ctx.unique_name("sim2real")
    alnum = "".join(c for c in raw if c.isalnum())
    return alnum[:20]


def _ensure_hub_enabled(sh):
    from botocore.exceptions import ClientError

    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
