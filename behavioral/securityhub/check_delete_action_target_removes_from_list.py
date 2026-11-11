"""delete-action-target-removes-from-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-action-target-removes-from-list"
GROUP = "state"
SERVICES = ["securityhub"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """DeleteActionTarget removes the action target from the list; a describe for the
    same id afterward comes back empty rather than erroring."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(ctx, sh)
    action_id = _action_id(ctx)
    arn = sh.create_action_target(
        Name="sim2real-del-test", Description="sim2real behavioral delete test", Id=action_id
    )["ActionTargetArn"]
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(sh, arn))

    listed = sh.describe_action_targets(ActionTargetArns=[arn])["ActionTargets"]
    assert len(listed) == 1 and listed[0]["ActionTargetArn"] == arn, f"expected exactly [{arn}], got {listed}"

    sh.delete_action_target(ActionTargetArn=arn)

    remaining = sh.describe_action_targets(ActionTargetArns=[arn]).get("ActionTargets", [])
    assert remaining == [], f"expected the deleted action target to be gone, got {remaining}"

    dup_code, dup_message = _error_code(lambda: sh.delete_action_target(ActionTargetArn=arn))
    assert dup_code == "ResourceNotFoundException", (
        f"expected repeat DeleteActionTarget on the same id to fail with ResourceNotFoundException, got {dup_code!r}"
    )
    expected = f"Given Arn: {arn} does not exist"
    assert dup_message == expected, f"expected message {expected!r}, got {dup_message!r}"

    # The id is reusable once freed.
    reused_arn = sh.create_action_target(
        Name="sim2real-del-test", Description="sim2real behavioral delete test", Id=action_id
    )["ActionTargetArn"]
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(sh, reused_arn))
    assert reused_arn == arn, f"expected the freed id to reuse the same arn, got {reused_arn}"
    relisted = sh.describe_action_targets(ActionTargetArns=[reused_arn])["ActionTargets"]
    assert len(relisted) == 1 and relisted[0]["ActionTargetArn"] == reused_arn, (
        f"expected the recreated action target to list as [{reused_arn}], got {relisted}"
    )


def _action_id(ctx):
    raw = ctx.unique_name("sim2real")
    alnum = "".join(c for c in raw if c.isalnum())
    return alnum[:20]


def _ensure_hub_enabled(ctx, sh):
    """Enable Security Hub for this check. When this call is what turned the hub on, cleanup
    turns it back off, so the account's hub subscription ends in the state it started in."""
    from botocore.exceptions import ClientError

    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise
        return
    ctx.on_cleanup(sh.disable_security_hub)


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _delete_ignoring_not_found(sh, arn):
    from botocore.exceptions import ClientError

    try:
        sh.delete_action_target(ActionTargetArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
