"""create-time-protection-blocks-delete-until-cleared-by-arn."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code, message):
    """Call fn(); assert it raises exactly (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected ({code!r}, {message!r}), but the call succeeded: {result!r}")


CHECK = "create-time-protection-blocks-delete-until-cleared-by-arn"
GROUP = "deletion-protection"
SERVICES = ["logs"]

_PROTECTED_DELETE_REFUSED = (
    "InvalidParameterException",
    "LogGroup has delete protection enabled. "
    "Disable delete protection before attempting to delete the resource.",
)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CreateLogGroup's deletionProtectionEnabled flag reports true in DescribeLogGroups and
    blocks DeleteLogGroup until PutLogGroupDeletionProtection(false), addressed by the group's
    bare ARN (no trailing ":*"), clears it; a sibling without the flag deletes immediately.
    """
    logs = ctx.client("logs")
    base = ctx.unique_name("sim2real-behav-lg-dp-")
    protected = base
    control = base + "-ctl"

    logs.create_log_group(logGroupName=protected, deletionProtectionEnabled=True)
    ctx.on_cleanup(
        _teardown(lambda: logs.delete_log_group(logGroupName=protected), "ResourceNotFoundException")
    )
    ctx.on_cleanup(
        _teardown(
            lambda: logs.put_log_group_deletion_protection(
                logGroupIdentifier=protected, deletionProtectionEnabled=False
            ),
            "ResourceNotFoundException",
        )
    )

    logs.create_log_group(logGroupName=control)
    ctx.on_cleanup(
        _teardown(lambda: logs.delete_log_group(logGroupName=control), "ResourceNotFoundException")
    )

    def _listed():
        groups = logs.describe_log_groups(logGroupNamePrefix=base)["logGroups"]
        return {g["logGroupName"]: g for g in groups}

    listed = _listed()
    assert listed.get(protected, {}).get("deletionProtectionEnabled") is True, listed.get(protected)
    assert listed.get(control, {}).get("deletionProtectionEnabled") is False, listed.get(control)
    arn = listed[protected]["arn"]
    assert arn.endswith(":*"), f"expected the log group ARN to end with ':*', got {arn!r}"

    expect_error(lambda: logs.delete_log_group(logGroupName=protected), *_PROTECTED_DELETE_REFUSED)

    # List-proven survival: the refused delete did not remove the protected group.
    listed = _listed()
    assert protected in listed, f"{protected} disappeared despite the delete being rejected"

    # Positive control: the sibling with no protection deletes immediately.
    logs.delete_log_group(logGroupName=control)
    listed = _listed()
    assert control not in listed, f"{control} still listed after an unblocked delete"
    assert protected in listed, f"{protected} vanished while only {control} was deleted"

    # Disable protection addressed by the bare ARN (without the trailing ":*").
    bare_arn = arn[: -len(":*")]
    logs.put_log_group_deletion_protection(logGroupIdentifier=bare_arn, deletionProtectionEnabled=False)
    listed = _listed()
    assert listed.get(protected, {}).get("deletionProtectionEnabled") is False, listed.get(protected)

    logs.delete_log_group(logGroupName=protected)

    # List-proven removal: the same previously-refused delete now succeeds and the group is gone.
    listed = _listed()
    assert protected not in listed, f"{protected} still listed after delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
