"""op-contract-delete-retention-policy."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-retention-policy"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRetentionPolicy: success path reverts a log group's retention to "Never
    Expire" (retentionInDays absent from DescribeLogGroups); error boundary is
    ResourceNotFoundException for a log group that does not exist."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")

    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    logs.put_retention_policy(logGroupName=group_name, retentionInDays=1)
    resp = logs.describe_log_groups(logGroupNamePrefix=group_name)
    group = next(g for g in resp["logGroups"] if g["logGroupName"] == group_name)
    assert group.get("retentionInDays") == 1, f"expected retentionInDays=1, got {group.get('retentionInDays')!r}"

    logs.delete_retention_policy(logGroupName=group_name)
    resp = logs.describe_log_groups(logGroupNamePrefix=group_name)
    group = next(g for g in resp["logGroups"] if g["logGroupName"] == group_name)
    assert "retentionInDays" not in group, (
        f"expected Never Expire after DeleteRetentionPolicy, got retentionInDays={group.get('retentionInDays')!r}"
    )

    # error boundary: log group does not exist
    error = _expect_error(
        lambda: logs.delete_retention_policy(
            logGroupName=ctx.unique_name("sim2real-behav-missing-lg-")
        )
    )
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error!r}"
    )
    expected_message = "The specified log group does not exist."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


def _expect_error(fn):
    """Call fn(); return the botocore Error dict. Raises if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
