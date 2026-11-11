"""op-contract-untagLogGroup."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-untagLogGroup"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagLogGroup removes only the named keys, is a no-op for an already-absent key, and fails
    with ResourceNotFoundException for a nonexistent log group.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    logs.tag_log_group(
        logGroupName=group_name,
        tags={"Sim2RealOwner": "behavioral-suite", "Sim2RealEnv": "test"},
    )
    tags_before = logs.list_tags_log_group(logGroupName=group_name)["tags"]
    assert tags_before.get("Sim2RealOwner") == "behavioral-suite", tags_before
    assert tags_before.get("Sim2RealEnv") == "test", tags_before

    logs.untag_log_group(logGroupName=group_name, tags=["Sim2RealOwner"])
    tags_after = logs.list_tags_log_group(logGroupName=group_name)["tags"]
    assert "Sim2RealOwner" not in tags_after, tags_after
    assert tags_after.get("Sim2RealEnv") == "test", (
        "untagging one key must not remove unrelated tags"
    )

    # Removing an already-absent tag key is a no-op, not an error.
    logs.untag_log_group(logGroupName=group_name, tags=["Sim2RealOwner"])
    tags_idempotent = logs.list_tags_log_group(logGroupName=group_name)["tags"]
    assert tags_idempotent.get("Sim2RealEnv") == "test", tags_idempotent

    missing_group = ctx.unique_name("sim2real-behav-missing-lg-")
    code, msg = _error(
        lambda: logs.untag_log_group(logGroupName=missing_group, tags=["Sim2RealEnv"])
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert msg == "The specified log group does not exist.", f"got {msg!r}"


def _error(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected ResourceNotFoundException, but call SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
