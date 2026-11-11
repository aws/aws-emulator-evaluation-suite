"""tag-log-group-reserved-aws-prefix-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-log-group-reserved-aws-prefix-rejected"
GROUP = 'overly-permissive'
SERVICES = ['logs']

def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_log_group(ctx, logs, name=None, **kwargs) -> str:
    name = name or ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_log_group(logs, name))
    return name


def _delete_log_group(logs, name) -> None:
    """Drop deletion protection (if any) before deleting, mirroring the suite's teardown."""
    try:
        logs.put_log_group_deletion_protection(
            logGroupIdentifier=name, deletionProtectionEnabled=False
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    logs.delete_log_group(logGroupName=name)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: tag keys using the reserved 'aws:' prefix must be rejected."""
    logs = ctx.client("logs")
    group = _create_log_group(ctx, logs)

    # Positive control: an ordinary tag key succeeds and is retrievable, so a later
    # rejection can only mean the reserved prefix was the cause, not that TagLogGroup
    # is broken or unreachable for this log group.
    logs.tag_log_group(logGroupName=group, tags={"team": "sim2real"})
    tags_after_control = logs.list_tags_log_group(logGroupName=group).get("tags", {})
    assert tags_after_control.get("team") == "sim2real", (
        f"positive control failed: expected 'team' tag to be set, got {tags_after_control}"
    )

    code, msg = _error(
        lambda: logs.tag_log_group(logGroupName=group, tags={"aws:reserved": "nope"})
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert msg == "Tags starting with 'AWS:' are reserved for AWS use.", f"got {msg!r}"

    tags = logs.list_tags_log_group(logGroupName=group).get("tags", {})
    assert "aws:reserved" not in tags, f"reserved tag key leaked into state: {tags}"
    assert tags.get("team") == "sim2real", (
        f"rejected call must leave the pre-existing tag untouched, got {tags}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
