"""tag-nonexistent-log-group-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_log_group(logs, name) -> None:
    """Delete the log group; one already gone is fine, any other error raises."""
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


CHECK = "tag-nonexistent-log-group-fails"
GROUP = 'tagging'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagLogGroup on a nonexistent log group is rejected, not silently accepted; the identical
    call succeeds once the name is a real group.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-tag-missing-")
    ctx.on_cleanup(lambda: _delete_log_group(svc, group))

    # Positive control: the group exists and tagging it works.
    svc.create_log_group(logGroupName=group)
    svc.tag_log_group(logGroupName=group, tags={"env": "before"})
    before = svc.list_tags_log_group(logGroupName=group).get("tags", {})
    assert before.get("env") == "before", f"positive control failed to tag an existing log group: {before}"

    # Break exactly one thing: remove the group out from under its own name.
    svc.delete_log_group(logGroupName=group)

    code, msg = _error(lambda: svc.tag_log_group(logGroupName=group, tags={"env": "after"}))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException tagging a non-existent log group, got {code!r}"
    assert msg == "The specified log group does not exist.", f"got {msg!r}"

    list_code, list_msg = _error(lambda: svc.list_tags_log_group(logGroupName=group))
    assert list_code == "ResourceNotFoundException", f"expected ResourceNotFoundException listing tags for a non-existent log group, got {list_code!r}"
    assert list_msg == "The specified log group does not exist.", f"got {list_msg!r}"

    # Restore: recreate the identical name and the identical call now succeeds.
    svc.create_log_group(logGroupName=group)
    svc.tag_log_group(logGroupName=group, tags={"env": "after"})
    after = svc.list_tags_log_group(logGroupName=group).get("tags", {})
    assert after.get("env") == "after", f"expected the tag to stick once the log group exists again, got {after}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
