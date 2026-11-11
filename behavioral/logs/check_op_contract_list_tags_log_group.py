"""op-contract-list-tags-log-group."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-tags-log-group"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsLogGroup: success path returns exactly the tags applied via TagLogGroup;
    error boundary is ResourceNotFoundException both for a log group name that was
    never created and for the group this check created and then deleted."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    tags_applied = {"sim2real-behav-owner": "fidelity-suite", "sim2real-behav-env": "test"}

    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: _delete_if_present(logs, group_name))
    logs.tag_log_group(logGroupName=group_name, tags=tags_applied)

    resp = logs.list_tags_log_group(logGroupName=group_name)
    assert resp["tags"] == tags_applied, f"unexpected tags: {resp['tags']}"

    # error boundary: log group name was never created
    code, msg = _error(
        lambda: logs.list_tags_log_group(
            logGroupName=ctx.unique_name("sim2real-behav-missing-lg-")
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} {msg!r}"
    assert msg == "The specified log group does not exist.", f"unexpected message: {msg!r}"

    # error boundary: the group this check itself created and tagged is now gone
    logs.delete_log_group(logGroupName=group_name)
    code, msg = _error(lambda: logs.list_tags_log_group(logGroupName=group_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading tags of a deleted log group, got {code!r} {msg!r}"
    )
    assert msg == "The specified log group does not exist.", f"unexpected message: {msg!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_if_present(logs, group_name) -> None:
    """The check deletes the group itself; teardown tolerates only that not-found."""
    try:
        logs.delete_log_group(logGroupName=group_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
