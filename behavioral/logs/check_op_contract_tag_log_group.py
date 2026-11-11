"""op-contract-tagLogGroup."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-tagLogGroup"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagLogGroup adds tags that ListTagsLogGroup returns merged with the existing ones; listing or
    tagging a deleted group and tagging a never-created one get ResourceNotFoundException and its message.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: _delete_if_present(logs, group_name))

    logs.tag_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    tags_now = logs.list_tags_log_group(logGroupName=group_name)["tags"]
    assert tags_now.get("Sim2RealOwner") == "behavioral-suite", tags_now

    # A second TagLogGroup call adds a tag without dropping the first (merge semantics).
    logs.tag_log_group(logGroupName=group_name, tags={"Sim2RealEnv": "test"})
    tags_after = logs.list_tags_log_group(logGroupName=group_name)["tags"]
    assert tags_after.get("Sim2RealOwner") == "behavioral-suite", tags_after
    assert tags_after.get("Sim2RealEnv") == "test", tags_after

    # Deletes prove gone and unusable: an independent read shows the group we
    # tagged is gone, and a further TagLogGroup on the same deleted id also fails.
    logs.delete_log_group(logGroupName=group_name)
    code, msg = _error(lambda: logs.list_tags_log_group(logGroupName=group_name))
    assert code == "ResourceNotFoundException", (
        f"expected deleted group to read as gone, got {code!r} {msg!r}"
    )
    assert msg == "The specified log group does not exist.", f"unexpected message: {msg!r}"
    code, msg = _error(
        lambda: logs.tag_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "x"})
    )
    assert code == "ResourceNotFoundException", (
        f"expected TagLogGroup on deleted group to fail, got {code!r} {msg!r}"
    )
    assert msg == "The specified log group does not exist.", f"unexpected message: {msg!r}"

    # Distinct error boundary: log group that was never created.
    missing_group = ctx.unique_name("sim2real-behav-missing-lg-")
    code, msg = _error(
        lambda: logs.tag_log_group(logGroupName=missing_group, tags={"Sim2RealOwner": "x"})
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} {msg!r}"
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
    try:
        logs.delete_log_group(logGroupName=group_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
