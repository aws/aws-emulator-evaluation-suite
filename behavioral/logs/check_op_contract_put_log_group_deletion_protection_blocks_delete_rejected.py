"""op-contract-put-log-group-deletion-protection-blocks-delete-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-put-log-group-deletion-protection-blocks-delete-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """While deletion protection is enabled DeleteLogGroup is rejected with
    InvalidParameterException and the group survives; once disabled the delete succeeds, and
    PutLogGroupDeletionProtection on a missing or deleted group is ResourceNotFoundException."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")

    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: _force_delete(logs, group_name))

    def _described():
        resp = logs.describe_log_groups(logGroupNamePrefix=group_name)
        return next((g for g in resp["logGroups"] if g["logGroupName"] == group_name), None)

    def _current_flag() -> bool:
        group = _described()
        assert group is not None, f"{group_name} not found via independent read"
        return bool(group.get("deletionProtectionEnabled", False))

    assert _current_flag() is False, "deletion protection should default to disabled"

    logs.put_log_group_deletion_protection(
        logGroupIdentifier=group_name, deletionProtectionEnabled=True
    )
    assert _current_flag() is True, "deletionProtectionEnabled did not flip to true"

    code, message = _client_error(lambda: logs.delete_log_group(logGroupName=group_name))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == (
        "LogGroup has delete protection enabled. Disable delete protection before attempting to "
        "delete the resource."
    ), f"unexpected message: {message!r}"

    assert _described() is not None, (
        f"{group_name} disappeared despite the delete being rejected"
    )

    code, message = _client_error(
        lambda: logs.put_log_group_deletion_protection(
            logGroupIdentifier=ctx.unique_name("sim2real-behav-missing-lg-"),
            deletionProtectionEnabled=True,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "The specified log group does not exist.", f"unexpected message: {message!r}"

    logs.put_log_group_deletion_protection(
        logGroupIdentifier=group_name, deletionProtectionEnabled=False
    )
    assert _current_flag() is False, "deletionProtectionEnabled did not flip back to false"
    logs.delete_log_group(logGroupName=group_name)

    assert _described() is None, f"{group_name} still present after delete"
    dead_code, dead_message = _client_error(
        lambda: logs.put_log_group_deletion_protection(
            logGroupIdentifier=group_name, deletionProtectionEnabled=True
        )
    )
    assert dead_code == "ResourceNotFoundException", (
        f"expected a mutation against the deleted group to fail with "
        f"ResourceNotFoundException, got {dead_code}"
    )
    assert dead_message == "The specified log group does not exist.", f"unexpected message: {dead_message!r}"


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _force_delete(logs, group_name):
    try:
        logs.put_log_group_deletion_protection(
            logGroupIdentifier=group_name, deletionProtectionEnabled=False
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        logs.delete_log_group(logGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
