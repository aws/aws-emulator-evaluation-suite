"""deletion-protected-log-group-delete-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deletion-protected-log-group-delete-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutLogGroupDeletionProtection(true) blocks DeleteLogGroup with a state
    conflict; disabling protection again allows the deletion to proceed."""
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-behav-delprot-")
    # Create the log group first, then explicitly enable deletion protection
    # via PutLogGroupDeletionProtection. Passing deletionProtectionEnabled=True
    # directly to CreateLogGroup looks like it should avoid a create-then-enable
    # race, but on real AWS that inline flag does not reliably wire into the
    # same enforcement path that DeleteLogGroup checks -- DeleteLogGroup can
    # still succeed even though DescribeLogGroups reports the flag as enabled.
    # Going through the dedicated PutLogGroupDeletionProtection call (the
    # documented way to toggle this setting) and then polling for it to be
    # visible is the reliable way to get enforcement to actually engage.
    logs.create_log_group(logGroupName=log_group_name)
    logs.put_log_group_deletion_protection(
        logGroupIdentifier=log_group_name, deletionProtectionEnabled=True
    )

    def _cleanup():
        # Turn protection off so cleanup can delete the log group even if the body failed
        # early. Only an already-gone group is tolerated; every other error raises.
        from botocore.exceptions import ClientError

        try:
            logs.put_log_group_deletion_protection(
                logGroupIdentifier=log_group_name, deletionProtectionEnabled=False
            )
            logs.delete_log_group(logGroupName=log_group_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # Real AWS can take a short time to propagate the deletion-protection flag
    # to the enforcement path that DeleteLogGroup checks. Poll DescribeLogGroups
    # until the flag is actually visible before attempting the delete, so we
    # don't race ahead of enforcement and accidentally delete the log group
    # before protection is active.
    _poll_until(
        lambda: logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"],
        lambda groups: any(
            g["logGroupName"] == log_group_name and g.get("deletionProtectionEnabled")
            for g in groups
        ),
        interval_s=2.0,
    )

    # DeleteLogGroup's documented error set for this API is
    # InvalidParameterException, OperationAbortedException,
    # ResourceNotFoundException, and ServiceUnavailableException. On real
    # AWS, the state-based rejection it actually raises when deletion
    # protection is enabled is InvalidParameterException (not
    # OperationAbortedException).
    refused = _expect_error(lambda: logs.delete_log_group(logGroupName=log_group_name),
                            ("InvalidParameterException",))
    expected_message = "LogGroup has delete protection enabled. Disable delete protection before attempting to delete the resource."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'

    # The log group must still exist -- the rejected delete must not have
    # partially applied.
    described = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
    assert any(g["logGroupName"] == log_group_name for g in described["logGroups"]), (
        "log group disappeared despite the delete being rejected"
    )

    logs.put_log_group_deletion_protection(
        logGroupIdentifier=log_group_name, deletionProtectionEnabled=False
    )
    logs.delete_log_group(logGroupName=log_group_name)

    described_after = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
    assert not any(g["logGroupName"] == log_group_name for g in described_after["logGroups"]), (
        "log group still present after protection was disabled and delete retried"
    )
    # Gone: a read of the deleted group is refused, and so is creating a stream in it.
    refused = _expect_error(lambda: logs.describe_log_streams(logGroupName=log_group_name),
                            ("ResourceNotFoundException",))
    expected_message = "The specified log group does not exist."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'
    refused = _expect_error(lambda: logs.create_log_stream(logGroupName=log_group_name,
                                                           logStreamName="sim2real-after-delete"),
                            ("ResourceNotFoundException",))
    expected_message = "The specified log group does not exist."
    assert refused.response["Error"].get("Message") == expected_message, f'expected the message {expected_message!r}, got {refused.response["Error"].get("Message")!r}'


def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status, the exact message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    assert msg.strip(), f"expected the exact message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


def _poll_until(probe, predicate, *, timeout_s=POLL_BUDGET_S, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
