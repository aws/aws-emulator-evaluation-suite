"""delete-log-stream-nonexistent-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _expect_error(fn):
    """Call fn(); return the botocore Error dict. Raises if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")

CHECK = "delete-log-stream-nonexistent-fails"
GROUP = 'log-stream-lifecycle'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLogStream rejects a stream name that was never created in an existing group.
    A positive control in the same group proves DeleteLogStream and the account are otherwise
    healthy, and that a stream it already removed cannot be deleted a second time."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-stream-del2-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))

    control = ctx.unique_name("sim2real-behav-stream-control-")
    svc.create_log_stream(logGroupName=group, logStreamName=control)
    svc.delete_log_stream(logGroupName=group, logStreamName=control)
    resp = svc.describe_log_streams(logGroupName=group, logStreamNamePrefix=control)
    names = [s["logStreamName"] for s in resp.get("logStreams", [])]
    assert control not in names, f"positive control {control} still present after delete"

    expected_message = "The specified log stream does not exist."
    error = _expect_error(lambda: svc.delete_log_stream(logGroupName=group, logStreamName=control))
    assert error.get("Code") == "ResourceNotFoundException", f"redelete of removed stream: expected ResourceNotFoundException, got {error!r}"
    assert error.get("Message") == expected_message, f"redelete of removed stream: expected message {expected_message!r}, got {error.get('Message')!r}"

    stream = ctx.unique_name("sim2real-behav-stream-missing-")
    error = _expect_error(lambda: svc.delete_log_stream(logGroupName=group, logStreamName=stream))
    assert error.get("Code") == "ResourceNotFoundException", f"never-created stream: expected ResourceNotFoundException, got {error!r}"
    assert error.get("Message") == expected_message, f"never-created stream: expected message {expected_message!r}, got {error.get('Message')!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
