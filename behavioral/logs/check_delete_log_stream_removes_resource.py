"""delete-log-stream-removes-resource."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-log-stream-removes-resource"
GROUP = 'log-stream-lifecycle'
SERVICES = ['logs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteLogStream removes the stream from DescribeLogStreams, and a second delete
    of the now-gone stream fails with ResourceNotFoundException rather than resurrecting
    it or silently succeeding."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-stream-del-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    resp = svc.describe_log_streams(logGroupName=group, logStreamNamePrefix=stream)
    names = [s["logStreamName"] for s in resp.get("logStreams", [])]
    assert stream in names, f"stream {stream} missing right after create (positive control failed)"

    svc.delete_log_stream(logGroupName=group, logStreamName=stream)

    resp = svc.describe_log_streams(logGroupName=group, logStreamNamePrefix=stream)
    names = [s["logStreamName"] for s in resp.get("logStreams", [])]
    assert stream not in names, f"stream {stream} still present after delete"

    error = _expect_error(lambda: svc.delete_log_stream(logGroupName=group, logStreamName=stream))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"delete of the already-deleted stream expected ResourceNotFoundException, got {error!r}"
    )
    expected_message = "The specified log stream does not exist."
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
