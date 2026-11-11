"""op-contract-delete-log-stream."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-log-stream"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteLogStream: success path removes the stream from the group so it no longer
    appears in DescribeLogStreams; error boundary is ResourceNotFoundException for a
    stream that doesn't exist in an existing group."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    stream_name = ctx.unique_name("sim2real-behav-ls-")

    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    resp = logs.describe_log_streams(logGroupName=group_name, logStreamNamePrefix=stream_name)
    assert len(resp["logStreams"]) == 1, f"expected 1 stream after create, got {resp['logStreams']!r}"

    logs.delete_log_stream(logGroupName=group_name, logStreamName=stream_name)

    resp = logs.describe_log_streams(logGroupName=group_name, logStreamNamePrefix=stream_name)
    assert resp["logStreams"] == [], "stream still present after delete"

    error = _expect_error(
        lambda: logs.delete_log_stream(logGroupName=group_name, logStreamName=stream_name)
    )
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error!r}"
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
