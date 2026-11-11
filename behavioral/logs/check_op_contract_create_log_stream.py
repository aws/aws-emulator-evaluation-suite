"""op-contract-create-log-stream."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-create-log-stream"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLogStream creates an empty stream visible in DescribeLogStreams; a missing log group
    is ResourceNotFoundException and a duplicate name ResourceAlreadyExistsException, and neither
    rejected attempt leaves a side effect behind."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    stream_name = ctx.unique_name("sim2real-behav-ls-")
    missing_group_name = ctx.unique_name("sim2real-behav-missing-lg-")

    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    resp = logs.describe_log_streams(logGroupName=group_name, logStreamNamePrefix=stream_name)
    streams = resp["logStreams"]
    assert len(streams) == 1, f"expected exactly 1 stream, got {len(streams)}"
    stream = streams[0]
    assert stream["logStreamName"] == stream_name, (
        f"expected stream name {stream_name!r}, got {stream['logStreamName']!r}"
    )
    assert stream.get("storedBytes", 0) == 0, (
        f"expected a freshly created stream to have storedBytes 0, got {stream.get('storedBytes')!r}"
    )
    assert "lastEventTimestamp" not in stream or stream["lastEventTimestamp"] is None, (
        f"expected no lastEventTimestamp on a freshly created stream, got {stream.get('lastEventTimestamp')!r}"
    )
    assert "arn" in stream and group_name in stream["arn"], (
        f"expected stream arn to reference log group {group_name!r}, got {stream.get('arn')!r}"
    )

    code, msg = _error(
        lambda: logs.create_log_stream(
            logGroupName=missing_group_name,
            logStreamName=stream_name,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} {msg!r}"
    assert msg == "The specified log group does not exist.", f"unexpected message: {msg!r}"
    still_missing = logs.describe_log_groups(logGroupNamePrefix=missing_group_name)["logGroups"]
    assert not still_missing, (
        f"expected {missing_group_name!r} to still not exist after a rejected create, "
        f"found {still_missing!r}"
    )

    code, msg = _error(
        lambda: logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)
    )
    assert code == "ResourceAlreadyExistsException", f"expected ResourceAlreadyExistsException, got {code!r} {msg!r}"
    assert msg == "The specified log stream already exists", f"unexpected message: {msg!r}"
    streams_after = logs.describe_log_streams(
        logGroupName=group_name, logStreamNamePrefix=stream_name
    )["logStreams"]
    assert len(streams_after) == 1, (
        f"expected the rejected duplicate create to leave exactly 1 stream, got {len(streams_after)}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
