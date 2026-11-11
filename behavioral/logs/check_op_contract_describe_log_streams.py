"""op-contract-describe-log-streams."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-log-streams"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLogStreams lists streams sorted by name; a missing log group gets ResourceNotFoundException
    and logStreamNamePrefix with orderBy=LastEventTime gets InvalidParameterException, each with its
    exact message.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    stream_a = ctx.unique_name("sim2real-behav-ls-a-")
    stream_b = ctx.unique_name("sim2real-behav-ls-b-")

    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_a)
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_b)

    resp = logs.describe_log_streams(logGroupName=group_name, orderBy="LogStreamName")
    names = [s["logStreamName"] for s in resp["logStreams"]]
    assert names == sorted(names), "log streams not ASCII-sorted by name"
    assert stream_a in names and stream_b in names, (
        f"expected both {stream_a!r} and {stream_b!r} in {names!r}"
    )

    # error boundary 1: log group does not exist
    code, message = _expect_error(
        lambda: logs.describe_log_streams(
            logGroupName=ctx.unique_name("sim2real-behav-missing-lg-")
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "The specified log group does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # error boundary 2: logStreamNamePrefix + orderBy=LastEventTime is documented as invalid
    code, message = _expect_error(
        lambda: logs.describe_log_streams(
            logGroupName=group_name,
            orderBy="LastEventTime",
            logStreamNamePrefix=stream_a,
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected = "Cannot order by LastEventTime with a logStreamNamePrefix."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _expect_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
