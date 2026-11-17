"""describe-log-streams-nexttoken-from-other-group-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-log-streams-nexttoken-from-other-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]

_CROSS_GROUP_TOKEN = (
    "InvalidParameterException",
    "Pagination token in request is invalid. Only token from previous list call or null is valid.",
)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code: str, message: str) -> None:
    """Call fn(); assert it raises exactly (code, message). An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == code, (
            f"expected error code {code!r}, got {err.get('Code')!r} ({err.get('Message')!r})"
        )
        assert err.get("Message") == message, (
            f"expected message {message!r}, got {err.get('Message')!r}"
        )
        return
    raise AssertionError(f"expected the call to be rejected with {code!r}, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A DescribeLogStreams nextToken minted for one log group is refused for another;
    the same token keeps working against the log group it was minted for.
    """
    logs = ctx.client("logs")
    group_a = ctx.unique_name("sim2real-behav-lg-tok-a-")
    logs.create_log_group(logGroupName=group_a)
    ctx.on_cleanup(_teardown(
        lambda: logs.delete_log_group(logGroupName=group_a), "ResourceNotFoundException"
    ))
    group_b = ctx.unique_name("sim2real-behav-lg-tok-b-")
    logs.create_log_group(logGroupName=group_b)
    ctx.on_cleanup(_teardown(
        lambda: logs.delete_log_group(logGroupName=group_b), "ResourceNotFoundException"
    ))

    stream_1 = ctx.unique_name("sim2real-behav-ls-1-")
    stream_2 = ctx.unique_name("sim2real-behav-ls-2-")
    logs.create_log_stream(logGroupName=group_a, logStreamName=stream_1)
    logs.create_log_stream(logGroupName=group_a, logStreamName=stream_2)

    page1 = logs.describe_log_streams(logGroupName=group_a, limit=1)
    assert len(page1["logStreams"]) == 1, page1["logStreams"]
    token = page1.get("nextToken")
    assert token, f"expected a nextToken with a second stream remaining, got {token!r}"

    # Positive control: the token is valid when replayed against the group it came from.
    control = logs.describe_log_streams(logGroupName=group_a, limit=1, nextToken=token)
    assert len(control["logStreams"]) == 1, control["logStreams"]
    assert control["logStreams"][0]["logStreamName"] == stream_2, control["logStreams"]

    expect_error(
        lambda: logs.describe_log_streams(logGroupName=group_b, limit=1, nextToken=token),
        *_CROSS_GROUP_TOKEN,
    )

    group_b_streams = logs.describe_log_streams(logGroupName=group_b).get("logStreams", [])
    assert group_b_streams == [], f"group_b unexpectedly holds streams: {group_b_streams}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
