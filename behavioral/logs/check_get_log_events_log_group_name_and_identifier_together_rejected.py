"""get-log-events-log-group-name-and-identifier-together-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-log-events-log-group-name-and-identifier-together-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetLogEvents rejects a request naming both logGroupName and logGroupIdentifier with
    ValidationException and its exact message, while naming only one still reads the stream.
    """
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-bothid-")
    stream = "control-stream"

    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)
    # DescribeLogGroups' arn carries a trailing ":*" that logGroupIdentifier's own pattern
    # (no "*") refuses, so the identifier form is the arn with that suffix removed.
    raw_arn = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0]["arn"]
    group_arn = raw_arn[:-2] if raw_arn.endswith(":*") else raw_arn

    now_ms = int(time.time() * 1000)
    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": now_ms, "message": "control-event"}],
    )

    code, message = _error(
        lambda: logs.get_log_events(
            logGroupName=group,
            logGroupIdentifier=group_arn,
            logStreamName=stream,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "LogGroup name and LogGroup ARN are mutually exclusive parameters.", (
        f"unexpected message: {message!r}"
    )

    # Positive control: naming only logGroupIdentifier for the same stream still reads it.
    events = _poll_until(
        lambda: logs.get_log_events(
            logGroupIdentifier=group_arn, logStreamName=stream, startFromHead=True
        )["events"],
        lambda evs: len(evs) == 1,
        timeout_s=30.0,
        interval_s=1.0,
    )
    assert events[0]["message"] == "control-event", (
        f"expected the one control event to read back, got {events!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects logGroupName+logGroupIdentifier together, but it SUCCEEDED and "
        f"returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
