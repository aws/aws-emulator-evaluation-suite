"""create-on-demand-stream-with-shard-count-must-fail."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _refusal(fn):
    """Call fn(); return its error code and message. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")

def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")

def _wait_stream_active(c, name, timeout_s=150, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )

CHECK = "create-on-demand-stream-with-shard-count-must-fail"
GROUP = 'overly-permissive'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStream with both ShardCount and ON_DEMAND mode is rejected with the exact
    InvalidArgumentException and leaves no stream (DescribeStreamSummary: not found), while a plain
    on-demand CreateStream succeeds."""
    c = ctx.client("kinesis")
    control_name = ctx.unique_name("sim2real-behav-kds-baddemand-ctl-")
    bad_name = ctx.unique_name("sim2real-behav-kds-baddemand-")

    _create_stream_with_retry(c, control_name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=control_name, EnforceConsumerDeletion=True))
    _wait_stream_active(c, control_name)

    # Guarded cleanup in case the stream is wrongly created despite the error.
    def _safe_delete():
        try:
            c.delete_stream(StreamName=bad_name, EnforceConsumerDeletion=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    ctx.on_cleanup(_safe_delete)

    code, message = _refusal(lambda: c.create_stream(
        StreamName=bad_name,
        ShardCount=1,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
    ))
    assert code == "InvalidArgumentException", (
        f"expected InvalidArgumentException, got {code}"
    )
    expected = "ShardCount cannot be set while creating stream in On-Demand StreamMode"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    absent_code, absent_message = _refusal(lambda: c.describe_stream_summary(StreamName=bad_name))
    assert absent_code == "ResourceNotFoundException", (
        f"rejected CreateStream must leave no stream behind; DescribeStreamSummary got {absent_code}"
    )
    expected_absent = f"Stream {bad_name} under account {ctx.account} not found."
    assert absent_message == expected_absent, (
        f"expected message {expected_absent!r}, got {absent_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
