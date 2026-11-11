"""update-stream-mode-concurrent-conflict-resource-in-use."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stream-mode-concurrent-conflict-resource-in-use"
GROUP = "concurrency"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second UpdateStreamMode issued while the first mode-switch is still applying is
    rejected with ResourceInUseException; the rejected call has no effect (the stream
    settles into the mode requested by the FIRST, accepted call, never the second)."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-usm-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "PROVISIONED"},
        ShardCount=1,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_stream(ctx, name))

    summary = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=120,
        interval_s=2,
    )
    stream_arn = summary["StreamARN"]
    assert summary["StreamModeDetails"]["StreamMode"] == "PROVISIONED", (
        f'expected a freshly-created stream to report StreamMode "PROVISIONED", '
        f'got {summary["StreamModeDetails"]["StreamMode"]!r}'
    )

    # Positive control: the FIRST mode switch is accepted while the stream is ACTIVE.
    kinesis.update_stream_mode(
        StreamARN=stream_arn, StreamModeDetails={"StreamMode": "ON_DEMAND"}
    )

    # Negative: issue a SECOND switch immediately -- no sleep -- while the first switch
    # is still applying (the stream cannot yet have settled back to ACTIVE). This must be
    # rejected rather than racing the first transition to completion.
    code, message = _error_code(
        lambda: kinesis.update_stream_mode(
            StreamARN=stream_arn, StreamModeDetails={"StreamMode": "PROVISIONED"}
        )
    )
    assert code == "ResourceInUseException", (
        f"expected the concurrent UpdateStreamMode to be rejected with "
        f"ResourceInUseException, got {code!r}"
    )
    expected_message = f"Stream {name} under account {ctx.account} not ACTIVE, instead in state UPDATING"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Let the (accepted) first transition settle, then confirm the rejected second call
    # had NO effect: the stream ends up ON_DEMAND (what call #1 asked for), never
    # PROVISIONED (what the rejected call #2 asked for).
    final = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=300,
        interval_s=5,
    )
    assert final["StreamModeDetails"]["StreamMode"] == "ON_DEMAND", (
        f'expected the stream to settle on the FIRST call\'s mode "ON_DEMAND" (never the '
        f'rejected second call\'s "PROVISIONED"), got '
        f'{final["StreamModeDetails"]["StreamMode"]!r}'
    )

    # Restore leg: the rejection above was about the transient conflict, not a permanent
    # block. Once the stream is idle, the IDENTICAL call that was rejected must now succeed.
    kinesis.update_stream_mode(
        StreamARN=stream_arn, StreamModeDetails={"StreamMode": "PROVISIONED"}
    )
    restored = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=300,
        interval_s=5,
    )
    assert restored["StreamModeDetails"]["StreamMode"] == "PROVISIONED", (
        f'expected the previously-rejected switch to PROVISIONED to succeed once the '
        f'stream was idle, got {restored["StreamModeDetails"]["StreamMode"]!r}'
    )


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _delete_stream(ctx, name: str) -> None:
    kinesis = ctx.client("kinesis")
    try:
        kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
