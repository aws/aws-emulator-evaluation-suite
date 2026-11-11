"""update-stream-mode-while-updating-conflicts."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-stream-mode-while-updating-conflicts"
GROUP = "error-semantics"
SERVICES = ["kinesis"]

_ATTEMPTS = 3


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second UpdateStreamMode fired while the first is still in flight is rejected."""
    kinesis = ctx.client("kinesis")
    # The conflicting change is sent right after the first, inside its in-flight window. A target
    # that finishes the switch before it arrives accepts it, so the leg is re-armed on a fresh
    # stream (a stream switches mode at most twice a day).
    for _ in range(_ATTEMPTS):
        name = ctx.unique_name("sim2real-strm-conflict-")
        kinesis.create_stream(
            StreamName=name, ShardCount=1, StreamModeDetails={"StreamMode": "PROVISIONED"}
        )
        ctx.on_cleanup(
            lambda n=name: kinesis.delete_stream(StreamName=n, EnforceConsumerDeletion=True)
        )
        stream_arn = _wait_stream_active(ctx, name)

        kinesis.update_stream_mode(StreamARN=stream_arn, StreamModeDetails={"StreamMode": "ON_DEMAND"})
        try:
            kinesis.update_stream_mode(
                StreamARN=stream_arn, StreamModeDetails={"StreamMode": "PROVISIONED"}
            )
        except ClientError as exc:
            err = exc.response["Error"]
            refused = (err["Code"], err.get("Message", ""))
            break
        # Accepted: the first switch had already settled; this stream is left settled for teardown.
        _wait_stream_mode(ctx, stream_arn, "PROVISIONED")
    else:
        raise AssertionError(
            f"a second UpdateStreamMode sent right after the first was accepted on each of "
            f"{_ATTEMPTS} streams; it must be refused while the first change is in flight"
        )

    expected = (
        "ResourceInUseException",
        f"Stream {name} under account {ctx.account} not ACTIVE, instead in state UPDATING",
    )
    assert refused == expected, f"expected {expected!r}, got {refused!r}"

    # Effect absent: the stream settles into what the FIRST call requested, not corrupted
    # by the rejected second call.
    settled = _wait_stream_mode(ctx, stream_arn, "ON_DEMAND")
    assert settled["StreamModeDetails"]["StreamMode"] == "ON_DEMAND", (
        f"expected settled mode ON_DEMAND, got {settled['StreamModeDetails']['StreamMode']}"
    )

    # Positive control: once settled, a fresh (non-conflicting) mode change succeeds.
    kinesis.update_stream_mode(StreamARN=stream_arn, StreamModeDetails={"StreamMode": "PROVISIONED"})
    resettled = _wait_stream_mode(ctx, stream_arn, "PROVISIONED")
    assert resettled["StreamModeDetails"]["StreamMode"] == "PROVISIONED", (
        f"expected resettled mode PROVISIONED, got {resettled['StreamModeDetails']['StreamMode']}"
    )


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 120.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)[
            "StreamDescriptionSummary"
        ]
        if summary["StreamStatus"] == "ACTIVE":
            return summary["StreamARN"]
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _wait_stream_mode(ctx, stream_arn: str, expected_mode: str, timeout_s: float = 180.0) -> dict:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamARN=stream_arn)["StreamDescriptionSummary"]
        last = summary
        if (
            summary["StreamStatus"] == "ACTIVE"
            and summary["StreamModeDetails"]["StreamMode"] == expected_mode
        ):
            return summary
        time.sleep(5)
    raise AssertionError(
        f"stream {stream_arn} never settled into ACTIVE/{expected_mode}, last={last}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
