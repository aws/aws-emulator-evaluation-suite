"""update-stream-mode-transitions-provisioned-to-ondemand."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-stream-mode-transitions-provisioned-to-ondemand"
GROUP = "state-machine"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStreamMode flips capacity mode and DescribeStreamSummary reflects the new mode."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-strm-mode-")
    kinesis.create_stream(
        StreamName=name,
        ShardCount=1,
        StreamModeDetails={"StreamMode": "PROVISIONED"},
        Tags={"sim2real": "ga-depth-kinesis"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))

    stream_arn = _wait_stream_active(ctx, name)
    summary = kinesis.describe_stream_summary(StreamARN=stream_arn)["StreamDescriptionSummary"]
    assert summary["StreamModeDetails"]["StreamMode"] == "PROVISIONED", (
        f"expected freshly created stream mode PROVISIONED, got {summary['StreamModeDetails']}"
    )

    kinesis.update_stream_mode(StreamARN=stream_arn, StreamModeDetails={"StreamMode": "ON_DEMAND"})

    final = _wait_stream_mode(ctx, stream_arn, "ON_DEMAND")
    assert final["StreamStatus"] == "ACTIVE", (
        f"expected stream ACTIVE after UpdateStreamMode settled, got {final['StreamStatus']}"
    )
    assert final["StreamModeDetails"]["StreamMode"] == "ON_DEMAND", (
        f"expected StreamMode ON_DEMAND after UpdateStreamMode, got {final['StreamModeDetails']}"
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
