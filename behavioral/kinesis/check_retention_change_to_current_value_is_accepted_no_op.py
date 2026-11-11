"""retention-change-to-current-value-is-accepted-no-op."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retention-change-to-current-value-is-accepted-no-op"
GROUP = "retention"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Retention changes naming a stream's current 24 hours are accepted as no-ops.

    Both Increase and DecreaseStreamRetentionPeriod succeed, and the stream is ACTIVE at 24 after each.
    """
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-kds-sameret-")
    kinesis.create_stream(StreamName=name, ShardCount=1, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))

    def summary():
        return kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]

    def wait_active():
        deadline = time.monotonic() + min(120.0, ctx.time_left())
        while True:
            current = summary()
            if current["StreamStatus"] == "ACTIVE" or time.monotonic() >= deadline:
                return current
            time.sleep(3)

    def call_settled(fn):
        """Call ``fn``, retrying only while the stream still reports ResourceInUseException."""
        deadline = time.monotonic() + min(60.0, ctx.time_left())
        while True:
            try:
                return fn()
            except ClientError as exc:
                if (
                    exc.response["Error"]["Code"] != "ResourceInUseException"
                    or time.monotonic() >= deadline
                ):
                    raise
                time.sleep(3)

    def state():
        current = wait_active()
        return current["StreamStatus"], current["RetentionPeriodHours"]

    initial = state()
    assert initial == ("ACTIVE", 24), f"a new stream reads {initial!r}"

    call_settled(
        lambda: kinesis.increase_stream_retention_period(StreamName=name, RetentionPeriodHours=24)
    )
    after_increase = state()
    assert after_increase == ("ACTIVE", 24), (
        f"after IncreaseStreamRetentionPeriod(24) the stream reads {after_increase!r}"
    )

    call_settled(
        lambda: kinesis.decrease_stream_retention_period(StreamName=name, RetentionPeriodHours=24)
    )
    after_decrease = state()
    assert after_decrease == ("ACTIVE", 24), (
        f"after DecreaseStreamRetentionPeriod(24) the stream reads {after_decrease!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
