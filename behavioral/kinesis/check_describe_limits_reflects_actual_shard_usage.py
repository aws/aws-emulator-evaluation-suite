"""describe-limits-reflects-actual-shard-usage."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-limits-reflects-actual-shard-usage"
GROUP = "server-side"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLimits' OpenShardCount accurately reflects the shards just created, tracked
    server-side (not merely echoed back or computed client-side from the request)."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-limits-")

    open_before = kinesis.describe_limits()["OpenShardCount"]
    _wait_for_shard_capacity(kinesis, needed=1)

    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(lambda: _delete_if_present(kinesis, name))
    _wait_for_stream_active(ctx, name)

    # DescribeLimits is a server-side, account-wide tally (not computed from this request), so
    # it must reflect our +1 shard, but other concurrent activity in the shared account may also
    # move the count -- assert it moved by AT LEAST our contribution and never went backwards.
    after = None
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        after = kinesis.describe_limits()
        if after["OpenShardCount"] >= open_before + 1:
            break
        time.sleep(3.0)
    assert after is not None, "describe_limits() never returned a reading within the poll window"
    assert after["OpenShardCount"] >= open_before + 1, (
        f"expected OpenShardCount to increase by at least 1 (from {open_before}), "
        f"got {after['OpenShardCount']}"
    )

    # deleting our stream must eventually free the shard we added, proving the count is a live
    # server-side tally rather than a client-echoed or monotonic-only value.
    kinesis.delete_stream(StreamName=name)
    freed = None
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        freed = kinesis.describe_limits()["OpenShardCount"]
        if freed <= after["OpenShardCount"] - 1:
            break
        time.sleep(3.0)
    assert freed is not None and freed <= after["OpenShardCount"] - 1, (
        f"expected OpenShardCount to drop by at least 1 after DeleteStream, "
        f"was {after['OpenShardCount']}, still {freed}"
    )


def _wait_for_shard_capacity(kinesis, needed=1, timeout_s=90.0):
    """Poll DescribeLimits until the account has at least `needed` free shards. Other
    checks in this shared account may still be releasing capacity from their own
    just-deleted streams (DeleteStream's effect on OpenShardCount is eventually
    consistent), so a momentary shortfall is not itself a fidelity finding. If the
    shared account is genuinely out of capacity (e.g. a large stream from elsewhere is
    still asynchronously deleting), skip rather than fail -- that is account contention,
    not a fidelity finding about this operation."""
    deadline = time.monotonic() + timeout_s
    limits = None
    while time.monotonic() < deadline:
        limits = kinesis.describe_limits()
        if limits["ShardLimit"] - limits["OpenShardCount"] >= needed:
            return limits
        time.sleep(3.0)
    raise AssertionError(
        f"shared account had no free shard capacity within {timeout_s}s "
        f"(ShardLimit={limits['ShardLimit'] if limits else '?'}, "
        f"OpenShardCount={limits['OpenShardCount'] if limits else '?'}); "
        "likely another large stream elsewhere in the account is still deleting"
    )


def _delete_if_present(kinesis, name):
    from botocore.exceptions import ClientError

    try:
        kinesis.delete_stream(StreamName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_stream_active(ctx, name, timeout_s=180.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3.0)
    raise AssertionError(f"stream {name} did not reach ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
