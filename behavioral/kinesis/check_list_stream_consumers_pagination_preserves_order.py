"""list-stream-consumers-pagination-preserves-order."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-stream-consumers-pagination-preserves-order"
GROUP = "ordering"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListStreamConsumers with NextToken returns every consumer a single unpaginated
    call returns, each exactly once; AWS documents no order, so the order is not compared."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-kinesis-lsc-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    )
    stream_arn = _wait_stream_active(ctx, stream_name)

    # Kinesis admits at most 5 consumers in CREATING per stream, so each is ACTIVE before the next.
    consumer_names = []
    for i in range(6):
        name = ctx.unique_name(f"cons-{i:02d}-")
        kinesis.register_stream_consumer(StreamARN=stream_arn, ConsumerName=name)
        consumer_names.append(name)
        ctx.on_cleanup(
            lambda n=name: kinesis.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName=n)
        )
        _wait_consumer_active_by_name(ctx, stream_arn, name)

    # unpaginated baseline: a single call large enough to return every consumer at once
    baseline = kinesis.list_stream_consumers(StreamARN=stream_arn, MaxResults=100)
    assert "NextToken" not in baseline or not baseline["NextToken"], (
        f"expected the unpaginated baseline to fit in one page, got NextToken={baseline.get('NextToken')!r}"
    )
    baseline_order = [c["ConsumerName"] for c in baseline["Consumers"]]
    assert set(baseline_order) == set(consumer_names), (
        f"baseline call did not return every registered consumer: expected {sorted(consumer_names)}, "
        f"got {sorted(baseline_order)}"
    )

    # paginated walk with a small page size, forcing multiple ListStreamConsumers calls
    paged_order: list[str] = []
    next_token = None
    pages = 0
    while True:
        kwargs = {"StreamARN": stream_arn, "MaxResults": 2}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = kinesis.list_stream_consumers(**kwargs)
        pages += 1
        paged_order.extend(c["ConsumerName"] for c in resp["Consumers"])
        next_token = resp.get("NextToken")
        if not next_token:
            break
        assert pages < 20, "pagination did not terminate within a reasonable number of pages"

    assert pages >= 3, f"expected pagination to span multiple pages, got {pages}"
    assert len(paged_order) == len(set(paged_order)), "pagination returned a duplicated consumer"
    assert set(paged_order) == set(consumer_names), "pagination did not return every registered consumer"


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 180.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(2)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _wait_consumer_active_by_name(ctx, stream_arn: str, consumer_name: str, timeout_s: float = 60.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_consumer(
            StreamARN=stream_arn, ConsumerName=consumer_name
        )["ConsumerDescription"]
        if desc["ConsumerStatus"] == "ACTIVE":
            return
        time.sleep(1)
    raise AssertionError(f"consumer {consumer_name} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
