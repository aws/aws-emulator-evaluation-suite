"""concurrent-consumable-resource-quantity-decrement."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-consumable-resource-quantity-decrement"
GROUP = "concurrency"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """15 concurrent UpdateConsumableResource REMOVE calls on one consumable resource all succeed,
    and its final totalQuantity is exactly the start minus the sum removed, so no concurrent
    decrement is lost."""
    batch = ctx.client("batch")

    name = ctx.unique_name("sim2real-batch-cr-")
    start_quantity = 1000
    batch.create_consumable_resource(
        consumableResourceName=name,
        resourceType="NON_REPLENISHABLE",
        totalQuantity=start_quantity,
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _try_delete_consumable_resource(ctx, name))

    describe = _poll_until(
        lambda: batch.describe_consumable_resource(consumableResource=name),
        lambda d: d.get("totalQuantity") == start_quantity,
        timeout_s=60,
        interval_s=3,
    )
    assert describe["totalQuantity"] == start_quantity, (
        f"expected freshly-created resource totalQuantity {start_quantity}, "
        f"got {describe['totalQuantity']!r}"
    )

    def _decrement(i: int) -> str:
        # UpdateConsumableResource is not gated on current availability, so every call is
        # expected to succeed. Retry (bounded, jittered) only on genuinely transient
        # throttling -- any other error is a real, unexpected failure and is returned as-is.
        last_code = None
        for attempt in range(10):
            try:
                batch.update_consumable_resource(consumableResource=name, operation="REMOVE", quantity=1)
                return "ok"
            except ClientError as e:
                last_code = e.response["Error"]["Code"]
                if last_code not in ("TooManyRequestsException", "ThrottlingException"):
                    return last_code
                time.sleep(0.2 + 0.1 * (i % 5))
        return last_code

    with ThreadPoolExecutor(max_workers=15) as pool:
        results = list(pool.map(_decrement, range(15)))

    successes = [r for r in results if r == "ok"]
    failures = [r for r in results if r != "ok"]

    # UpdateConsumableResource performs no admission check against current quantity, so
    # every one of the 15 concurrent racers must succeed -- there is no "capacity" to be
    # rejected against. The property under test is that the concurrent decrements are
    # correctly serialized: none of them is lost to a race, so the resource's remaining
    # quantity is exactly consistent with how many decrements actually succeeded.
    assert len(failures) == 0, (
        f"expected all 15 concurrent decrements to succeed (UpdateConsumableResource is not "
        f"gated on current availability), but got failures: {failures}"
    )
    assert len(successes) == 15, f"expected 15 successful decrements, got: {results}"

    final = _poll_until(
        lambda: batch.describe_consumable_resource(consumableResource=name),
        lambda d: d.get("totalQuantity") == start_quantity - len(successes),
        timeout_s=30,
        interval_s=2,
    )
    assert final["totalQuantity"] == start_quantity - len(successes), (
        f"totalQuantity ({final['totalQuantity']}) inconsistent with "
        f"{len(successes)} successful concurrent decrements out of a starting quantity of "
        f"{start_quantity}: a decrement was lost to a race"
    )


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch-cr"}


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _try_delete_consumable_resource(ctx, name: str) -> None:
    batch = ctx.client("batch")
    batch.delete_consumable_resource(consumableResource=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
