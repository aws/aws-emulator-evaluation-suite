"""consumable-resource-lifecycle."""

from __future__ import annotations
import time

from behavioral_harness import tags


CHECK = "consumable-resource-lifecycle"
GROUP = 'consumable-resource'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    fn()


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _describe_consumable_resource(bat, name):
    return bat.describe_consumable_resource(consumableResource=name)


def _create_consumable_resource(ctx, bat, name=None, total_quantity=10, resource_type="REPLENISHABLE"):
    name = name or ctx.unique_name("sim2real-behav-cr-")
    resp = bat.create_consumable_resource(
        consumableResourceName=name,
        totalQuantity=total_quantity,
        resourceType=resource_type,
        tags=dict(_MANAGED_TAGS),
    )
    ctx.on_cleanup(lambda: _swallow(lambda: bat.delete_consumable_resource(consumableResource=name)))
    return name, resp["consumableResourceArn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConsumableResource sets available=total; UpdateConsumableResource ADD/SET mutate totalQuantity."""
    bat = ctx.client("batch")
    name, arn = _create_consumable_resource(ctx, bat, total_quantity=10, resource_type="REPLENISHABLE")

    d = _describe_consumable_resource(bat, name)
    assert d["totalQuantity"] == 10, f"expected fresh totalQuantity 10, got {d.get('totalQuantity')!r}"
    assert d["availableQuantity"] == 10, f"expected fresh availableQuantity 10, got {d.get('availableQuantity')!r}"
    assert d["inUseQuantity"] == 0, f"expected fresh inUseQuantity 0, got {d.get('inUseQuantity')!r}"
    assert d["consumableResourceArn"] == arn, f"expected arn {arn!r}, got {d.get('consumableResourceArn')!r}"

    bat.update_consumable_resource(consumableResource=name, operation="ADD", quantity=5)
    d = _poll_until(lambda: _describe_consumable_resource(bat, name), lambda d: d.get("totalQuantity") == 15, timeout_s=60, interval_s=3, description="consumable resource total == 15 after ADD 5")
    assert d["totalQuantity"] == 15, f"expected 10+5=15 after ADD, got {d.get('totalQuantity')!r}"
    assert d["availableQuantity"] == 15, f"expected availableQuantity to track totalQuantity (15) with no jobs in use, got {d.get('availableQuantity')!r}"

    bat.update_consumable_resource(consumableResource=name, operation="SET", quantity=3)
    d = _poll_until(lambda: _describe_consumable_resource(bat, name), lambda d: d.get("totalQuantity") == 3, timeout_s=60, interval_s=3, description="consumable resource total == 3 after SET 3")
    assert d["totalQuantity"] == 3, f"expected SET to pin totalQuantity to 3, got {d.get('totalQuantity')!r}"
    assert d["availableQuantity"] == 3, f"expected availableQuantity to track totalQuantity (3) with no jobs in use, got {d.get('availableQuantity')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
