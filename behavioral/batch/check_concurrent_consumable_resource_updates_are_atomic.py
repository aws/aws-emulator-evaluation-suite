"""concurrent-consumable-resource-updates-are-atomic."""

from __future__ import annotations
from collections.abc import Callable

from behavioral_harness import tags


CHECK = "concurrent-consumable-resource-updates-are-atomic"
GROUP = 'concurrency'
SERVICES = ['batch']


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    fn()


def _create_consumable_resource(ctx, bat, name=None, total_quantity=10, resource_type="REPLENISHABLE"):
    name = name or ctx.unique_name("sim2real-behav-cr-")
    resp = bat.create_consumable_resource(
        consumableResourceName=name,
        totalQuantity=total_quantity,
        resourceType=resource_type,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-cr", "sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _swallow(lambda: bat.delete_consumable_resource(consumableResource=name)))
    return name, resp["consumableResourceArn"]


def _parallel(fns: list[Callable]) -> tuple[list, list[str]]:
    """Run callables concurrently; return (successful results, error codes)."""
    import concurrent.futures

    oks: list = []
    errs: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(fn) for fn in fns]
        for fut in futures:
            try:
                oks.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                resp = getattr(exc, "response", None) or {}
                errs.append(resp.get("Error", {}).get("Code", type(exc).__name__))
    return oks, errs


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent ADD updates to a consumable resource's quantity must not lose updates."""
    bat = ctx.client("batch")
    name, _arn = _create_consumable_resource(ctx, bat, total_quantity=0, resource_type="REPLENISHABLE")

    n = 10
    add_amount = 3
    # Several rounds, so a target that loses updates only under some interleavings shows it on
    # every run rather than occasionally.
    rounds = 3

    def add_once():
        return bat.update_consumable_resource(
            consumableResource=name, operation="ADD", quantity=add_amount
        )

    for r in range(1, rounds + 1):
        oks, errs = _parallel([add_once for _ in range(n)])
        assert len(oks) == n, (
            f"expected all {n} concurrent ADD updates to succeed, got {len(oks)} in round {r}: {errs}"
        )

        cr = bat.describe_consumable_resource(consumableResource=name)
        assert cr["totalQuantity"] == r * n * add_amount, (
            f"expected totalQuantity {r * n * add_amount} after {r} rounds of {n} concurrent ADDs "
            f"of {add_amount}, got {cr['totalQuantity']!r} (lost update under contention)"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
