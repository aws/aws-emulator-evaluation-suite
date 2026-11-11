"""consumable-resource-add-remove-arithmetic."""

from __future__ import annotations

from behavioral_harness import tags


CHECK = "consumable-resource-add-remove-arithmetic"
GROUP = 'consumable-resource'
SERVICES = ['batch']


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    fn()


def _describe_consumable_resource(bat, name):
    return bat.describe_consumable_resource(consumableResource=name)


def _create_consumable_resource(ctx, bat, name=None, total_quantity=10, resource_type="REPLENISHABLE"):
    name = name or ctx.unique_name("sim2real-behav-cr-")
    resp = bat.create_consumable_resource(
        consumableResourceName=name,
        totalQuantity=total_quantity,
        resourceType=resource_type,
        tags={"sim2real": "true"},
    )
    ctx.on_cleanup(lambda: _swallow(lambda: bat.delete_consumable_resource(consumableResource=name)))
    return name, resp["consumableResourceArn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ADD/REMOVE on a consumable resource apply as relative deltas to totalQuantity."""
    bat = ctx.client("batch")
    name, _arn = _create_consumable_resource(ctx, bat, total_quantity=10, resource_type="REPLENISHABLE")

    bat.update_consumable_resource(consumableResource=name, operation="ADD", quantity=7)
    cr = _describe_consumable_resource(bat, name)
    assert cr["totalQuantity"] == 17, f"expected 10+7=17, got {cr['totalQuantity']!r}"

    bat.update_consumable_resource(consumableResource=name, operation="REMOVE", quantity=5)
    cr = _describe_consumable_resource(bat, name)
    assert cr["totalQuantity"] == 12, f"expected 17-5=12, got {cr['totalQuantity']!r}"

    assert cr["availableQuantity"] == 12, (
        f"with no jobs consuming it, availableQuantity should track totalQuantity, "
        f"got {cr.get('availableQuantity')!r}"
    )
    assert cr["inUseQuantity"] == 0, f"expected inUseQuantity 0, got {cr.get('inUseQuantity')!r}"

    listed = bat.list_consumable_resources()["consumableResources"]
    assert any(c["consumableResourceName"] == name for c in listed), (
        "ListConsumableResources must include the created resource"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
