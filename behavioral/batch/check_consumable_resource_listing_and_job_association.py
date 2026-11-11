"""consumable-resource-listing-and-job-association."""

from __future__ import annotations

from behavioral_harness import tags


CHECK = "consumable-resource-listing-and-job-association"
GROUP = 'consumable-resource'
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
        tags={"sim2real": "true"},
    )
    ctx.on_cleanup(lambda: _swallow(lambda: bat.delete_consumable_resource(consumableResource=name)))
    return name, resp["consumableResourceArn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A consumable resource with no consumers lists cleanly and has no associated jobs."""
    bat = ctx.client("batch")
    name, arn = _create_consumable_resource(ctx, bat, total_quantity=6, resource_type="NON_REPLENISHABLE")

    cr = bat.describe_consumable_resource(consumableResource=name)
    assert cr["resourceType"] == "NON_REPLENISHABLE", (
        f"resourceType must round-trip, got {cr['resourceType']!r}"
    )
    assert cr["totalQuantity"] == 6, f"totalQuantity must round-trip, got {cr['totalQuantity']!r}"
    assert cr["consumableResourceArn"] == arn, (
        f"describe's arn must match the arn returned at creation, got {cr['consumableResourceArn']!r} vs {arn!r}"
    )

    matching = [
        c for c in bat.list_consumable_resources()["consumableResources"]
        if c["consumableResourceName"] == name
    ]
    assert len(matching) == 1, f"ListConsumableResources must include exactly one entry for {name!r}, got {matching}"
    assert matching[0]["totalQuantity"] == 6, (
        f"listed totalQuantity must match what was created, got {matching[0]['totalQuantity']!r}"
    )
    assert matching[0]["resourceType"] == "NON_REPLENISHABLE", (
        f"listed resourceType must match what was created, got {matching[0]['resourceType']!r}"
    )

    jobs = bat.list_jobs_by_consumable_resource(consumableResource=name)["jobs"]
    assert jobs == [], f"a brand-new consumable resource must have no associated jobs, got {jobs}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
