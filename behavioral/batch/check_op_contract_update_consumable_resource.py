"""op-contract-update-consumable-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-update-consumable-resource"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConsumableResource ADD 5 on 10 gives totalQuantity 15 and SET 100 gives 100, each
    matching DescribeConsumableResource where read; a REMOVE larger than the total succeeds and
    clamps totalQuantity to 0, in the response and on a later describe."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-cr-")
    created = batch.create_consumable_resource(
        consumableResourceName=name, resourceType="REPLENISHABLE", totalQuantity=10, tags={"sim2real": "true"}
    )
    arn = created["consumableResourceArn"]
    ctx.on_cleanup(lambda: batch.delete_consumable_resource(consumableResource=arn))

    desc0 = batch.describe_consumable_resource(consumableResource=arn)
    assert desc0["totalQuantity"] == 10, f"expected initial totalQuantity 10, got {desc0['totalQuantity']!r}"

    # success path: ADD increases the total by exactly `quantity`
    resp_add = batch.update_consumable_resource(consumableResource=arn, operation="ADD", quantity=5)
    assert resp_add["totalQuantity"] == 15, resp_add
    desc1 = batch.describe_consumable_resource(consumableResource=arn)
    assert desc1["totalQuantity"] == 15, f"expected 10+5=15 on independent read, got {desc1['totalQuantity']!r}"

    # success path: SET pins the total to exactly `quantity`
    resp_set = batch.update_consumable_resource(consumableResource=arn, operation="SET", quantity=100)
    assert resp_set["totalQuantity"] == 100, resp_set

    # boundary: REMOVE quantity greater than current total does not raise an error;
    # it clamps totalQuantity to 0 and never goes negative
    resp_remove = batch.update_consumable_resource(consumableResource=arn, operation="REMOVE", quantity=1000)
    assert resp_remove["totalQuantity"] == 0, resp_remove

    desc2 = batch.describe_consumable_resource(consumableResource=arn)
    assert desc2["totalQuantity"] == 0, f"expected clamp to 0 on independent read, got {desc2['totalQuantity']!r}"


def _error_code(fn) -> str | None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
