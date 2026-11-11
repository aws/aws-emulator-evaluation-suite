"""register-scalable-target-capacity-clamped-on-max-decrease."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "register-scalable-target-capacity-clamped-on-max-decrease"
GROUP = "data-plane"
SERVICES = ["application-autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """When RegisterScalableTarget is called again for an already-registered target and
    the resource's *current* capacity now exceeds the new MaxCapacity, Application Auto
    Scaling actively adjusts the real resource's capacity down into the new bounds."""
    aas = ctx.client("application-autoscaling")
    ddb = ctx.client("dynamodb")
    table_name = _create_provisioned_table(ctx, write_cap=5, check=CHECK)
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"

    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=1,
        MaxCapacity=20,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: aas.deregister_scalable_target(
            ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
        )
    )

    # Bump the table's actual write capacity above the max we're about to set.
    ddb.update_table(TableName=table_name, ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 15})
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    current = ddb.describe_table(TableName=table_name)["Table"]["ProvisionedThroughput"]["WriteCapacityUnits"]
    assert current == 15, f"expected the pre-bump write capacity to read back as 15, saw {current}"

    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=1,
        MaxCapacity=8,
    )

    final_capacity = _poll_until(
        probe=lambda: ddb.describe_table(TableName=table_name)["Table"]["ProvisionedThroughput"][
            "WriteCapacityUnits"
        ],
        predicate=lambda cap: cap <= 8,
        timeout_s=150.0,
        interval_s=10.0,
    )
    assert final_capacity == 8, f"expected capacity clamped to 8, saw {final_capacity}"


def _create_provisioned_table(ctx, read_cap: int = 5, write_cap: int = 5, check: str = "") -> str:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-aas-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": read_cap, "WriteCapacityUnits": write_cap},
        Tags=[{"Key": "sim2real", "Value": check}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={value!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
