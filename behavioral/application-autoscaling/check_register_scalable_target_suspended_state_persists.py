"""register-scalable-target-suspended-state-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-scalable-target-suspended-state-persists"
GROUP = "state"
SERVICES = ["application-autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SuspendedState set on RegisterScalableTarget persists exactly as given and can be
    toggled by a subsequent upsert."""
    aas = ctx.client("application-autoscaling")
    table_name = _create_provisioned_table(ctx, check=CHECK)
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"

    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=1,
        MaxCapacity=10,
        SuspendedState={
            "DynamicScalingInSuspended": True,
            "DynamicScalingOutSuspended": False,
            "ScheduledScalingSuspended": False,
        },
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: aas.deregister_scalable_target(
            ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
        )
    )

    target = aas.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=[resource_id], ScalableDimension=dimension
    )["ScalableTargets"][0]
    expected_first = {
        "DynamicScalingInSuspended": True,
        "DynamicScalingOutSuspended": False,
        "ScheduledScalingSuspended": False,
    }
    assert target["SuspendedState"] == expected_first, (
        f"expected SuspendedState {expected_first}, got {target['SuspendedState']}"
    )

    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        SuspendedState={
            "DynamicScalingInSuspended": False,
            "DynamicScalingOutSuspended": True,
            "ScheduledScalingSuspended": True,
        },
    )
    target = aas.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=[resource_id], ScalableDimension=dimension
    )["ScalableTargets"][0]
    expected_second = {
        "DynamicScalingInSuspended": False,
        "DynamicScalingOutSuspended": True,
        "ScheduledScalingSuspended": True,
    }
    assert target["SuspendedState"] == expected_second, (
        f"expected SuspendedState {expected_second}, got {target['SuspendedState']}"
    )
    # Min/MaxCapacity from the first call must survive an update that only touches
    # SuspendedState.
    assert target["MinCapacity"] == 1, f"expected MinCapacity 1, got {target['MinCapacity']}"
    assert target["MaxCapacity"] == 10, f"expected MaxCapacity 10, got {target['MaxCapacity']}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
