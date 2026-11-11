"""register-scalable-target-idempotent-upsert."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-scalable-target-idempotent-upsert"
GROUP = "state"
SERVICES = ["application-autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Calling RegisterScalableTarget again for the same namespace/resource/dimension
    updates the existing scalable target in place rather than creating a duplicate."""
    aas = ctx.client("application-autoscaling")
    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"

    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=1,
        MaxCapacity=5,
    )
    ctx.on_cleanup(
        lambda: aas.deregister_scalable_target(
            ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
        )
    )

    initial = aas.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=[resource_id], ScalableDimension=dimension
    )["ScalableTargets"]
    assert len(initial) == 1, f"expected exactly one target after first register, got {len(initial)}"
    initial_arn = initial[0]["ScalableTargetARN"]
    initial_created = initial[0]["CreationTime"]

    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=2,
        MaxCapacity=20,
    )

    resp = aas.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=[resource_id], ScalableDimension=dimension
    )
    targets = resp["ScalableTargets"]
    assert len(targets) == 1, f"upsert created a duplicate target: {targets}"
    target = targets[0]
    assert target["MinCapacity"] == 2, f"expected MinCapacity updated to 2, got {target['MinCapacity']}"
    assert target["MaxCapacity"] == 20, f"expected MaxCapacity updated to 20, got {target['MaxCapacity']}"
    # An in-place update must preserve identity, not delete-and-recreate: same ARN and
    # CreationTime as the target the first register call produced.
    assert target["ScalableTargetARN"] == initial_arn, (
        f"upsert changed target identity: {initial_arn!r} -> {target['ScalableTargetARN']!r}"
    )
    assert target["CreationTime"] == initial_created, (
        f"upsert reset CreationTime: {initial_created!r} -> {target['CreationTime']!r}"
    )


def _create_provisioned_table(ctx, read_cap: int = 5, write_cap: int = 5) -> str:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-aas-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": read_cap, "WriteCapacityUnits": write_cap},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
