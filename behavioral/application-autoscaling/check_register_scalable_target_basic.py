"""register-scalable-target-basic."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "register-scalable-target-basic"
GROUP = "state"
SERVICES = ["application-autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterScalableTarget persists Min/MaxCapacity and auto-assigns a service-linked
    RoleARN for DynamoDB when RoleARN is omitted."""
    aas = ctx.client("application-autoscaling")
    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"

    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=1,
        MaxCapacity=10,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: aas.deregister_scalable_target(
            ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
        )
    )

    resp = aas.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=[resource_id], ScalableDimension=dimension
    )
    targets = resp["ScalableTargets"]
    assert len(targets) == 1, f"expected exactly one scalable target, got {len(targets)}"
    target = targets[0]
    assert target["MinCapacity"] == 1, f"expected MinCapacity 1, got {target['MinCapacity']}"
    assert target["MaxCapacity"] == 10, f"expected MaxCapacity 10, got {target['MaxCapacity']}"
    assert target["ResourceId"] == resource_id, (
        f"expected ResourceId {resource_id}, got {target['ResourceId']}"
    )
    assert target["ScalableDimension"] == dimension, (
        f"expected ScalableDimension {dimension}, got {target['ScalableDimension']}"
    )
    assert "CreationTime" in target, f"expected CreationTime in target, got keys {list(target)}"
    assert "scalable-target/" in target["ScalableTargetARN"], (
        f"expected 'scalable-target/' in ARN, got {target['ScalableTargetARN']}"
    )
    # DynamoDB supports a service-linked role; when RoleARN is omitted, Application Auto
    # Scaling auto-assigns AWSServiceRoleForApplicationAutoScaling_DynamoDBTable.
    assert "AWSServiceRoleForApplicationAutoScaling_DynamoDBTable" in target["RoleARN"], target["RoleARN"]


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
