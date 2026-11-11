"""register-scalable-target-nonexistent-resource-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-scalable-target-nonexistent-resource-rejected"
GROUP = "overly-permissive"
SERVICES = ["application-autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterScalableTarget for a never-created DynamoDB table is rejected with
    ValidationException and persists no target, while the same call on a real table succeeds."""
    aas = ctx.client("application-autoscaling")
    ghost_resource_id = f"table/{ctx.unique_name('sim2real-behav-aas-ghost-')}"
    dimension = "dynamodb:table:WriteCapacityUnits"

    error = _client_error(
        lambda: aas.register_scalable_target(
            ServiceNamespace="dynamodb",
            ResourceId=ghost_resource_id,
            ScalableDimension=dimension,
            MinCapacity=1,
            MaxCapacity=5,
        )
    )
    code = error.get("Code")
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert error.get("Message") == f"DynamoDB table does not exist: {ghost_resource_id}", (
        f"unexpected rejection message: {error.get('Message')!r}"
    )

    targets = aas.describe_scalable_targets(ServiceNamespace="dynamodb", ResourceIds=[ghost_resource_id])[
        "ScalableTargets"
    ]
    assert targets == [], f"a target was created for a nonexistent table: {targets}"

    # Positive control: the same kind of registration against a real table succeeds.
    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"
    resp = aas.register_scalable_target(
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
    assert resp["ScalableTargetARN"], f"registration against a real table returned no ARN: {resp!r}"
    targets = aas.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=[resource_id], ScalableDimension=dimension
    )["ScalableTargets"]
    assert len(targets) == 1, f"expected exactly one target for {resource_id!r}, got {targets!r}"
    assert targets[0]["ResourceId"] == resource_id, (
        f"expected target ResourceId {resource_id!r}, got {targets[0]['ResourceId']!r}"
    )


def _client_error(fn: Any) -> dict[str, Any]:
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_provisioned_table(ctx, read_cap: int = 5, write_cap: int = 5) -> str:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-aas-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": read_cap, "WriteCapacityUnits": write_cap},
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
