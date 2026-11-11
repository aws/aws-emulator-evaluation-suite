"""register-scalable-target-min-greater-than-max-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-scalable-target-min-greater-than-max-rejected"
GROUP = "overly-permissive"
SERVICES = ["application-autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterScalableTarget rejects MinCapacity > MaxCapacity; no scalable target is
    created, and a correctly-ordered registration in the same file still succeeds."""
    aas = ctx.client("application-autoscaling")
    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"

    error = _error_response(
        lambda: aas.register_scalable_target(
            ServiceNamespace="dynamodb",
            ResourceId=resource_id,
            ScalableDimension=dimension,
            MinCapacity=10,
            MaxCapacity=5,
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"expected ValidationException for MinCapacity=10 > MaxCapacity=5, got {error!r}"
    )
    assert error.get("Message") == "Maximum capacity cannot be less than minimum capacity", (
        f"unexpected rejection message: {error.get('Message')!r}"
    )

    targets = aas.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=[resource_id], ScalableDimension=dimension
    )["ScalableTargets"]
    assert targets == [], f"a target was created despite the rejected request: {targets}"

    # Positive control: the same resource with a valid Min<=Max registers successfully.
    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=1,
        MaxCapacity=10,
    )
    ctx.on_cleanup(
        lambda: aas.deregister_scalable_target(
            ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
        )
    )
    targets = aas.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=[resource_id], ScalableDimension=dimension
    )["ScalableTargets"]
    assert len(targets) == 1, f"expected exactly one registered target, saw {targets!r}"


def _error_response(fn: Any) -> dict:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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
