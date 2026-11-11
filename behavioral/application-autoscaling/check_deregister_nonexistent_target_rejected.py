"""deregister-nonexistent-target-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-nonexistent-target-rejected"
GROUP = "overly-permissive"
SERVICES = ["application-autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterScalableTarget on a resource/dimension combination that was never
    registered (or already deregistered) raises ObjectNotFoundException, and a normal
    register-then-deregister on a fresh, real table still succeeds."""
    aas = ctx.client("application-autoscaling")
    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"

    expected_message = (
        f"No scalable target found for service namespace: dynamodb, resource ID: {resource_id}, "
        f"scalable dimension: {dimension}"
    )

    # Never registered.
    error = _client_error(
        lambda: aas.deregister_scalable_target(
            ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
        )
    )
    assert error.get("Code") == "ObjectNotFoundException", error
    assert error.get("Message") == expected_message, (
        f"unexpected rejection message: {error.get('Message')!r}"
    )

    targets = aas.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=[resource_id], ScalableDimension=dimension
    )["ScalableTargets"]
    assert targets == [], f"expected no scalable targets for never-registered {resource_id}, got {targets}"

    # Register, deregister successfully, then deregister a *second* time to confirm the
    # same error fires once the target is genuinely gone (not merely never created).
    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=1,
        MaxCapacity=5,
    )
    aas.deregister_scalable_target(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )
    targets = aas.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=[resource_id], ScalableDimension=dimension
    )["ScalableTargets"]
    assert targets == [], f"expected no scalable targets for deregistered {resource_id}, got {targets}"

    error2 = _client_error(
        lambda: aas.deregister_scalable_target(
            ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
        )
    )
    assert error2.get("Code") == "ObjectNotFoundException", error2
    assert error2.get("Message") == expected_message, (
        f"unexpected rejection message after deregistration: {error2.get('Message')!r}"
    )


def _client_error(fn: Any) -> dict[str, Any]:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
