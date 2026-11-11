"""describe-scalable-targets-invalid-next-token-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-scalable-targets-invalid-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["application-autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeScalableTargets rejects a NextToken that was not produced by a previous
    call with InvalidNextTokenException, while a plain call for the same resource (no
    token) still succeeds and returns the registered target."""
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

    error = _client_error(
        lambda: aas.describe_scalable_targets(
            ServiceNamespace="dynamodb", NextToken="sim2real-not-a-real-token=="
        )
    )
    code = error.get("Code")
    assert code == "InvalidNextTokenException", f"expected InvalidNextTokenException, got {code!r}"
    assert error.get("Message") == "The NextToken value is not valid", (
        f"unexpected rejection message: {error.get('Message')!r}"
    )

    targets = aas.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=[resource_id], ScalableDimension=dimension
    )["ScalableTargets"]
    assert len(targets) == 1, f"expected exactly 1 scalable target, got {len(targets)}: {targets!r}"
    assert targets[0]["ResourceId"] == resource_id, (
        f"expected ResourceId {resource_id!r}, got {targets[0].get('ResourceId')!r}"
    )


def _client_error(fn: Any) -> dict[str, Any]:
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
