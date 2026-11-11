"""register-scalable-target-invalid-dimension-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-scalable-target-invalid-dimension-rejected"
GROUP = "overly-permissive"
SERVICES = ["application-autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterScalableTarget rejects a ScalableDimension value that is not one of the
    documented enum values at all; no target is created, and the same resource
    registers successfully with a valid dimension."""
    aas = ctx.client("application-autoscaling")
    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"

    error = _client_error(
        lambda: aas.register_scalable_target(
            ServiceNamespace="dynamodb",
            ResourceId=resource_id,
            ScalableDimension="sim2real:not-a-real:dimension",
            MinCapacity=1,
            MaxCapacity=5,
        )
    )
    code = error.get("Code")
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {error}"
    # The message ends with every ScalableDimension enum value, a list that grows with the
    # service, so only its fixed prefix and closing bracket are asserted.
    message = error.get("Message", "")
    prefix = (
        "1 validation error detected: Value 'sim2real:not-a-real:dimension' at 'scalableDimension' "
        "failed to satisfy constraint: Member must satisfy enum value set: ["
    )
    assert message.startswith(prefix) and message.endswith("]"), (
        f"expected the enum-constraint message starting {prefix!r}, got {message!r}"
    )

    targets = aas.describe_scalable_targets(ServiceNamespace="dynamodb", ResourceIds=[resource_id])[
        "ScalableTargets"
    ]
    assert targets == [], f"a target was created despite the rejected dimension: {targets}"

    valid_dimension = "dynamodb:table:WriteCapacityUnits"
    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=valid_dimension,
        MinCapacity=1,
        MaxCapacity=5,
    )
    ctx.on_cleanup(
        lambda: aas.deregister_scalable_target(
            ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=valid_dimension
        )
    )
    targets = aas.describe_scalable_targets(ServiceNamespace="dynamodb", ResourceIds=[resource_id])[
        "ScalableTargets"
    ]
    assert len(targets) == 1, f"expected exactly 1 target after valid registration, got {targets}"


def _client_error(fn: Any) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting input AWS refuses must not read as a code mismatch."""
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
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
