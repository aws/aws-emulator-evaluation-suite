"""put-scaling-policy-unregistered-dimension-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-scaling-policy-unregistered-dimension-rejected"
GROUP = "server-side"
SERVICES = ["application-autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutScalingPolicy is rejected with ObjectNotFoundException for a scalable dimension that
    was never registered via RegisterScalableTarget, leaves no policy behind for that
    dimension, while the registered dimension's policy still succeeds (positive control)."""
    ddb = ctx.client("dynamodb")
    aas = ctx.client("application-autoscaling")

    table_name = ctx.unique_name("sim2real-autoscale-neg-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _wait_table_active(ddb, table_name)

    resource_id = f"table/{table_name}"
    registered_dimension = "dynamodb:table:WriteCapacityUnits"
    unregistered_dimension = "dynamodb:table:ReadCapacityUnits"

    # Only WriteCapacityUnits is registered as a scalable target -- ReadCapacityUnits is not.
    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=registered_dimension,
        MinCapacity=1,
        MaxCapacity=10,
    )
    ctx.on_cleanup(
        lambda: aas.deregister_scalable_target(
            ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=registered_dimension
        )
    )

    tt_config = {
        "TargetValue": 50.0,
        "PredefinedMetricSpecification": {"PredefinedMetricType": "DynamoDBWriteCapacityUtilization"},
    }

    # Confirm the initial state: exactly the write dimension is registered, not the read one.
    initial_targets = aas.describe_scalable_targets(ServiceNamespace="dynamodb", ResourceIds=[resource_id])[
        "ScalableTargets"
    ]
    assert [t["ScalableDimension"] for t in initial_targets] == [registered_dimension], initial_targets

    # Break exactly one thing: target the dimension that was never registered.
    error = _client_error(
        lambda: aas.put_scaling_policy(
            PolicyName=ctx.unique_name("sim2real-autoscale-neg-policy-"),
            ServiceNamespace="dynamodb",
            ResourceId=resource_id,
            ScalableDimension=unregistered_dimension,
            PolicyType="TargetTrackingScaling",
            TargetTrackingScalingPolicyConfiguration={
                "TargetValue": 50.0,
                "PredefinedMetricSpecification": {
                    "PredefinedMetricType": "DynamoDBReadCapacityUtilization"
                },
            },
        )
    )
    assert error.get("Code") == "ObjectNotFoundException", error
    assert error.get("Message") == (
        f"No scalable target registered for service namespace: dynamodb, "
        f"resource ID: {resource_id}, scalable dimension: {unregistered_dimension}"
    ), error.get("Message")

    # Effect absent: no scaling policy exists for the unregistered dimension.
    unregistered_policies = aas.describe_scaling_policies(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=unregistered_dimension
    )["ScalingPolicies"]
    assert unregistered_policies == [], unregistered_policies

    # Positive control: the same call against the registered dimension succeeds.
    control_policy_name = ctx.unique_name("sim2real-autoscale-ctrl-policy-")
    aas.put_scaling_policy(
        PolicyName=control_policy_name,
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=registered_dimension,
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration=tt_config,
    )
    registered_policies = aas.describe_scaling_policies(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=registered_dimension
    )["ScalingPolicies"]
    assert any(p["PolicyName"] == control_policy_name for p in registered_policies), registered_policies


def _wait_table_active(client, table_name: str, timeout_s: float = 120.0, interval_s: float = 2.0) -> None:
    def _status() -> str:
        return client.describe_table(TableName=table_name)["Table"]["TableStatus"]

    _poll_until(_status, lambda s: s == "ACTIVE", timeout_s=timeout_s, interval_s=interval_s)


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value: {last!r}")


def _client_error(fn: Callable[[], Any]) -> dict[str, Any]:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
