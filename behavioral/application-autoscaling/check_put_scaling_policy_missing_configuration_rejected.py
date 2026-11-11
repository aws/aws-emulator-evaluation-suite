"""put-scaling-policy-missing-configuration-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-scaling-policy-missing-configuration-rejected"
GROUP = "overly-permissive"
SERVICES = ["application-autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutScalingPolicy is rejected with ValidationException when PolicyType is
    TargetTrackingScaling but TargetTrackingScalingPolicyConfiguration is omitted; no
    policy is created, and supplying the configuration in the same file succeeds."""
    aas = ctx.client("application-autoscaling")
    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"
    policy_name = ctx.unique_name("sim2real-behav-policy-")

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

    error = _client_error(
        lambda: aas.put_scaling_policy(
            PolicyName=policy_name,
            ServiceNamespace="dynamodb",
            ResourceId=resource_id,
            ScalableDimension=dimension,
            PolicyType="TargetTrackingScaling",
        )
    )
    code = error.get("Code")
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert error.get("Message") == "TargetTrackingScaling policy configuration must be specified", (
        f"unexpected rejection message: {error.get('Message')!r}"
    )

    policies = aas.describe_scaling_policies(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )["ScalingPolicies"]
    assert policies == [], f"a policy was created despite the missing configuration: {policies}"

    aas.put_scaling_policy(
        PolicyName=policy_name,
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration={
            "TargetValue": 70.0,
            "PredefinedMetricSpecification": {"PredefinedMetricType": "DynamoDBWriteCapacityUtilization"},
        },
    )
    policies = aas.describe_scaling_policies(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )["ScalingPolicies"]
    assert len(policies) == 1, f"expected exactly one policy once the configuration was supplied, got {policies}"
    assert policies[0]["PolicyName"] == policy_name, (
        f"expected policy {policy_name!r}, got {policies[0].get('PolicyName')!r}"
    )


def _client_error(fn: Any) -> dict[str, Any]:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
