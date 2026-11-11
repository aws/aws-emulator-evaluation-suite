"""put-scaling-policy-without-target-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-scaling-policy-without-target-rejected"
GROUP = "overly-permissive"
SERVICES = ["application-autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutScalingPolicy on a REAL table with no scalable target registered for that dimension is
    rejected with ObjectNotFoundException and creates no policy; the identical policy succeeds once
    a target is registered on the same table."""
    aas = ctx.client("application-autoscaling")
    dimension = "dynamodb:table:WriteCapacityUnits"

    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"
    policy_config = {
        "TargetValue": 70.0,
        "PredefinedMetricSpecification": {"PredefinedMetricType": "DynamoDBWriteCapacityUtilization"},
    }

    baseline_targets = aas.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=[resource_id], ScalableDimension=dimension
    )["ScalableTargets"]
    assert baseline_targets == [], (
        f"this check requires the table to be UNregistered before the policy attempt, "
        f"but found {baseline_targets!r}"
    )

    error = _client_error(
        lambda: aas.put_scaling_policy(
            PolicyName="sim2real-behav-no-target-policy",
            ServiceNamespace="dynamodb",
            ResourceId=resource_id,
            ScalableDimension=dimension,
            PolicyType="TargetTrackingScaling",
            TargetTrackingScalingPolicyConfiguration=policy_config,
        )
    )
    assert error.get("Code") == "ObjectNotFoundException", (
        f"attaching a policy to a real but unregistered table was rejected with "
        f"{error.get('Code')!r}, expected 'ObjectNotFoundException'"
    )
    assert error.get("Message") == (
        f"No scalable target registered for service namespace: dynamodb, resource ID: {resource_id}, "
        f"scalable dimension: {dimension}"
    ), f"unexpected rejection message: {error.get('Message')!r}"

    policies = aas.describe_scaling_policies(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )["ScalingPolicies"]
    assert policies == [], f"a policy was created despite no registered target: {policies}"
    targets_after_refusal = aas.describe_scalable_targets(
        ServiceNamespace="dynamodb", ResourceIds=[resource_id], ScalableDimension=dimension
    )["ScalableTargets"]
    assert targets_after_refusal == [], (
        f"the refused PutScalingPolicy implicitly registered a scalable target: {targets_after_refusal!r}"
    )

    # Positive control: register a target on the SAME real table, then the identical
    # policy definition succeeds.
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
    aas.put_scaling_policy(
        PolicyName="sim2real-behav-with-target-policy",
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration=policy_config,
    )
    policies = aas.describe_scaling_policies(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )["ScalingPolicies"]
    assert [p["PolicyName"] for p in policies] == ["sim2real-behav-with-target-policy"], (
        f"the positive control did not store exactly the one policy: "
        f"{[p['PolicyName'] for p in policies]!r}"
    )
    assert policies[0]["TargetTrackingScalingPolicyConfiguration"]["TargetValue"] == 70.0, (
        f"the stored policy came back with TargetValue "
        f"{policies[0]['TargetTrackingScalingPolicyConfiguration']['TargetValue']!r}, expected 70.0"
    )


def _client_error(fn: Any) -> dict[str, Any]:
    """Call fn(); return its botocore Error dict. An unexpected success raises rather than being
    reported as an error-code mismatch."""
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
        Tags=[{"Key": "sim2real-behav-check", "Value": "put-scaling-policy-without-target-rejected"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
