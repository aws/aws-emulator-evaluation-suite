"""put-scaling-policy-idempotent-upsert-updates-config."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-scaling-policy-idempotent-upsert-updates-config"
GROUP = "state"
SERVICES = ["application-autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Calling PutScalingPolicy again with the same PolicyName replaces the policy's
    configuration in place (same PolicyARN, updated TargetValue) instead of creating a
    second policy."""
    aas = ctx.client("application-autoscaling")
    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"
    policy_name = ctx.unique_name("sim2real-behav-policy-")

    target_arn = aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=1,
        MaxCapacity=10,
    )["ScalableTargetARN"]
    ctx.on_cleanup(
        lambda: aas.deregister_scalable_target(
            ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
        )
    )
    aas.tag_resource(ResourceARN=target_arn, Tags={"sim2real": "behavioral"})

    first_arn = aas.put_scaling_policy(
        PolicyName=policy_name,
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration={
            "TargetValue": 70.0,
            "PredefinedMetricSpecification": {"PredefinedMetricType": "DynamoDBWriteCapacityUtilization"},
        },
    )["PolicyARN"]

    policies = aas.describe_scaling_policies(PolicyNames=[policy_name], ServiceNamespace="dynamodb")[
        "ScalingPolicies"
    ]
    assert len(policies) == 1, f"expected exactly 1 policy named {policy_name!r}, got {policies}"
    assert policies[0]["TargetTrackingScalingPolicyConfiguration"]["TargetValue"] == 70.0, (
        f"expected TargetValue 70.0 after first put, got {policies[0]['TargetTrackingScalingPolicyConfiguration']}"
    )

    second_arn = aas.put_scaling_policy(
        PolicyName=policy_name,
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration={
            "TargetValue": 45.0,
            "PredefinedMetricSpecification": {"PredefinedMetricType": "DynamoDBWriteCapacityUtilization"},
        },
    )["PolicyARN"]
    assert second_arn == first_arn, "upsert produced a different PolicyARN"

    policies = aas.describe_scaling_policies(PolicyNames=[policy_name], ServiceNamespace="dynamodb")[
        "ScalingPolicies"
    ]
    assert len(policies) == 1, f"upsert created a duplicate policy: {policies}"
    assert policies[0]["TargetTrackingScalingPolicyConfiguration"]["TargetValue"] == 45.0, (
        f"expected TargetValue 45.0 after upsert, got {policies[0]['TargetTrackingScalingPolicyConfiguration']}"
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
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
