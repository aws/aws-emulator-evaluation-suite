"""describe-scaling-policies-filters-by-dimension."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-scaling-policies-filters-by-dimension"
GROUP = "state"
SERVICES = ["application-autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeScalingPolicies with ScalableDimension set returns only the policy for
    that dimension on the resource, not a sibling policy registered on a different
    dimension of the same resource."""
    aas = ctx.client("application-autoscaling")
    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"
    read_dim = "dynamodb:table:ReadCapacityUnits"
    write_dim = "dynamodb:table:WriteCapacityUnits"
    read_policy = ctx.unique_name("sim2real-behav-read-policy-")
    write_policy = ctx.unique_name("sim2real-behav-write-policy-")

    for dim in (read_dim, write_dim):
        aas.register_scalable_target(
            ServiceNamespace="dynamodb",
            ResourceId=resource_id,
            ScalableDimension=dim,
            MinCapacity=1,
            MaxCapacity=10,
        )
        ctx.on_cleanup(
            lambda dim=dim: aas.deregister_scalable_target(
                ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dim
            )
        )

    aas.put_scaling_policy(
        PolicyName=read_policy,
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=read_dim,
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration={
            "TargetValue": 60.0,
            "PredefinedMetricSpecification": {"PredefinedMetricType": "DynamoDBReadCapacityUtilization"},
        },
    )
    aas.put_scaling_policy(
        PolicyName=write_policy,
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=write_dim,
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration={
            "TargetValue": 60.0,
            "PredefinedMetricSpecification": {"PredefinedMetricType": "DynamoDBWriteCapacityUtilization"},
        },
    )

    read_only = aas.describe_scaling_policies(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=read_dim
    )["ScalingPolicies"]
    assert [p["PolicyName"] for p in read_only] == [read_policy], read_only

    write_only = aas.describe_scaling_policies(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=write_dim
    )["ScalingPolicies"]
    assert [p["PolicyName"] for p in write_only] == [write_policy], write_only

    both = aas.describe_scaling_policies(ServiceNamespace="dynamodb", ResourceId=resource_id)["ScalingPolicies"]
    both_names = {p["PolicyName"] for p in both}
    assert both_names == {read_policy, write_policy}, (
        f"expected both policies with no dimension filter, got {both_names}"
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
        Tags=[{"Key": "sim2real", "Value": "describe-scaling-policies-filters-by-dimension"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
