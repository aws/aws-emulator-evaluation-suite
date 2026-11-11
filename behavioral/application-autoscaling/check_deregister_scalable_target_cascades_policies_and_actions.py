"""deregister-scalable-target-cascades-policies-and-actions."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deregister-scalable-target-cascades-policies-and-actions"
GROUP = "state"
SERVICES = ["application-autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterScalableTarget deletes any scaling policies and scheduled actions that
    were attached to that scalable target, including the CloudWatch alarms the policy
    created."""
    aas = ctx.client("application-autoscaling")
    cw = ctx.client("cloudwatch")
    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"
    policy_name = ctx.unique_name("sim2real-behav-policy-")
    action_name = ctx.unique_name("sim2real-behav-action-")

    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=1,
        MaxCapacity=10,
    )

    put_resp = aas.put_scaling_policy(
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
    alarm_names = [a["AlarmName"] for a in put_resp["Alarms"]]
    assert alarm_names, "target tracking policy did not create any CloudWatch alarms"

    aas.put_scheduled_action(
        ServiceNamespace="dynamodb",
        ScheduledActionName=action_name,
        ResourceId=resource_id,
        ScalableDimension=dimension,
        Schedule="at(2099-01-01T00:00:00)",
        ScalableTargetAction={"MinCapacity": 2, "MaxCapacity": 12},
    )

    policies_before = aas.describe_scaling_policies(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )["ScalingPolicies"]
    assert len(policies_before) == 1, (
        f"expected exactly 1 scaling policy registered before deregister, got {len(policies_before)}"
    )
    actions_before = aas.describe_scheduled_actions(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )["ScheduledActions"]
    assert len(actions_before) == 1, (
        f"expected exactly 1 scheduled action registered before deregister, got {len(actions_before)}"
    )
    live_alarms_before = cw.describe_alarms(AlarmNames=alarm_names)["MetricAlarms"]
    assert len(live_alarms_before) == len(alarm_names), (
        f"expected all {len(alarm_names)} policy-minted alarms visible in CloudWatch before "
        f"deregister, found {len(live_alarms_before)}: {[a['AlarmName'] for a in live_alarms_before]!r}"
    )

    aas.deregister_scalable_target(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )

    policies_after = aas.describe_scaling_policies(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )["ScalingPolicies"]
    assert policies_after == [], (
        f"scaling policy outlived its scalable target after deregister: {policies_after!r}"
    )
    actions_after = aas.describe_scheduled_actions(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )["ScheduledActions"]
    assert actions_after == [], (
        f"scheduled action outlived its scalable target after deregister: {actions_after!r}"
    )

    # Policy/action cascade removal is synchronous with the Deregister call; deleting the
    # CloudWatch alarms a target-tracking policy created is asynchronous and can take over a
    # minute, so this leg polls within a wider bounded window rather than asserting on the
    # first read.
    window_s = 180.0
    deadline = time.monotonic() + window_s
    remaining_alarms = cw.describe_alarms(AlarmNames=alarm_names)["MetricAlarms"]
    while remaining_alarms and time.monotonic() < deadline:
        time.sleep(5.0)
        remaining_alarms = cw.describe_alarms(AlarmNames=alarm_names)["MetricAlarms"]
    assert remaining_alarms == [], (
        f"alarms were not cleaned up within {window_s:.0f}s of deregister: "
        f"{[a['AlarmName'] for a in remaining_alarms]!r}"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
