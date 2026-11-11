"""target-tracking-policy-manages-cloudwatch-alarms."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "target-tracking-policy-manages-cloudwatch-alarms"
GROUP = "state"
SERVICES = ["application-autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutScalingPolicy with PolicyType=TargetTrackingScaling auto-creates the scale-out
    and scale-in CloudWatch alarms (no manual alarm definition needed), and
    DeleteScalingPolicy removes exactly those alarms as a side effect."""
    aas = ctx.client("application-autoscaling")
    cw = ctx.client("cloudwatch")
    table_name = _create_provisioned_table(ctx)
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:ReadCapacityUnits"
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

    put_resp = aas.put_scaling_policy(
        PolicyName=policy_name,
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration={
            "TargetValue": 70.0,
            "PredefinedMetricSpecification": {"PredefinedMetricType": "DynamoDBReadCapacityUtilization"},
        },
    )
    alarm_names = [a["AlarmName"] for a in put_resp["Alarms"]]
    # A DynamoDB target tracking policy with scale-in enabled (the default) manages
    # exactly four alarms, TargetTracking-<resource id>-<kind>-<uuid>: the scale-out
    # AlarmHigh, the scale-in AlarmLow, and the ProvisionedCapacityHigh/Low pair.
    assert alarm_names, "target tracking policy did not create any CloudWatch alarms"
    prefix = f"TargetTracking-{resource_id}-"
    kinds = sorted(
        name[len(prefix):].split("-", 1)[0] if name.startswith(prefix) else name for name in alarm_names
    )
    assert kinds == ["AlarmHigh", "AlarmLow", "ProvisionedCapacityHigh", "ProvisionedCapacityLow"], (
        f"target tracking policy alarms {alarm_names!r} (kinds {kinds!r}), expected exactly one "
        f"{prefix}<kind>-* alarm per kind AlarmHigh, AlarmLow, ProvisionedCapacityHigh, ProvisionedCapacityLow"
    )

    live_alarms = cw.describe_alarms(AlarmNames=alarm_names)["MetricAlarms"]
    live_names = {a["AlarmName"] for a in live_alarms}
    assert live_names == set(alarm_names), (
        f"CloudWatch reports alarms {live_names!r}, expected exactly {set(alarm_names)!r} "
        f"from the target tracking policy"
    )

    described = aas.describe_scaling_policies(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )["ScalingPolicies"]
    assert len(described) == 1, f"expected exactly 1 scaling policy on the target, found {len(described)}"
    described_names = {a["AlarmName"] for a in described[0]["Alarms"]}
    assert described_names == set(alarm_names), (
        f"DescribeScalingPolicies reports alarms {described_names!r}, expected exactly "
        f"{set(alarm_names)!r} to match PutScalingPolicy's own response"
    )

    aas.delete_scaling_policy(
        PolicyName=policy_name, ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )
    # Alarm teardown lags DeleteScalingPolicy's own response (measured on real AWS: an
    # immediate read still sees the alarm), so absence is bounded by a deadline rather than
    # asserted on the very next call.
    remaining = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=alarm_names)["MetricAlarms"],
        lambda alarms: alarms == [],
        timeout_s=60,
        interval_s=3.0,
        description="alarms being removed after policy deletion",
    )
    assert remaining == [], f"alarms survived policy deletion: {remaining}"


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


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
