"""target-tracking-alarm-breach-triggers-scaling-activity."""
from __future__ import annotations

import threading
import time

from behavioral_harness import tags

CHECK = "target-tracking-alarm-breach-triggers-scaling-activity"
GROUP = "data-plane"
SERVICES = ["application-autoscaling"]


# timing:real-time — metric: 120 s https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-target-tracking.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """Sustained PutItem traffic past a target-tracking policy's utilization target makes
    Application Auto Scaling raise the table's WriteCapacityUnits and record a scaling activity."""
    aas = ctx.client("application-autoscaling")
    ctx.client("cloudwatch")
    ddb = ctx.client("dynamodb")
    table_name = _create_provisioned_table(ctx, write_cap=5)
    resource_id = f"table/{table_name}"
    dimension = "dynamodb:table:WriteCapacityUnits"
    policy_name = ctx.unique_name("sim2real-behav-policy-")

    aas.register_scalable_target(
        ServiceNamespace="dynamodb",
        ResourceId=resource_id,
        ScalableDimension=dimension,
        MinCapacity=1,
        MaxCapacity=40,
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
            "TargetValue": 20.0,
            "ScaleOutCooldown": 0,
            "ScaleInCooldown": 0,
            "PredefinedMetricSpecification": {"PredefinedMetricType": "DynamoDBWriteCapacityUtilization"},
        },
    )
    alarm_names = [a["AlarmName"] for a in put_resp["Alarms"]]
    assert alarm_names, "target tracking policy did not create any CloudWatch alarms"
    ctx.on_cleanup(
        lambda: aas.delete_scaling_policy(
            PolicyName=policy_name, ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
        )
    )

    initial_capacity = ddb.describe_table(TableName=table_name)["Table"]["ProvisionedThroughput"][
        "WriteCapacityUnits"
    ]
    assert initial_capacity == 5, f"table {table_name!r} started at {initial_capacity} WCU, expected the 5 provisioned at creation"

    # Real PutItem load (not SetAlarmState) so the breach comes from Application Auto Scaling's own
    # utilization math; 8 writers easily exceed 20% of 5 WCU/s.
    stop_event = threading.Event()
    load_threads = _start_write_load(ddb, table_name, stop_event, workers=8)
    try:
        final_capacity = _poll_until(
            probe=lambda: ddb.describe_table(TableName=table_name)["Table"]["ProvisionedThroughput"][
                "WriteCapacityUnits"
            ],
            predicate=lambda cap: cap > initial_capacity,
            timeout_s=420.0,
            interval_s=15.0,
        )
    finally:
        stop_event.set()
        for t in load_threads:
            t.join(timeout=10)

    assert final_capacity is not None and final_capacity > initial_capacity, (
        f"WriteCapacityUnits never increased past {initial_capacity} after several "
        "minutes of sustained write load well above the policy's target utilization"
    )

    activities = aas.describe_scaling_activities(
        ServiceNamespace="dynamodb", ResourceId=resource_id, ScalableDimension=dimension
    )["ScalingActivities"]
    statuses = [a["StatusCode"] for a in activities]
    assert any(s in ("Successful", "InProgress") for s in statuses), (
        f"describe_scaling_activities for {resource_id!r} returned status codes {statuses!r}; "
        "expected at least one Successful or InProgress activity attributable to the capacity "
        "increase already observed on the table"
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


def _start_write_load(ddb, table_name: str, stop_event: threading.Event, workers: int = 8) -> list[threading.Thread]:
    payload = "x" * 1024

    def worker(worker_id: int) -> None:
        i = 0
        while not stop_event.is_set():
            try:
                ddb.put_item(
                    TableName=table_name,
                    Item={"pk": {"S": f"sim2real-behav-load-{worker_id}-{i}"}, "payload": {"S": payload}},
                )
            except Exception:
                # Throttling or transient errors are expected under sustained
                # above-capacity load; keep pushing traffic regardless.
                pass
            i += 1

    threads = [threading.Thread(target=worker, args=(w,), daemon=True) for w in range(workers)]
    for t in threads:
        t.start()
    return threads


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
