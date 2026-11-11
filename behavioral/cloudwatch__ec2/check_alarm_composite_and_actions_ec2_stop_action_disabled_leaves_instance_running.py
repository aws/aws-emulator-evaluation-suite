"""alarm-composite-and-actions-ec2-stop-action-disabled-leaves-instance-running."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alarm-composite-and-actions-ec2-stop-action-disabled-leaves-instance-running"
GROUP = "alerting"
SERVICES = ["cloudwatch", "ec2"]

_THRESHOLD = 50.0
_BREACH = 181.0
_INSTANCE_TYPE = "t3.micro"
_STEP_BUDGET_S = 600.0
_CHECK_BUDGET_S = 1500.0


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags(
    "axis:negative-delivery",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """An alarm's EC2 stop action (`arn:aws:automate:<region>:ec2:stop`) really stops its instance
    when real datapoints breach, while the identical alarm with ActionsEnabled=False, also in
    ALARM, leaves its instance running and records no Action history item."""
    cw = ctx.client("cloudwatch")
    ec2 = ctx.client("ec2")
    started = time.monotonic()
    budget = lambda: max(5.0, min(_STEP_BUDGET_S, _CHECK_BUDGET_S - (time.monotonic() - started)))
    tag = [{"Key": "sim2real", "Value": CHECK}]

    ami = _latest_al2023(ec2)
    vpc_id = ec2.create_vpc(
        CidrBlock="10.93.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag + [{"Key": "Name", "Value": ctx.unique_name("sim2real-cwec2-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, f"no available AZ in {ctx.region} offers {_INSTANCE_TYPE}; offerings {sorted(offered)!r}"
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.93.1.0/24", AvailabilityZone=usable[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    resp = ec2.run_instances(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=2, MaxCount=2, SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": tag},
            {"ResourceType": "volume", "Tags": tag},
        ],
    )
    ids = [i["InstanceId"] for i in resp["Instances"]]
    ctx.on_cleanup(lambda: _terminate(ec2, ids))
    assert len(ids) == 2, f"RunInstances returned {ids!r}"
    armed_id, disarmed_id = ids
    ec2.get_waiter("instance_running").wait(
        InstanceIds=ids, WaiterConfig={"Delay": 2, "MaxAttempts": int(budget() // 2)}
    )

    namespace = ctx.unique_name("sim2real/cwec2-")
    stop_arn = f"arn:aws:automate:{ctx.region}:ec2:stop"
    alarms = {}
    for key, instance_id, enabled in (("armed", armed_id, True), ("disarmed", disarmed_id, False)):
        name = ctx.unique_name(f"sim2real-cwec2-{key}-")
        cw.put_metric_alarm(
            AlarmName=name, Namespace=namespace, MetricName="HeartbeatLag",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            Statistic="Maximum", Period=10, EvaluationPeriods=1, Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold", TreatMissingData="ignore",
            AlarmActions=[stop_arn], ActionsEnabled=enabled, Tags=tag,
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
        alarms[key] = (name, instance_id)

    def pump():
        for _, instance_id in alarms.values():
            cw.put_metric_data(Namespace=namespace, MetricData=[{
                "MetricName": "HeartbeatLag", "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                "Value": _BREACH, "StorageResolution": 1,
            }])

    states = _wait_for(
        "both alarms to reach ALARM from real breaching datapoints",
        lambda: {k: _alarm(cw, n) for k, (n, _) in alarms.items()},
        lambda d: all(a["StateValue"] == "ALARM" for a in d.values()),
        budget(), each=pump,
    )
    for key, alarm in states.items():
        assert f"[{_BREACH}" in alarm["StateReason"], f"{key} StateReason {alarm['StateReason']!r}"
    assert states["disarmed"]["ActionsEnabled"] is False, "the disarmed alarm's ActionsEnabled flipped"

    # Positive control: the armed alarm's action really stops its instance.
    _wait_for(
        f"instance {armed_id} to be STOPPED by its alarm's EC2 stop action",
        lambda: _instance_state(ec2, armed_id),
        lambda s: s == "stopped",
        budget(),
        interval_s=10.0,
    )
    armed_actions = _history(cw, alarms["armed"][0])
    outcomes = [json.loads(h["HistoryData"]).get("actionState") for h in armed_actions]
    assert "Succeeded" in outcomes, f"the armed alarm's Action history shows {outcomes!r}, no Succeeded"
    # Measured on real AWS: the summary reads "Stop EC2 Instance '<id>' action completed successfully".
    assert any(f"'{armed_id}'" in h["HistorySummary"] for h in armed_actions), (
        f"no Action history item names instance {armed_id!r}: {[h['HistorySummary'] for h in armed_actions]!r}"
    )

    # Effect absent: same alarm, actions disabled -- the instance keeps running.
    assert _alarm(cw, alarms["disarmed"][0])["StateValue"] == "ALARM", "the disarmed alarm left ALARM"
    disarmed_state = _instance_state(ec2, disarmed_id)
    assert disarmed_state == "running", (
        f"instance {disarmed_id}, whose alarm has ActionsEnabled=False, is {disarmed_state!r}; a disabled "
        f"EC2 stop action must not act"
    )
    disarmed_actions = _history(cw, alarms["disarmed"][0])
    assert disarmed_actions == [], f"the disarmed alarm recorded Action items: {disarmed_actions!r}"

    # Teardown in-body as well as in cleanup: termination latency can exceed the cleanup budget.
    _terminate(ec2, ids)


# ===== helpers =====


def _latest_al2023(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-kernel-6.1-x86_64"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "architecture", "Values": ["x86_64"]},
        ],
    )["Images"]
    assert images, "no Amazon Linux 2023 x86_64 AMI is visible in this region"
    return max(images, key=lambda i: i["CreationDate"])["ImageId"]


def _alarm(cw, name: str) -> dict:
    found = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
    assert len(found) == 1, f"describe_alarms({name!r}) returned {len(found)} alarms"
    return found[0]


def _history(cw, name: str) -> list:
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=name, HistoryItemType="Action", AlarmTypes=["MetricAlarm"]
    ):
        items.extend(page["AlarmHistoryItems"])
    return items


def _instance_state(ec2, instance_id: str) -> str:
    res = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    return res[0]["Instances"][0]["State"]["Name"]


def _terminate(ec2, ids: list) -> None:
    try:
        ec2.terminate_instances(InstanceIds=ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise
        return
    ec2.get_waiter("instance_terminated").wait(InstanceIds=ids, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _retry(fn, attempts: int = 12, delay_s: float = 5.0):
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or i == attempts - 1:
                raise
            time.sleep(delay_s)


def _wait_for(what, fetch, pred, budget_s, each=None, interval_s=5.0):
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        if each is not None:
            each()
        last = fetch()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {budget_s:.0f}s waiting for {what}; last={last!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
