"""xsvc-cloudwatch-3-alarm-ec2-terminate-action-disabled-blocked-until-enabled."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudwatch-3-alarm-ec2-terminate-action-disabled-blocked-until-enabled"
GROUP = "alerting"
SERVICES = ["cloudwatch", "ec2"]

_INSTANCE_TYPE = "t3.micro"
_STEP_BUDGET_S = 600.0
_CHECK_BUDGET_S = 1500.0


@tags(
    "axis:negative-delivery",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An alarm's `arn:aws:automate:<region>:ec2:terminate` action terminates its instance on ALARM;
    the twin with ActionsEnabled=False, forced to ALARM at the same instant, leaves its instance
    running until EnableAlarmActions and a fresh OK->ALARM transition terminate it too."""
    cw = ctx.client("cloudwatch")
    ec2 = ctx.client("ec2")
    started = time.monotonic()
    budget = lambda: max(5.0, min(_STEP_BUDGET_S, _CHECK_BUDGET_S - (time.monotonic() - started)))  # noqa: E731
    tag = [{"Key": "sim2real", "Value": CHECK[:200]}]

    ami = _latest_al2023(ec2)
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

    vpc_id = ec2.create_vpc(
        CidrBlock="10.95.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag + [
            {"Key": "Name", "Value": ctx.unique_name("sim2real-xsvc-cwterm-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.95.1.0/24", AvailabilityZone=usable[0],
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

    namespace = ctx.unique_name("sim2real/xsvc-cwterm-")
    term_arn = f"arn:aws:automate:{ctx.region}:ec2:terminate"
    alarms = {}
    for key, instance_id, enabled in (("armed", armed_id, True), ("disarmed", disarmed_id, False)):
        name = ctx.unique_name(f"sim2real-xsvc-cwterm-{key}-")
        cw.put_metric_alarm(
            AlarmName=name, Namespace=namespace, MetricName="Heartbeat",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            Statistic="Maximum", Period=60, EvaluationPeriods=1, Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold", TreatMissingData="ignore",
            AlarmActions=[term_arn], ActionsEnabled=enabled, Tags=tag,
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
        alarms[key] = (name, instance_id)
    assert _alarm(cw, alarms["disarmed"][0])["ActionsEnabled"] is False, "disarmed alarm stored ActionsEnabled=True"

    for key, (name, _) in alarms.items():
        cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason=f"sim2real forced {key}")
    for key, (name, _) in alarms.items():
        assert _alarm(cw, name)["StateValue"] == "ALARM", f"{key} alarm did not enter ALARM"

    # Positive control: the armed alarm's action is attempted and reports success...
    armed_actions = _drive_until_succeeded(cw, alarms["armed"][0], budget(), already_forced=True)
    assert f"'{armed_id}'" in armed_actions[0]["HistorySummary"], (
        f"the Action history item does not name instance {armed_id!r}: {armed_actions[0]['HistorySummary']!r}"
    )
    # ...and the instance is really terminated (the barrier).
    gone = {"shutting-down", "terminated"}
    _wait_for(
        f"instance {armed_id} to be TERMINATED by its alarm's EC2 terminate action",
        lambda: _instance_state(ec2, armed_id), lambda s: s in gone, budget(), interval_s=10.0,
    )

    # Effect absent: the disabled twin was in ALARM the whole time and its instance is untouched.
    assert _alarm(cw, alarms["disarmed"][0])["StateValue"] == "ALARM", "the disarmed alarm left ALARM"
    state = _instance_state(ec2, disarmed_id)
    assert state == "running", (
        f"instance {disarmed_id}, whose alarm has ActionsEnabled=False, is {state!r}; a disabled "
        f"terminate action must not act"
    )
    assert _history(cw, alarms["disarmed"][0]) == [], "the disarmed alarm recorded Action items while disabled"

    # Repair the one broken thing: re-enable actions and drive a fresh OK -> ALARM transition.
    dname = alarms["disarmed"][0]
    cw.enable_alarm_actions(AlarmNames=[dname])
    assert _alarm(cw, dname)["ActionsEnabled"] is True, "EnableAlarmActions did not set ActionsEnabled"
    _drive_until_succeeded(cw, dname, budget(), already_forced=False)
    _wait_for(
        f"instance {disarmed_id} to be TERMINATED once its alarm's actions were re-enabled",
        lambda: _instance_state(ec2, disarmed_id), lambda s: s in gone, budget(), interval_s=10.0,
    )
    rearmed = _history(cw, dname)
    assert any(f"'{disarmed_id}'" in h["HistorySummary"] for h in rearmed), (
        f"re-armed alarm's Action history does not name {disarmed_id!r}: {[h['HistorySummary'] for h in rearmed]!r}"
    )

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


def _drive_until_succeeded(cw, name: str, budget_s: float, already_forced: bool) -> list:
    """Force OK -> ALARM until that transition's Action item reads Succeeded; return the newest items.
    CloudWatch acts on EC2 through a service-linked role PutMetricAlarm creates on an account that
    lacks it, and a role that young can fail the first action -- so re-drive while it reads Failed.
    With already_forced the caller's own SetAlarmState is round one, so it is awaited, not repeated."""
    deadline = time.monotonic() + budget_s
    rounds = []
    first = already_forced
    while True:
        seen = 0 if first else len(_history(cw, name))
        if not first:
            cw.set_alarm_state(AlarmName=name, StateValue="OK", StateReason="sim2real reset")
            _wait_for(f"{name} to read OK", lambda: _alarm(cw, name)["StateValue"], lambda v: v == "OK", 30.0)
            cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason="sim2real re-driven")
        first = False
        items = _wait_for(f"{name}'s Action history to record its attempt",
                          lambda: _history(cw, name), lambda h: len(h) > seen, 120.0)
        data = json.loads(items[0]["HistoryData"])
        rounds.append(data.get("actionState"))
        if rounds[-1] == "Succeeded":
            return items
        assert time.monotonic() < deadline, f"{name}'s action never succeeded; rounds {rounds!r}, last {data!r}"
        time.sleep(2.0)


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
