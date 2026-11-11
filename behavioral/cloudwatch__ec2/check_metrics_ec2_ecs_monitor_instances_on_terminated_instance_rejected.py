"""metrics-ec2-ecs-monitor-instances-on-terminated-instance-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "metrics-ec2-ecs-monitor-instances-on-terminated-instance-rejected"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "ec2"]

_INSTANCE_TYPE = "t3.micro"
_VPC_CIDR = "10.93.0.0/16"
_SUBNET_CIDR = "10.93.1.0/24"
_RUNNING_BUDGET_S = 300.0
_METRIC_BUDGET_S = 1200.0
_USER_DATA = "#!/bin/bash\nshutdown -h +40\n"


# timing:real-time — metric: 300 s https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/manage-detailed-monitoring.html
@tags("axis:rejection", "cap:c4", "concern:metrics", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """MonitorInstances on a terminated instance fails with InvalidState and its exact message,
    leaves Monitoring.State disabled, publishes no later datapoint and keeps its history, while the
    same call on its running twin moves it to pending/enabled."""
    ec2 = ctx.client("ec2")
    cw = ctx.client("cloudwatch")
    launched_at = datetime.now(timezone.utc)

    ami = _latest_al2023_ami(ec2)
    subnet, sg = _private_network(ctx, ec2)
    ids: list[str] = []
    ctx.on_cleanup(lambda: _terminate_all(ec2, ids))
    doomed = _launch(ec2, ami=ami, subnet=subnet, sg=sg, user_data=_USER_DATA, role="doomed")
    ids.append(doomed["InstanceId"])
    live = _launch(ec2, ami=ami, subnet=subnet, sg=sg, user_data=_USER_DATA, role="live")
    ids.append(live["InstanceId"])
    doomed_id, live_id = doomed["InstanceId"], live["InstanceId"]

    for iid in ids:
        _poll_until(lambda i=iid: _instance_state(ec2, i), lambda s: s == "running",
                    timeout_s=_RUNNING_BUDGET_S, interval_s=5.0,
                    description=f"instance {iid} reaching 'running'",
                    terminal_bad={"terminated", "shutting-down", "stopped"})

    # ---- history exists before the break -------------------------------------------------------- #
    history = _poll_until(lambda: _series(cw, doomed_id, launched_at), lambda d: len(d) >= 1,
                          timeout_s=_METRIC_BUDGET_S, interval_s=30.0,
                          description=f"instance {doomed_id} publishing its first CPUUtilization "
                                      f"datapoint on basic monitoring")
    history_stamps = {d["Timestamp"] for d in history}

    # ---- break exactly one thing: the instance is terminated ------------------------------------ #
    ec2.terminate_instances(InstanceIds=[doomed_id])
    _poll_until(lambda: _instance_state(ec2, doomed_id), lambda s: s == "terminated",
                timeout_s=180.0, interval_s=3.0,
                description=f"instance {doomed_id} reaching 'terminated'")
    terminated_at = datetime.now(timezone.utc)

    refusal = _error(lambda: ec2.monitor_instances(InstanceIds=[doomed_id]))
    want = ("InvalidState", "Instance is not in a supported state.")
    assert refusal == want, (
        f"MonitorInstances on terminated instance {doomed_id} returned error {refusal!r}; real AWS "
        f"answers {want!r}"
    )
    state = _describe(ec2, doomed_id)["Monitoring"]["State"]
    assert state == "disabled", (
        f"the refused MonitorInstances left terminated instance {doomed_id} at Monitoring.State="
        f"{state!r}; a refusal must not change the monitoring state"
    )

    # ---- positive control: the identical call on the live twin succeeds and takes effect ------- #
    resp = ec2.monitor_instances(InstanceIds=[live_id])
    reported = {m["InstanceId"]: m["Monitoring"]["State"] for m in resp["InstanceMonitorings"]}
    assert reported.get(live_id) in {"pending", "enabled"}, (
        f"MonitorInstances on running twin {live_id} reported {reported!r}"
    )
    switched_at = datetime.now(timezone.utc)
    _poll_until(lambda: _describe(ec2, live_id)["Monitoring"]["State"], lambda s: s == "enabled",
                timeout_s=180.0, interval_s=5.0,
                description=f"twin {live_id} reporting Monitoring.State='enabled'")

    epoch = int(terminated_at.timestamp())
    barrier = datetime.fromtimestamp(((epoch // 300) + 1) * 300 + 60, tz=timezone.utc)
    # Raises on timeout, so reaching the next line means the barrier was crossed.
    _poll_until(
        lambda: [d for d in _series(cw, live_id, launched_at)
                 if d["Timestamp"] > switched_at and int(d["Timestamp"].timestamp()) % 300 != 0
                 and d["Timestamp"] >= barrier],
        lambda dps: len(dps) >= 1, timeout_s=_METRIC_BUDGET_S, interval_s=30.0,
        description=(f"twin {live_id} publishing a 1-minute (off-5-minute-grid) CPUUtilization "
                     f"datapoint at or after the barrier {barrier.isoformat()}"),
    )

    # ---- effect absent on the refused instance, history intact --------------------------------- #
    after = _series(cw, doomed_id, launched_at)
    late = [d["Timestamp"].isoformat() for d in after if d["Timestamp"] >= terminated_at]
    assert not late, (
        f"terminated instance {doomed_id} has CPUUtilization buckets starting at or after its "
        f"termination ({terminated_at.isoformat()}): {late!r}; a terminated instance publishes "
        f"nothing, and a refused MonitorInstances must not revive it"
    )
    missing = sorted(t.isoformat() for t in history_stamps - {d["Timestamp"] for d in after})
    assert not missing, (
        f"pre-termination CPUUtilization datapoints {missing!r} for {doomed_id} are no longer "
        f"readable after termination; metric history outlives the instance"
    )
    assert _describe(ec2, doomed_id)["Monitoring"]["State"] == "disabled", (
        f"terminated instance {doomed_id} changed Monitoring.State after the refusal"
    )


def _error(fn) -> tuple[str, str]:
    try:
        resp = fn()
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED: {resp!r}")


def _series(cw, iid: str, since: datetime) -> list[dict]:
    """CPUUtilization at Period=60 on purpose: the finest period exposes the STORED resolution."""
    now = datetime.now(timezone.utc)
    dps = cw.get_metric_statistics(
        Namespace="AWS/EC2", MetricName="CPUUtilization",
        Dimensions=[{"Name": "InstanceId", "Value": iid}],
        StartTime=since - timedelta(minutes=10), EndTime=now + timedelta(minutes=1),
        Period=60, Statistics=["Average", "SampleCount"],
    )["Datapoints"]
    return sorted(dps, key=lambda d: d["Timestamp"])


def _tags(ctx_value: str, name: str) -> list[dict]:
    return [{"Key": "sim2real", "Value": ctx_value}, {"Key": "Name", "Value": name}]


def _private_network(ctx, ec2) -> tuple[str, str]:
    """A VPC of our own (no IGW: nothing here needs the internet). No default VPC is used."""
    name = ctx.unique_name("sim2real-xsvc-cwec2-")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ in {ctx.region} offers {_INSTANCE_TYPE!r}: {sorted(offered)!r}"
    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags(CHECK, name)}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=_SUBNET_CIDR, AvailabilityZone=usable[0],
                               TagSpecifications=[{"ResourceType": "subnet",
                                                   "Tags": _tags(CHECK, name)}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet)))
    sg = ec2.create_security_group(GroupName=name, Description="sim2real metrics check, no ingress",
                                   VpcId=vpc, TagSpecifications=[
                                       {"ResourceType": "security-group",
                                        "Tags": _tags(CHECK, name)}])["GroupId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_security_group(GroupId=sg)))
    return subnet, sg


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(Owners=["amazon"], Filters=[
        {"Name": "name", "Values": ["al2023-ami-2023.*-kernel-6.*-x86_64"]},
        {"Name": "state", "Values": ["available"]}])["Images"]
    assert images, "no Amazon-owned AL2023 x86_64 AMI is visible in this region"
    return max(images, key=lambda i: i["CreationDate"])["ImageId"]


def _launch(ec2, *, ami: str, subnet: str, sg: str, user_data: str, role: str) -> dict:
    return ec2.run_instances(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        SubnetId=subnet, SecurityGroupIds=[sg], UserData=user_data,
        Monitoring={"Enabled": False},
        CreditSpecification={"CpuCredits": "unlimited"},
        InstanceInitiatedShutdownBehavior="terminate",
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": _tags(CHECK, f"sim2real-{role}")},
            {"ResourceType": "volume", "Tags": _tags(CHECK, f"sim2real-{role}")},
        ],
    )["Instances"][0]


def _terminate_all(ec2, ids: list[str]) -> None:
    if not ids:
        return
    ec2.terminate_instances(InstanceIds=list(ids))
    deadline = time.monotonic() + 45.0
    while time.monotonic() < deadline:
        states = {_instance_state(ec2, i) for i in ids}
        if states <= {"terminated", None}:
            return
        time.sleep(3.0)


def _retry_dependency(fn, budget_s: float = 25.0) -> None:
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(3.0)


def _describe(ec2, iid: str) -> dict:
    return ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]


def _instance_state(ec2, iid: str):
    """None while DescribeInstances does not yet admit a just-launched id (eventual consistency)."""
    try:
        return _describe(ec2, iid)["State"]["Name"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            return None
        raise


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, terminal_bad=frozenset()):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if isinstance(last, str) and last in terminal_bad:
            raise AssertionError(f"{description}: reached terminal value {last!r}")
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not happen within {timeout_s}s; last read {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
