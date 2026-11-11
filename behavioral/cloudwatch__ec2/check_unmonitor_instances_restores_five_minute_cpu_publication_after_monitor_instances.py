"""unmonitor-instances-restores-five-minute-cpu-publication-after-monitor-instances."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unmonitor-instances-restores-five-minute-cpu-publication-after-monitor-instances"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "ec2"]

_INSTANCE_TYPE = "t3.micro"
_AMI_NAME_PATTERN = "al2023-ami-2023.*-kernel-*-x86_64"

_RUNNING_BUDGET_S = 300.0
_STATE_BUDGET_S = 180.0
#: First 1-minute (off-grid) datapoint after MonitorInstances took effect; the launch-to-off-grid
#: sequence typically takes ~400 s.
_DETAILED_BUDGET_S = 600.0
#: After `disabled`, one full basic period is allowed for the restore to land before the cadence
#: is graded, then a whole 5-minute bucket must be published and read back.
_RESTORE_GRACE_S = 300
_RESTORED_BUDGET_S = 900.0


# timing:real-time — metric: 300 s https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/manage-detailed-monitoring.html
@tags("axis:happy-path", "concern:metrics", "dp:api", "plane:data", "cap:c1", "cap:c5", "timing:real-time")
def run(ctx) -> None:
    """After MonitorInstances has demonstrably produced 1-minute CPUUtilization, UnmonitorInstances
    walks Monitoring.State to disabled and CloudWatch returns to publishing the series only on
    5-minute boundaries, while still publishing it.
    """
    ec2 = ctx.client("ec2")
    cw = ctx.client("cloudwatch")
    token = ctx.unique_name("sim2real-xsvc-cwunmon-")
    tag_spec = [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real-run", "Value": token}]

    state: dict = {"vpc": None, "subnet": None, "instances": []}
    state["vpc"] = ec2.create_vpc(
        CidrBlock="10.44.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _teardown(ec2, state))
    state["subnet"] = ec2.create_subnet(
        VpcId=state["vpc"], CidrBlock="10.44.1.0/24",
        AvailabilityZone=_usable_az(ec2, _INSTANCE_TYPE),
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_spec}],
    )["Subnet"]["SubnetId"]

    resp = ec2.run_instances(
        ImageId=_latest_al2023_ami(ec2), InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        SubnetId=state["subnet"],
        TagSpecifications=[{"ResourceType": "instance", "Tags": tag_spec},
                           {"ResourceType": "volume", "Tags": tag_spec}],
    )
    iid = resp["Instances"][0]["InstanceId"]
    state["instances"].append(iid)

    got = _poll(lambda: _instance_field(ec2, iid, "State"), lambda s: s == "running",
                _RUNNING_BUDGET_S, 5.0, f"instance {iid} reaching running")
    assert got == "running", f"instance {iid} settled at {got!r}"
    base = _instance_field(ec2, iid, "Monitoring")
    assert base == "disabled", f"instance {iid} launched with Monitoring.State={base!r}, not basic"

    up = ec2.monitor_instances(InstanceIds=[iid])["InstanceMonitorings"]
    assert [m["InstanceId"] for m in up] == [iid], f"MonitorInstances answered for {up!r}"
    assert up[0]["Monitoring"]["State"] == "pending", (
        f"MonitorInstances reported {up[0]['Monitoring']!r}; a basic instance moves to 'pending'"
    )
    got = _poll(lambda: _instance_field(ec2, iid, "Monitoring"), lambda s: s == "enabled",
                _STATE_BUDGET_S, 5.0, f"instance {iid} Monitoring.State reaching enabled")
    assert got == "enabled", f"Monitoring.State settled at {got!r} after MonitorInstances"
    enabled_at = datetime.now(timezone.utc)
    off_grid = _poll(
        lambda: [d for d in _cpu(cw, iid, minutes=40) if d["Timestamp"] >= enabled_at
                 - timedelta(minutes=1) and _off_grid(d)],
        lambda dps: len(dps) >= 1, _DETAILED_BUDGET_S, 20.0,
        f"a 1-minute (off 5-minute grid) CPUUtilization datapoint for {iid} after MonitorInstances",
    )
    assert off_grid, (
        f"no off-grid CPUUtilization datapoint appeared for {iid} within {_DETAILED_BUDGET_S}s of "
        f"Monitoring.State=enabled at {enabled_at.isoformat()}; all datapoints: "
        f"{[d['Timestamp'].isoformat() for d in _cpu(cw, iid, minutes=40)]!r}"
    )

    down = ec2.unmonitor_instances(InstanceIds=[iid])["InstanceMonitorings"]
    assert [m["InstanceId"] for m in down] == [iid], f"UnmonitorInstances answered for {down!r}"
    assert down[0]["Monitoring"]["State"] == "disabling", (
        f"UnmonitorInstances reported {down[0]['Monitoring']!r}; an enabled instance moves to "
        f"'disabling'"
    )
    got = _poll(lambda: _instance_field(ec2, iid, "Monitoring"), lambda s: s == "disabled",
                _STATE_BUDGET_S, 5.0, f"instance {iid} Monitoring.State reaching disabled")
    assert got == "disabled", f"Monitoring.State settled at {got!r} after UnmonitorInstances"
    disabled_at = datetime.now(timezone.utc)
    graded_from = disabled_at + timedelta(seconds=_RESTORE_GRACE_S)

    # Positive control for the absence below: the series is still being published after the
    # restore -- a 5-minute bucket that starts after the grace window has been written. Its
    # bucket covers [B, B+300), so by the time it is readable any 1-minute datapoints inside it
    # would have been readable too.
    def _restored_bucket():
        return [d for d in _cpu(cw, iid, minutes=40)
                if d["Timestamp"] >= graded_from and not _off_grid(d)]

    buckets = _poll(_restored_bucket, lambda b: len(b) >= 1, _RESTORED_BUDGET_S, 30.0,
                    f"a 5-minute CPUUtilization bucket for {iid} starting after "
                    f"{graded_from.isoformat()}")
    assert buckets, (
        f"{iid} published no on-grid CPUUtilization datapoint starting after "
        f"{graded_from.isoformat()} within {_RESTORED_BUDGET_S}s of disabling; the instance "
        f"stopped publishing altogether rather than returning to 5-minute periods. All "
        f"datapoints: {[d['Timestamp'].isoformat() for d in _cpu(cw, iid, minutes=40)]!r}"
    )
    first_restored = min(d["Timestamp"] for d in buckets)
    window_end = first_restored + timedelta(seconds=300)
    all_dps = _cpu(cw, iid, minutes=40)
    late_one_minute = [d["Timestamp"].isoformat() for d in all_dps
                       if graded_from <= d["Timestamp"] < window_end and _off_grid(d)]
    assert not late_one_minute, (
        f"after UnmonitorInstances reached 'disabled' at {disabled_at.isoformat()}, {iid} still "
        f"published 1-minute CPUUtilization datapoints at {late_one_minute!r} inside "
        f"[{graded_from.isoformat()}, {window_end.isoformat()}); the restore changed the state "
        f"string but not the publication cadence"
    )
    # Same lower bound as the off-grid poll: a minute bucket is stamped at its start.
    before = [d for d in all_dps
              if enabled_at - timedelta(minutes=1) <= d["Timestamp"] < disabled_at and _off_grid(d)]
    assert before, (
        f"the off-grid datapoints proving detailed monitoring are no longer readable for {iid}; "
        f"the before/after contrast is gone. All datapoints: "
        f"{[d['Timestamp'].isoformat() for d in all_dps]!r}"
    )
    assert _instance_field(ec2, iid, "Monitoring") == "disabled", (
        f"{iid} drifted off Monitoring.State=disabled during the cadence wait"
    )
    # Teardown in the body, under the check's own ceiling rather than the 60 s cleanup bound;
    # the registered net stays as the backstop on any failure path.
    _teardown(ec2, state)


def _off_grid(d) -> bool:
    return int(d["Timestamp"].timestamp()) % 300 != 0


def _cpu(cw, instance_id: str, *, minutes: int) -> list:
    """CPUUtilization at Period=60 -- the finest read, which cannot invent buckets never stored."""
    now = datetime.now(timezone.utc)
    dps = cw.get_metric_statistics(
        Namespace="AWS/EC2", MetricName="CPUUtilization",
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=now - timedelta(minutes=minutes), EndTime=now + timedelta(minutes=1),
        Period=60, Statistics=["Average"],
    )["Datapoints"]
    return sorted(dps, key=lambda d: d["Timestamp"])


def _instance_field(ec2, instance_id: str, field: str):
    try:
        res = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            return None  # eventual consistency right after RunInstances
        raise
    for r in res:
        for inst in r["Instances"]:
            return inst[field]["State"] if field == "Monitoring" else inst[field]["Name"]
    return None


def _poll(probe, ok, budget_s: float, interval_s: float, what: str):
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if ok(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} did not happen within {budget_s}s; last read {last!r}")


def _usable_az(ec2, instance_type: str) -> str:
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {instance_type!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[{"Name": "name", "Values": [_AMI_NAME_PATTERN]},
                 {"Name": "architecture", "Values": ["x86_64"]},
                 {"Name": "state", "Values": ["available"]}],
    )["Images"]
    assert images, f"no Amazon-owned available image matches {_AMI_NAME_PATTERN!r}"
    return max(images, key=lambda i: i["CreationDate"])["ImageId"]


def _teardown(ec2, state: dict) -> None:
    """Terminate first (the only billable thing), then subnet and VPC. Idempotent: only the
    not-found codes count as gone; any other failure, or a delete still blocked at its deadline, raises."""
    ids = [i for i in state["instances"] if i]
    if ids:
        try:
            ec2.terminate_instances(InstanceIds=ids)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise
        for iid in ids:
            deadline = time.monotonic() + 240.0
            while _instance_field(ec2, iid, "State") not in ("terminated", None):
                if time.monotonic() > deadline:
                    raise RuntimeError(f"instance {iid} not terminated within 240 s")
                time.sleep(2.0)
        state["instances"] = []
    for key, fn, gone in (
        ("subnet", lambda: ec2.delete_subnet(SubnetId=state["subnet"]), "InvalidSubnetID.NotFound"),
        ("vpc", lambda: ec2.delete_vpc(VpcId=state["vpc"]), "InvalidVpcID.NotFound"),
    ):
        if not state[key]:
            continue
        deadline = time.monotonic() + 90.0
        while True:
            try:
                fn()
                state[key] = None
                break
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == gone:
                    state[key] = None
                    break
                if code != "DependencyViolation" or time.monotonic() > deadline:
                    raise
            time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
