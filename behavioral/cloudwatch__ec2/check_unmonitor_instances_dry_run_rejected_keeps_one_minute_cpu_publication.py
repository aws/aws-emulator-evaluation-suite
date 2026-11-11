"""unmonitor-instances-dry-run-rejected-keeps-one-minute-cpu-publication."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unmonitor-instances-dry-run-rejected-keeps-one-minute-cpu-publication"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "ec2"]

_INSTANCE_TYPE = "t3.micro"
_AMI_NAME_PATTERN = "al2023-ami-2023.*-kernel-*-x86_64"

_RUNNING_BUDGET_S = 300.0
_STATE_BUDGET_S = 180.0
_DRY_RUN_MSG = "Request would have succeeded, but DryRun flag is set."
#: Wait for an off-grid (1-minute) datapoint stamped after the dry run; the launch-to-off-grid
#: sequence typically takes ~400 s.
_DETAILED_BUDGET_S = 720.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/manage-detailed-monitoring.html
@tags(
    "axis:rejection",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "cap:c1",
    "cap:c5",
    "timing:real-time",
)
def run(ctx) -> None:
    """A valid UnmonitorInstances with DryRun=True is refused DryRunOperation and changes nothing:
    Monitoring.State stays enabled and 1-minute CPUUtilization keeps publishing after the refusal;
    the same call without DryRun walks the state to disabled.
    """
    ec2 = ctx.client("ec2")
    cw = ctx.client("cloudwatch")
    token = ctx.unique_name("sim2real-xsvc-cwdry-")
    tag_spec = [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real-run", "Value": token}]

    state: dict = {"vpc": None, "subnet": None, "instances": []}
    state["vpc"] = ec2.create_vpc(
        CidrBlock="10.45.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_spec}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _teardown(ec2, state))
    state["subnet"] = ec2.create_subnet(
        VpcId=state["vpc"], CidrBlock="10.45.1.0/24",
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
    ec2.monitor_instances(InstanceIds=[iid])
    got = _poll(lambda: _instance_field(ec2, iid, "Monitoring"), lambda s: s == "enabled",
                _STATE_BUDGET_S, 5.0, f"instance {iid} Monitoring.State reaching enabled")
    assert got == "enabled", f"Monitoring.State settled at {got!r} after MonitorInstances"

    try:
        dry = ec2.unmonitor_instances(InstanceIds=[iid], DryRun=True)
        raise AssertionError(
            f"UnmonitorInstances with DryRun=True SUCCEEDED ({dry.get('InstanceMonitorings')!r}); "
            f"a dry run must answer DryRunOperation and change nothing"
        )
    except ClientError as err:
        code, message = err.response["Error"]["Code"], err.response["Error"]["Message"]
    assert code == "DryRunOperation", (
        f"a valid DryRun UnmonitorInstances was refused with {code!r}, expected 'DryRunOperation'"
    )
    assert message == _DRY_RUN_MSG, (
        f"the DryRun UnmonitorInstances refusal said {message!r}, expected {_DRY_RUN_MSG!r}"
    )
    dry_at = datetime.now(timezone.utc)
    after_dry = _instance_field(ec2, iid, "Monitoring")
    assert after_dry == "enabled", (
        f"Monitoring.State is {after_dry!r} right after a REFUSED dry-run UnmonitorInstances; it "
        f"must still be 'enabled'"
    )

    late = _poll(
        lambda: [d for d in _cpu(cw, iid, minutes=40)
                 if d["Timestamp"] >= dry_at + timedelta(seconds=60) and _off_grid(d)],
        lambda dps: len(dps) >= 1, _DETAILED_BUDGET_S, 20.0,
        f"a 1-minute (off 5-minute grid) CPUUtilization datapoint for {iid} stamped after the "
        f"refused dry run at {dry_at.isoformat()}",
    )
    assert late, f"no 1-minute datapoint for {iid} after the dry run"
    still = _instance_field(ec2, iid, "Monitoring")
    assert still == "enabled", (
        f"Monitoring.State drifted to {still!r} after the refused dry run; nothing else touched it"
    )

    down = ec2.unmonitor_instances(InstanceIds=[iid])["InstanceMonitorings"]
    assert [m["InstanceId"] for m in down] == [iid], f"UnmonitorInstances answered for {down!r}"
    assert down[0]["Monitoring"]["State"] == "disabling", (
        f"the non-dry UnmonitorInstances reported {down[0]['Monitoring']!r}, expected 'disabling'"
    )
    got = _poll(lambda: _instance_field(ec2, iid, "Monitoring"), lambda s: s == "disabled",
                _STATE_BUDGET_S, 5.0, f"instance {iid} Monitoring.State reaching disabled")
    assert got == "disabled", f"Monitoring.State settled at {got!r} after the real Unmonitor"
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
