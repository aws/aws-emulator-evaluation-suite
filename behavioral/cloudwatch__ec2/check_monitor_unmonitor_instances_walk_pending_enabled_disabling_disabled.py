"""monitor-unmonitor-instances-walk-pending-enabled-disabling-disabled."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "monitor-unmonitor-instances-walk-pending-enabled-disabling-disabled"
GROUP = "metric-emission"
SERVICES = ["ec2"]

_INSTANCE_TYPE = "t3.micro"
_AMI_NAME_PATTERN = "al2023-ami-2023.*-kernel-*-x86_64"

_RUNNING_BUDGET_S = 300.0
_STATE_BUDGET_S = 180.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A basic-monitoring instance reports Monitoring.State disabled; MonitorInstances answers
    pending and the state settles to enabled, then UnmonitorInstances answers disabling and the
    state settles back to disabled, each echoed by DescribeInstances.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/manage-detailed-monitoring.html
    """
    ec2 = ctx.client("ec2")
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
    launched = resp["Instances"][0]["Monitoring"]["State"]
    assert launched == "disabled", (
        f"RunInstances without Monitoring reported Monitoring.State={launched!r}, expected basic "
        f"monitoring 'disabled'"
    )

    got = _poll(lambda: _instance_field(ec2, iid, "State"), lambda s: s == "running",
                _budget_s(ctx, _RUNNING_BUDGET_S), 5.0, f"instance {iid} reaching running")
    assert got == "running", f"instance {iid} settled at {got!r}"
    base = _instance_field(ec2, iid, "Monitoring")
    assert base == "disabled", f"instance {iid} launched with Monitoring.State={base!r}, not basic"

    up = ec2.monitor_instances(InstanceIds=[iid])["InstanceMonitorings"]
    assert [m["InstanceId"] for m in up] == [iid], f"MonitorInstances answered for {up!r}"
    assert up[0]["Monitoring"]["State"] == "pending", (
        f"MonitorInstances reported {up[0]['Monitoring']!r}; a basic instance moves to 'pending'"
    )
    got = _poll(lambda: _instance_field(ec2, iid, "Monitoring"), lambda s: s == "enabled",
                _budget_s(ctx, _STATE_BUDGET_S), 3.0,
                f"instance {iid} Monitoring.State reaching enabled")
    assert got == "enabled", f"Monitoring.State settled at {got!r} after MonitorInstances"

    down = ec2.unmonitor_instances(InstanceIds=[iid])["InstanceMonitorings"]
    assert [m["InstanceId"] for m in down] == [iid], f"UnmonitorInstances answered for {down!r}"
    assert down[0]["Monitoring"]["State"] == "disabling", (
        f"UnmonitorInstances reported {down[0]['Monitoring']!r}; an enabled instance moves to "
        f"'disabling'"
    )
    got = _poll(lambda: _instance_field(ec2, iid, "Monitoring"), lambda s: s == "disabled",
                _budget_s(ctx, _STATE_BUDGET_S), 3.0,
                f"instance {iid} Monitoring.State reaching disabled")
    assert got == "disabled", f"Monitoring.State settled at {got!r} after UnmonitorInstances"
    # Teardown in the body, under the check's own ceiling rather than the cleanup bound;
    # the registered net stays as the backstop on any failure path.
    _teardown(ec2, state)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


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
