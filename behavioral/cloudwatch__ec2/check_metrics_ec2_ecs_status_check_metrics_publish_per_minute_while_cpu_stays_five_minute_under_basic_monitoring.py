"""metrics-ec2-ecs-status-check-metrics-publish-per-minute-while-cpu-stays-five-minute-under-basic-monitoring."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = (
    "metrics-ec2-ecs-status-check-metrics-publish-per-minute-while-cpu-stays-five-minute-under-basic-monitoring"
)
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "ec2"]

_INSTANCE_TYPE = "t3.micro"
_VPC_CIDR = "10.92.0.0/16"
_SUBNET_CIDR = "10.92.1.0/24"
_STATUS_METRICS = ("StatusCheckFailed", "StatusCheckFailed_Instance", "StatusCheckFailed_System")
_RUNNING_BUDGET_S = 300.0
_METRIC_BUDGET_S = 1200.0
_USER_DATA = "#!/bin/bash\nshutdown -h +40\n"


# timing:real-time — metric: 300 s https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/manage-detailed-monitoring.html
@tags("axis:happy-path", "cap:c4", "concern:metrics", "concern:representation", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Under basic monitoring one instance's status-check metrics (Unit Count, value 0) have
    datapoints one minute apart while its CPUUtilization over the same window at Period=60 stays on
    the 5-minute grid, as EC2 documents for basic monitoring."""
    ec2 = ctx.client("ec2")
    cw = ctx.client("cloudwatch")
    launched_at = datetime.now(timezone.utc)

    ami = _latest_al2023_ami(ec2)
    subnet, sg = _private_network(ctx, ec2)
    ids: list[str] = []
    ctx.on_cleanup(lambda: _terminate_all(ec2, ids))
    inst = _launch(ec2, ami=ami, subnet=subnet, sg=sg, user_data=_USER_DATA, role="status")
    ids.append(inst["InstanceId"])
    iid = inst["InstanceId"]

    _poll_until(lambda: _instance_state(ec2, iid), lambda s: s == "running",
                timeout_s=_RUNNING_BUDGET_S, interval_s=5.0,
                description=f"instance {iid} reaching 'running'",
                terminal_bad={"terminated", "shutting-down", "stopped"})
    mon = _describe(ec2, iid)["Monitoring"]["State"]
    assert mon == "disabled", f"instance {iid} reports Monitoring.State={mon!r}, expected 'disabled'"

    def _off_grid(dps: list[dict]) -> list[dict]:
        return [d for d in dps if int(d["Timestamp"].timestamp()) % 300 != 0]

    def _ready() -> bool:
        sc = _series(cw, "StatusCheckFailed", iid, launched_at)
        cpu = _series(cw, "CPUUtilization", iid, launched_at)
        # CPU must have published at least one bucket AFTER a status datapoint exists, or the
        # grid assertion on CPU below would be vacuous.
        return len(sc) >= 3 and len(_off_grid(sc)) >= 1 and len(cpu) >= 1

    _poll_until(_ready, lambda ok: ok, timeout_s=_METRIC_BUDGET_S, interval_s=30.0,
                description=(f"instance {iid} publishing >= 3 StatusCheckFailed datapoints, at "
                             f"least one on a non-5-minute boundary, plus >= 1 CPUUtilization "
                             f"datapoint"))
    # The other two status metrics are published on the same schedule; give them one more poll
    # window rather than assuming they landed in the same read.
    for metric in _STATUS_METRICS[1:]:
        _poll_until(lambda m=metric: _off_grid(_series(cw, m, iid, launched_at)),
                    lambda dps: len(dps) >= 1, timeout_s=300.0, interval_s=20.0,
                    description=f"{metric} for {iid} publishing an off-5-minute-grid datapoint")

    for metric in _STATUS_METRICS:
        dps = _series(cw, metric, iid, launched_at)
        units = {d.get("Unit") for d in dps}
        assert units == {"Count"}, f"{metric} for {iid} carries Unit(s) {units!r}, expected 'Count'"
        worst = max(d["Maximum"] for d in dps)
        assert worst == 0.0, (
            f"{metric} for the healthy instance {iid} has Maximum {worst!r} over "
            f"{[(d['Timestamp'].isoformat(), d['Maximum']) for d in dps]!r}; a passing status check "
            f"publishes 0"
        )
        stamps = [int(d["Timestamp"].timestamp()) for d in dps]
        gaps = {b - a for a, b in zip(stamps, stamps[1:])}
        assert 60 in gaps, (
            f"{metric} for {iid} has no two datapoints one minute apart (gaps {sorted(gaps)!r}); "
            f"status-check metrics are 1-minute even under basic monitoring"
        )

    # ---- the contrast: CPU on the same instance, over the same window, is 5-minute only -------- #
    status = _series(cw, "StatusCheckFailed", iid, launched_at)
    cpu = _series(cw, "CPUUtilization", iid, launched_at)
    off = _off_grid(cpu)
    assert not off, (
        f"CPUUtilization for BASIC-monitoring instance {iid}, read at Period=60, returned buckets "
        f"at {[d['Timestamp'].isoformat() for d in off]!r} that are not 5-minute boundaries, while "
        f"its status checks are per-minute; CPU must stay on the 5-minute grid"
    )
    first, last = status[0]["Timestamp"], status[-1]["Timestamp"]
    cpu_in = [d for d in cpu if first <= d["Timestamp"] <= last]
    status_in = [d for d in status if first <= d["Timestamp"] <= last]
    assert len(status_in) > len(cpu_in), (
        f"over {first.isoformat()}..{last.isoformat()} StatusCheckFailed has {len(status_in)} "
        f"datapoints and CPUUtilization {len(cpu_in)}; the 1-minute metric must out-number the "
        f"5-minute one over the same span"
    )
    assert _describe(ec2, iid)["Monitoring"]["State"] == "disabled", (
        f"instance {iid} left basic monitoring during the check"
    )


def _series(cw, metric: str, iid: str, since: datetime) -> list[dict]:
    """Period=60 on purpose: the finest period exposes the STORED resolution."""
    now = datetime.now(timezone.utc)
    dps = cw.get_metric_statistics(
        Namespace="AWS/EC2", MetricName=metric,
        Dimensions=[{"Name": "InstanceId", "Value": iid}],
        StartTime=since - timedelta(minutes=10), EndTime=now + timedelta(minutes=1),
        Period=60, Statistics=["Average", "Maximum", "Sum", "SampleCount"],
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
