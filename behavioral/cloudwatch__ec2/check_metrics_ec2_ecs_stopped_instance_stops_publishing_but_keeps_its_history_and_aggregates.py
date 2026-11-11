"""metrics-ec2-ecs-stopped-instance-stops-publishing-but-keeps-its-history-and-aggregates."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "metrics-ec2-ecs-stopped-instance-stops-publishing-but-keeps-its-history-and-aggregates"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "ec2"]

_INSTANCE_TYPE = "t3.micro"
_VPC_CIDR = "10.94.0.0/16"
_SUBNET_CIDR = "10.94.1.0/24"
_RUNNING_BUDGET_S = 300.0
_METRIC_BUDGET_S = 900.0
_USER_DATA = "#!/bin/bash\nshutdown -h +40\n"


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/manage-detailed-monitoring.html
@tags("axis:happy-path", "cap:c4", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Two detailed-monitoring instances publish CPUUtilization that the InstanceType and ImageId
    aggregates cover (SampleCount and Maximum at least theirs, Unit Percent); a stopped one
    publishes no later bucket but keeps its history while its twin keeps running."""
    ec2 = ctx.client("ec2")
    cw = ctx.client("cloudwatch")
    launched_at = datetime.now(timezone.utc)

    ami = _latest_al2023_ami(ec2)
    subnet, sg = _private_network(ctx, ec2)
    ids: list[str] = []
    ctx.on_cleanup(lambda: _terminate_all(ec2, ids))
    a = _launch(ec2, ami=ami, subnet=subnet, sg=sg, user_data=_USER_DATA, role="stopped")
    ids.append(a["InstanceId"])
    b = _launch(ec2, ami=ami, subnet=subnet, sg=sg, user_data=_USER_DATA, role="twin")
    ids.append(b["InstanceId"])
    a_id, b_id = a["InstanceId"], b["InstanceId"]

    for iid in ids:
        _poll_until(lambda i=iid: _instance_state(ec2, i), lambda s: s == "running",
                    timeout_s=_RUNNING_BUDGET_S, interval_s=5.0,
                    description=f"instance {iid} reaching 'running'",
                    terminal_bad={"terminated", "shutting-down", "stopped"})
        mon = _poll_until(lambda i=iid: _describe(ec2, i)["Monitoring"]["State"],
                          lambda s: s in ("enabled", "disabled"),
                          timeout_s=_RUNNING_BUDGET_S, interval_s=5.0,
                          description=f"instance {iid} Monitoring.State settling")
        assert mon == "enabled", f"instance {iid} launched with Monitoring.Enabled=True reports {mon!r}"

    inst_dims = {i: [{"Name": "InstanceId", "Value": i}] for i in ids}

    # ---- both publish at 1-minute resolution -------------------------------------------------- #
    def _common_minutes() -> list[datetime]:
        sa = {d["Timestamp"] for d in _series(cw, inst_dims[a_id], launched_at)}
        sb = {d["Timestamp"] for d in _series(cw, inst_dims[b_id], launched_at)}
        return sorted(t for t in sa & sb if int(t.timestamp()) % 300 != 0)

    _poll_until(_common_minutes, lambda ts: len(ts) >= 2, timeout_s=_METRIC_BUDGET_S,
                interval_s=30.0,
                description=(f"both detailed-monitoring instances {ids!r} publishing CPUUtilization "
                             f"for at least two common off-5-minute-grid minutes"))

    # ---- aggregate series exist and bound the per-instance ones ------------------------------- #
    for dim_name, dim_value in (("InstanceType", _INSTANCE_TYPE), ("ImageId", ami)):
        agg_dims = [{"Name": dim_name, "Value": dim_value}]

        def _bounded_minutes(dims=agg_dims) -> list[tuple]:
            agg = {d["Timestamp"]: d for d in _series(cw, dims, launched_at)}
            pa = {d["Timestamp"]: d for d in _series(cw, inst_dims[a_id], launched_at)}
            pb = {d["Timestamp"]: d for d in _series(cw, inst_dims[b_id], launched_at)}
            return [(t, agg[t], pa[t], pb[t]) for t in sorted(set(agg) & set(pa) & set(pb))]

        rows = _poll_until(_bounded_minutes, lambda r: len(r) >= 1, timeout_s=600.0,
                           interval_s=30.0,
                           description=(f"the aggregate AWS/EC2 CPUUtilization series "
                                        f"[{dim_name}={dim_value}] publishing a minute that both "
                                        f"of our instances also published"))
        for t, agg, pa, pb in rows:
            assert agg["SampleCount"] >= pa["SampleCount"] + pb["SampleCount"], (
                f"aggregate [{dim_name}={dim_value}] at {t.isoformat()} has SampleCount "
                f"{agg['SampleCount']!r}, below the {pa['SampleCount']!r} + {pb['SampleCount']!r} "
                f"our two instances alone contributed"
            )
            assert agg["Maximum"] >= max(pa["Maximum"], pb["Maximum"]), (
                f"aggregate [{dim_name}={dim_value}] at {t.isoformat()} has Maximum "
                f"{agg['Maximum']!r}, below our instances' {pa['Maximum']!r}/{pb['Maximum']!r}"
            )
            assert agg.get("Unit") == "Percent", (
                f"aggregate [{dim_name}={dim_value}] carries Unit {agg.get('Unit')!r}"
            )

    # ---- stop one instance --------------------------------------------------------------------- #
    before = {d["Timestamp"] for d in _series(cw, inst_dims[a_id], launched_at)}
    ec2.stop_instances(InstanceIds=[a_id])
    _poll_until(lambda: _instance_state(ec2, a_id), lambda s: s == "stopped", timeout_s=300.0,
                interval_s=3.0, description=f"instance {a_id} reaching 'stopped'")
    stopped_at = datetime.now(timezone.utc)

    # Barrier: the running twin publishes two minutes that START after the stop was observed.
    _poll_until(lambda: [d for d in _series(cw, inst_dims[b_id], launched_at)
                         if d["Timestamp"] >= stopped_at + timedelta(seconds=60)],
                lambda dps: len(dps) >= 2, timeout_s=600.0, interval_s=20.0,
                description=(f"running twin {b_id} publishing two CPUUtilization minutes after "
                             f"{a_id} was observed stopped at {stopped_at.isoformat()}"))

    after = _series(cw, inst_dims[a_id], launched_at)
    late = [d["Timestamp"].isoformat() for d in after if d["Timestamp"] >= stopped_at]
    assert not late, (
        f"stopped instance {a_id} has CPUUtilization buckets starting at or after it was observed "
        f"stopped ({stopped_at.isoformat()}): {late!r}; a stopped instance publishes nothing"
    )
    missing = sorted(t.isoformat() for t in before - {d["Timestamp"] for d in after})
    assert not missing, (
        f"datapoints {missing!r} that {a_id} published before it was stopped are no longer "
        f"readable; stopping an instance must not erase its metric history"
    )
    assert _instance_state(ec2, b_id) == "running", f"twin {b_id} is no longer running"


def _series(cw, dims: list[dict], since: datetime) -> list[dict]:
    now = datetime.now(timezone.utc)
    dps = cw.get_metric_statistics(
        Namespace="AWS/EC2", MetricName="CPUUtilization", Dimensions=dims,
        StartTime=since - timedelta(minutes=10), EndTime=now + timedelta(minutes=1),
        Period=60, Statistics=["Average", "Maximum", "SampleCount"],
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
        Monitoring={"Enabled": True},
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
