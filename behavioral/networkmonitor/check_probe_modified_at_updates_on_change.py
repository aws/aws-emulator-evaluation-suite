"""probe-modified-at-updates-on-change."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "probe-modified-at-updates-on-change"
GROUP = "state"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A probe's modifiedAt timestamp advances after a real configuration change
    (UpdateProbe), while createdAt never changes -- an emulator that fakes these
    volatile fields as static or as "now" on every read would fail this."""
    nm = ctx.client("networkmonitor")
    net = _create_vpc_and_subnet(ctx)
    monitor_name = _create_monitor(ctx)
    probe = nm.create_probe(
        monitorName=monitor_name,
        probe={"sourceArn": net["subnet_arn"], "destination": "203.0.113.80",
               "protocol": "ICMP", "packetSize": 56},
    )
    probe_id = probe["probeId"]
    ctx.on_cleanup(lambda: nm.delete_probe(monitorName=monitor_name, probeId=probe_id))

    _poll_until(
        lambda: nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"],
        lambda s: s != "PENDING",
        timeout_s=300.0,
        interval_s=10.0,
    )

    before = nm.get_probe(monitorName=monitor_name, probeId=probe_id)
    created_at_before = before["createdAt"]
    modified_at_before = before["modifiedAt"]

    nm.update_probe(monitorName=monitor_name, probeId=probe_id, packetSize=128)

    after = _poll_until(
        lambda: nm.get_probe(monitorName=monitor_name, probeId=probe_id),
        lambda p: p["packetSize"] == 128 and p["modifiedAt"] > modified_at_before,
        timeout_s=60.0,
        interval_s=5.0,
    )

    assert after["createdAt"] == created_at_before, (
        "createdAt must never change after the initial creation"
    )
    assert after["modifiedAt"] > modified_at_before, (
        f"modifiedAt must advance after UpdateProbe: before={modified_at_before!r} "
        f"after={after['modifiedAt']!r}"
    )


def _poll_until(probe_fn, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe_fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value: {last!r}")


def _create_vpc_and_subnet(ctx):
    ec2 = ctx.client("ec2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.235.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nm-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.235.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nm-subnet-")}],
        }],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    subnet_arn = f"arn:aws:ec2:{ctx.region}:{account_id}:subnet/{subnet_id}"
    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "subnet_arn": subnet_arn}


def _create_monitor(ctx, aggregation_period=30):
    nm = ctx.client("networkmonitor")
    name = ctx.unique_name("sim2real-nm-mon-")
    nm.create_monitor(monitorName=name, aggregationPeriod=aggregation_period)
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
