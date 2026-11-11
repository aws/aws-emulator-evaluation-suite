"""create-monitor-with-embedded-probes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-monitor-with-embedded-probes"
GROUP = "state"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMonitor can embed a probe directly in the same call (probes=[...]).
    The probe shows up on a subsequent GetMonitor with the exact fields supplied,
    and it independently reaches ACTIVE like a probe added via CreateProbe."""
    nm = ctx.client("networkmonitor")
    net = _create_vpc_and_subnet(ctx)
    name = ctx.unique_name("sim2real-nm-mon-")

    create_resp = nm.create_monitor(
        monitorName=name,
        aggregationPeriod=30,
        probes=[{
            "sourceArn": net["subnet_arn"],
            "destination": "203.0.113.20",
            "protocol": "ICMP",
            "packetSize": 56,
        }],
    )
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=name))
    assert create_resp["monitorName"] == name, (
        f"expected CreateMonitor to echo monitorName {name!r}, got {create_resp['monitorName']!r}"
    )

    monitor = nm.get_monitor(monitorName=name)
    probes = monitor.get("probes", [])
    assert len(probes) == 1, f"expected exactly 1 embedded probe, got {len(probes)}"
    embedded = probes[0]
    assert embedded["destination"] == "203.0.113.20", (
        f"expected embedded probe destination 203.0.113.20, got {embedded['destination']!r}"
    )
    assert embedded["protocol"] == "ICMP", (
        f"expected embedded probe protocol ICMP, got {embedded['protocol']!r}"
    )
    assert embedded["sourceArn"] == net["subnet_arn"], (
        f"expected embedded probe sourceArn {net['subnet_arn']!r}, got {embedded['sourceArn']!r}"
    )
    probe_id = embedded["probeId"]
    ctx.on_cleanup(lambda: nm.delete_probe(monitorName=name, probeId=probe_id))

    final_probe = _poll_until(
        lambda: nm.get_probe(monitorName=name, probeId=probe_id),
        lambda p: p["state"] in ("ACTIVE", "ERROR"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert final_probe["state"] == "ACTIVE", (
        f"expected embedded probe to reach ACTIVE, got {final_probe['state']}"
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
        CidrBlock="10.218.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nm-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.218.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nm-subnet-")}],
        }],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    subnet_arn = f"arn:aws:ec2:{ctx.region}:{account_id}:subnet/{subnet_id}"
    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "subnet_arn": subnet_arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
