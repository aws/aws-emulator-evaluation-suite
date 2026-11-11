"""update-probe-persists-packet-size."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-probe-persists-packet-size"
GROUP = "update-semantics"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateProbe(packetSize=...) durably changes the probe's configured packet size, observable
    via a subsequent GetProbe.
    """
    nm = ctx.client("networkmonitor")
    subnet_arn = _subnet_arn(ctx)
    monitor_name = ctx.unique_name("sim2real-nwm-mon-")
    nm.create_monitor(monitorName=monitor_name, aggregationPeriod=60)
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=monitor_name))

    probe = nm.create_probe(
        monitorName=monitor_name,
        probe={"sourceArn": subnet_arn, "destination": "192.168.61.61", "protocol": "ICMP", "packetSize": 64},
    )
    probe_id = probe["probeId"]
    ctx.on_cleanup(lambda: _delete_probe_and_wait(ctx, monitor_name, probe_id))
    assert probe["packetSize"] == 64, f"expected packetSize 64 on create, got {probe['packetSize']!r}"

    # A probe must leave the transient PENDING state before UpdateProbe is accepted.
    active_state = _poll_until(
        lambda: nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"],
        lambda s: s != "PENDING",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert active_state == "ACTIVE", f"expected probe to converge to ACTIVE before update, got {active_state!r}"

    nm.update_probe(monitorName=monitor_name, probeId=probe_id, packetSize=128)

    final_size = _poll_until(
        lambda: nm.get_probe(monitorName=monitor_name, probeId=probe_id)["packetSize"],
        lambda s: s == 128,
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert final_size == 128, f"expected UpdateProbe(packetSize=128) to persist, GetProbe returned {final_size!r}"


# ===== helpers =====
def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _subnet_arn(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.80.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    az = next(z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"] if z["State"] == "available")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.80.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-subnet-")}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:ec2:{ctx.region}:{account_id}:subnet/{subnet_id}"


def _delete_probe_and_wait(ctx, monitor_name, probe_id, timeout_s=240.0, interval_s=2.0):
    nm = ctx.client("networkmonitor")
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if state != "PENDING":
            break
        time.sleep(interval_s)
    try:
        nm.delete_probe(monitorName=monitor_name, probeId=probe_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            nm.get_probe(monitorName=monitor_name, probeId=probe_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if time.monotonic() >= deadline:
            raise TimeoutError(f"probe {probe_id} still present after DeleteProbe")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
