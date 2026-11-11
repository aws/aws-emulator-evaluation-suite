"""monitor-reaches-active-without-probes."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "monitor-reaches-active-without-probes"
GROUP = "state"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A monitor created with zero probes is INACTIVE and stays INACTIVE; adding an ICMP probe
    that leaves PENDING drives the monitor from INACTIVE to ACTIVE, so the monitor's state tracks
    its probes rather than activating on its own."""
    nm = ctx.client("networkmonitor")
    subnet_arn = _subnet_arn(ctx)
    name = ctx.unique_name("sim2real-nwm-mon-")
    created = nm.create_monitor(monitorName=name, aggregationPeriod=30)
    ctx.on_cleanup(lambda: _force_cleanup(ctx, name))
    assert created["state"] == "INACTIVE", f"unexpected initial state {created['state']!r}"

    # No probes: the monitor must not spontaneously become ACTIVE on its own — freeze detector:
    # repeated independent reads over a window must all agree, never a single sleep-then-check.
    _assert_frozen(
        lambda: nm.get_monitor(monitorName=name)["state"],
        "INACTIVE",
        duration_s=10.0,
        interval_s=2.0,
    )

    probe = nm.create_probe(
        monitorName=name,
        probe={"sourceArn": subnet_arn, "destination": "192.168.55.55", "protocol": "ICMP", "packetSize": 56},
    )
    probe_id = probe["probeId"]

    probe_state = _poll_until(
        lambda: nm.get_probe(monitorName=name, probeId=probe_id)["state"],
        lambda s: s == "ACTIVE",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert probe_state == "ACTIVE", f"expected probe to reach ACTIVE, got {probe_state!r}"

    final_state = _poll_until(
        lambda: nm.get_monitor(monitorName=name)["state"],
        lambda s: s == "ACTIVE",
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert final_state == "ACTIVE", f"monitor with an ACTIVE probe should itself be ACTIVE, got {final_state!r}"


# ===== helpers =====
def _assert_frozen(probe, expected, duration_s=10.0, interval_s=2.0):
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        actual = probe()
        assert actual == expected, f"expected to stay {expected!r}, observed {actual!r}"
        time.sleep(interval_s)


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
        CidrBlock="10.66.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    az = next(z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"] if z["State"] == "available")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.66.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-subnet-")}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:ec2:{ctx.region}:{account_id}:subnet/{subnet_id}"


def _force_cleanup(ctx, monitor_name):
    from botocore.exceptions import ClientError

    nm = ctx.client("networkmonitor")
    try:
        mon = nm.get_monitor(monitorName=monitor_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    for p in mon.get("probes", []):
        probe_id = p["probeId"] if isinstance(p, dict) else p
        deadline = time.monotonic() + 180.0
        while time.monotonic() < deadline:
            try:
                state = nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                break
            if state != "PENDING":
                break
            time.sleep(2.0)
        try:
            nm.delete_probe(monitorName=monitor_name, probeId=probe_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 180.0
        while True:
            try:
                nm.get_probe(monitorName=monitor_name, probeId=probe_id)
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                break
            if time.monotonic() >= deadline:
                raise TimeoutError(f"probe {probe_id} still present after DeleteProbe")
            time.sleep(2.0)
    try:
        nm.delete_monitor(monitorName=monitor_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
