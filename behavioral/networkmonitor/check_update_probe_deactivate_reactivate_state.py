"""update-probe-deactivate-reactivate-state."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-probe-deactivate-reactivate-state"
GROUP = "state"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateProbe(state=INACTIVE) deterministically deactivates a probe (stops billing without
    deleting it), and UpdateProbe(state=ACTIVE) reactivates it back to ACTIVE.
    """
    nm = ctx.client("networkmonitor")
    subnet_arn = _subnet_arn(ctx)
    monitor_name = ctx.unique_name("sim2real-nwm-mon-")
    nm.create_monitor(monitorName=monitor_name, aggregationPeriod=60)
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=monitor_name))

    probe = nm.create_probe(
        monitorName=monitor_name,
        probe={"sourceArn": subnet_arn, "destination": "192.168.50.51", "protocol": "ICMP", "packetSize": 56},
    )
    probe_id = probe["probeId"]
    ctx.on_cleanup(lambda: _delete_probe_and_wait(ctx, monitor_name, probe_id))

    # A probe must leave the transient PENDING state before UpdateProbe is accepted.
    active_state = _poll_until(
        lambda: nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"],
        lambda s: s != "PENDING",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert active_state == "ACTIVE", f"expected probe to converge to ACTIVE before update, got {active_state!r}"

    nm.update_probe(monitorName=monitor_name, probeId=probe_id, state="INACTIVE")
    state_after_deactivate = _poll_until(
        lambda: nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"],
        lambda s: s == "INACTIVE",
        timeout_s=240.0,
        interval_s=5.0,
    )
    assert state_after_deactivate == "INACTIVE", (
        f"expected INACTIVE after deactivation, got {state_after_deactivate!r}"
    )

    nm.update_probe(monitorName=monitor_name, probeId=probe_id, state="ACTIVE")
    state_after_reactivate = _poll_until(
        lambda: nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"],
        lambda s: s == "ACTIVE",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert state_after_reactivate == "ACTIVE", f"expected ACTIVE after reactivation, got {state_after_reactivate!r}"


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
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    az = next(z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"] if z["State"] == "available")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.77.1.0/24",
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
