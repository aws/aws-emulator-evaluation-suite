"""create-probe-tcp-missing-port-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-probe-tcp-missing-port-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProbe rejects a TCP probe that omits the required destinationPort with
    ValidationException, no probe is left attached to the monitor, and an ICMP probe (which
    needs no port) still succeeds on the very same monitor (positive control).
    """
    nm = ctx.client("networkmonitor")
    subnet_arn = _subnet_arn(ctx)
    monitor_name = ctx.unique_name("sim2real-nwm-mon-")
    nm.create_monitor(monitorName=monitor_name, aggregationPeriod=60)
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=monitor_name))

    err = _error(
        lambda: nm.create_probe(
            monitorName=monitor_name,
            probe={"sourceArn": subnet_arn, "destination": "192.168.63.63", "protocol": "TCP", "packetSize": 56},
        )
    )
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
    expected = "Destination port must be provided for TCP protocol."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    after_reject = nm.get_monitor(monitorName=monitor_name)
    assert len(after_reject.get("probes", [])) == 0, "the rejected TCP probe must not have been attached"

    ok_probe = nm.create_probe(
        monitorName=monitor_name,
        probe={"sourceArn": subnet_arn, "destination": "192.168.63.63", "protocol": "ICMP", "packetSize": 56},
    )
    probe_id = ok_probe["probeId"]
    ctx.on_cleanup(lambda: _delete_probe(ctx, monitor_name, probe_id))
    fetched = nm.get_probe(monitorName=monitor_name, probeId=probe_id)
    assert fetched["protocol"] == "ICMP", f"expected ICMP protocol on the accepted probe, got {fetched.get('protocol')!r}"


def _error(fn):
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _subnet_arn(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.82.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    az = next(z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"] if z["State"] == "available")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.82.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-subnet-")}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:ec2:{ctx.region}:{account_id}:subnet/{subnet_id}"


def _delete_probe(ctx, monitor_name, probe_id, timeout_s=300.0, interval_s=5.0):
    """Teardown: wait for the probe to leave PENDING (DeleteProbe refuses it there), delete it,
    and wait until it is gone so the monitor delete that follows is accepted."""
    import time
    from botocore.exceptions import ClientError

    nm = ctx.client("networkmonitor")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if state not in ("PENDING", "DELETING"):
            try:
                nm.delete_probe(monitorName=monitor_name, probeId=probe_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        time.sleep(interval_s)
    raise AssertionError(f"teardown: probe {probe_id} still present after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
