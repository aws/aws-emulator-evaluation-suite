"""get-probe-not-found."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-probe-not-found"
GROUP = "errors"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetProbe on a real monitor with a never-created probeId fails with ResourceNotFoundException
    and the exact message, while GetProbe on a real probe of that monitor succeeds."""
    nm = ctx.client("networkmonitor")
    name = ctx.unique_name("sim2real-nm-mon-")
    nm.create_monitor(monitorName=name, aggregationPeriod=30, tags={"sim2real": "audit"})
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=name))

    subnet_arn = _subnet_arn(ctx)
    probe = nm.create_probe(
        monitorName=name,
        probe={"sourceArn": subnet_arn, "destination": "192.168.65.65", "protocol": "ICMP", "packetSize": 56},
    )
    probe_id = probe["probeId"]
    ctx.on_cleanup(lambda: _delete_probe(ctx, name, probe_id))

    # positive control: GetProbe on the real probe succeeds
    got = nm.get_probe(monitorName=name, probeId=probe_id)
    assert got["probeId"] == probe_id, f"expected probeId {probe_id}, got {got.get('probeId')}"

    fake_probe_id = "probe-" + "a" * 25  # matches ^probe-[a-z0-9A-Z-]{21,64}$, never created

    err = _error(lambda: nm.get_probe(monitorName=name, probeId=fake_probe_id))
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err['Code']!r}"
    expected = f"No existing probe {fake_probe_id} found for account {ctx.account} and monitorName {name}."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"


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
        CidrBlock="10.85.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    az = next(z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"] if z["State"] == "available")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.85.1.0/24",
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
