"""access-denied-without-permission-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "access-denied-without-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A probeId that exists under one monitor is not resolvable through a second, unrelated
    monitor: GetProbe there is rejected with ResourceNotFoundException, while the same probeId
    under its own monitor still resolves (positive control)."""
    nm = ctx.client("networkmonitor")
    subnet_arn = _subnet_arn(ctx)

    monitor_a = ctx.unique_name("sim2real-nwm-mon-")
    monitor_b = ctx.unique_name("sim2real-nwm-mon-")
    nm.create_monitor(monitorName=monitor_a, aggregationPeriod=60)
    ctx.on_cleanup(lambda: _delete_monitor_and_probes(ctx, monitor_a))
    nm.create_monitor(monitorName=monitor_b, aggregationPeriod=60)
    ctx.on_cleanup(lambda: _delete_monitor_and_probes(ctx, monitor_b))

    probe = nm.create_probe(
        monitorName=monitor_a,
        probe={"sourceArn": subnet_arn, "destination": "192.168.90.90", "protocol": "ICMP", "packetSize": 56},
    )
    probe_id = probe["probeId"]

    # Wrong monitor: the probe must not be reachable, even though the probeId is real.
    err = _error(lambda: nm.get_probe(monitorName=monitor_b, probeId=probe_id))
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err['Code']!r}"
    expected = f"No existing probe {probe_id} found for account {ctx.account} and monitorName {monitor_b}."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    # Positive control: same probeId, correct (owning) monitor, must resolve.
    own = nm.get_probe(monitorName=monitor_a, probeId=probe_id)
    assert own["probeId"] == probe_id


# ===== helpers =====
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
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    az = next(z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"] if z["State"] == "available")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.91.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-subnet-")}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:ec2:{ctx.region}:{account_id}:subnet/{subnet_id}"


def _delete_monitor_and_probes(ctx, monitor_name):
    import time as _t
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
        deadline = _t.monotonic() + 180.0
        while _t.monotonic() < deadline:
            try:
                state = nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                break
            if state != "PENDING":
                break
            _t.sleep(2.0)
        try:
            nm.delete_probe(monitorName=monitor_name, probeId=probe_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = _t.monotonic() + 180.0
        while True:
            try:
                nm.get_probe(monitorName=monitor_name, probeId=probe_id)
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                break
            if _t.monotonic() >= deadline:
                raise TimeoutError(f"probe {probe_id} still present after DeleteProbe")
            _t.sleep(2.0)
    try:
        nm.delete_monitor(monitorName=monitor_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
