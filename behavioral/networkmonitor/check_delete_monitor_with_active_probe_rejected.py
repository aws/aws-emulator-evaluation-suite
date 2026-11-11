"""delete-monitor-with-active-probe-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-monitor-with-active-probe-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteMonitor on a monitor that still has a probe attached is rejected with
    ValidationException; the monitor and its probe both remain intact. Deleting the probe first
    and then the monitor (positive control, in the same file) succeeds.
    """
    nm = ctx.client("networkmonitor")
    subnet_arn = _subnet_arn(ctx)
    monitor_name = ctx.unique_name("sim2real-nwm-mon-")
    nm.create_monitor(monitorName=monitor_name, aggregationPeriod=60)
    ctx.on_cleanup(lambda: _force_cleanup(ctx, monitor_name))

    probe = nm.create_probe(
        monitorName=monitor_name,
        probe={"sourceArn": subnet_arn, "destination": "192.168.64.64", "protocol": "ICMP", "packetSize": 56},
    )
    probe_id = probe["probeId"]

    err = _error(lambda: nm.delete_monitor(monitorName=monitor_name))
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
    expected = f"All probes on monitor {monitor_name} must be inactive before deletion."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    still_there = nm.get_monitor(monitorName=monitor_name)
    assert still_there["monitorName"] == monitor_name, "monitor must survive the rejected delete"
    probe_still_there = nm.get_probe(monitorName=monitor_name, probeId=probe_id)
    assert probe_still_there["probeId"] == probe_id, "probe must survive the rejected delete"

    _delete_probe_and_wait(ctx, monitor_name, probe_id)
    nm.delete_monitor(monitorName=monitor_name)
    final = _error(lambda: nm.get_monitor(monitorName=monitor_name))
    assert final["Code"] == "ResourceNotFoundException", (
        f"expected the now-unblocked monitor delete to converge to a 404 GetMonitor, got {final['Code']!r}"
    )
    expected = f"No existing monitor found for account {ctx.account} and monitorName {monitor_name}."
    assert final["Message"] == expected, f"expected message {expected!r}, got {final['Message']!r}"


def _error(fn):
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
        try:
            _delete_probe_and_wait(ctx, monitor_name, probe_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    try:
        nm.delete_monitor(monitorName=monitor_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _subnet_arn(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.83.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    az = next(z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"] if z["State"] == "available")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.83.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nwm-subnet-")}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:ec2:{ctx.region}:{account_id}:subnet/{subnet_id}"


def _delete_probe_and_wait(ctx, monitor_name, probe_id, timeout_s=240.0, interval_s=5.0):
    import time

    nm = ctx.client("networkmonitor")
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    # A probe must leave the transient PENDING state before DeleteProbe is accepted.
    state = None
    while time.monotonic() < deadline:
        try:
            state = nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if state != "PENDING":
            break
        time.sleep(interval_s)
    else:
        raise AssertionError(f"probe {probe_id} did not leave PENDING within {timeout_s}s, last state {state!r}")

    nm.delete_probe(monitorName=monitor_name, probeId=probe_id)

    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            nm.get_probe(monitorName=monitor_name, probeId=probe_id)
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if last_code == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(
        f"expected probe {probe_id} delete to converge to ResourceNotFoundException within {timeout_s}s; "
        f"last observed code {last_code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
