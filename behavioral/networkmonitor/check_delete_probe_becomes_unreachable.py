"""delete-probe-becomes-unreachable."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-probe-becomes-unreachable"
GROUP = "state"
SERVICES = ["networkmonitor"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new probe starts PENDING and reaches ACTIVE; after DeleteProbe, GetProbe and a further
    mutation of the probe both answer ResourceNotFoundException with the exact message."""
    nm = ctx.client("networkmonitor")
    subnet_arn = _subnet_arn(ctx)
    monitor_name = ctx.unique_name("sim2real-nwm-mon-")
    nm.create_monitor(monitorName=monitor_name, aggregationPeriod=60)
    ctx.on_cleanup(lambda: nm.delete_monitor(monitorName=monitor_name))

    probe = nm.create_probe(
        monitorName=monitor_name,
        probe={"sourceArn": subnet_arn, "destination": "192.168.50.50", "protocol": "ICMP", "packetSize": 56},
    )
    probe_id = probe["probeId"]
    assert probe["state"] == "PENDING", f"expected freshly-created probe to be PENDING, got {probe['state']!r}"

    active_state = _wait_probe_leaves_pending(nm, monitor_name, probe_id)
    assert active_state == "ACTIVE", f"expected probe to converge to ACTIVE, got {active_state!r}"

    nm.delete_probe(monitorName=monitor_name, probeId=probe_id)

    expected = f"No existing probe {probe_id} found for account {ctx.account} and monitorName {monitor_name}."
    final = _poll_until_error(
        lambda: nm.get_probe(monitorName=monitor_name, probeId=probe_id),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final["Code"] == "ResourceNotFoundException", (
        f"expected the deleted probe to become unresolvable, got {final['Code']!r}"
    )
    assert final["Message"] == expected, f"expected message {expected!r}, got {final['Message']!r}"

    # the dead id is not just unreadable, it is unusable: a mutation against it fails the
    # same specific not-found code rather than reviving or silently no-op'ing the probe.
    mutate = _error(lambda: nm.update_probe(monitorName=monitor_name, probeId=probe_id, state="INACTIVE"))
    assert mutate["Code"] == "ResourceNotFoundException", (
        f"mutating a probe id that no longer resolves must fail not-found, got {mutate['Code']!r}"
    )
    assert mutate["Message"] == expected, f"expected message {expected!r}, got {mutate['Message']!r}"


def _error(fn):
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until_error(fn, timeout_s=120.0, interval_s=5.0):
    """Poll fn() until it raises a ClientError and return that error; time out loudly."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as e:
            return e.response["Error"]
        time.sleep(interval_s)
    raise AssertionError(f"expected the read to start failing within {timeout_s}s; last={last!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _wait_probe_leaves_pending(nm, monitor_name, probe_id, timeout_s=180.0, interval_s=5.0):
    return _poll_until(
        lambda: nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"],
        lambda s: s != "PENDING",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
