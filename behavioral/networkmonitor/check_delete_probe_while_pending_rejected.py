"""delete-probe-while-pending-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-probe-while-pending-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteProbe on a probe that is still in its transient PENDING state is
    rejected with ValidationException; the probe survives the rejected delete, and
    once it converges to ACTIVE, deleting it succeeds (positive control)."""
    nm = ctx.client("networkmonitor")
    net = _create_vpc_and_subnet(ctx)
    monitor_name = _create_monitor(ctx)
    probe = nm.create_probe(
        monitorName=monitor_name,
        probe={"sourceArn": net["subnet_arn"], "destination": "203.0.113.50",
               "protocol": "ICMP", "packetSize": 56},
    )
    probe_id = probe["probeId"]
    assert probe["state"] == "PENDING", f"expected freshly-created probe to be PENDING, got {probe['state']}"

    err = _error(lambda: nm.delete_probe(monitorName=monitor_name, probeId=probe_id))
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
    expected = f"Probe {probe_id} must not be in pending state before deletion."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    # effect absent: the probe still exists and is not in a deleting/deleted state
    still_there = nm.get_probe(monitorName=monitor_name, probeId=probe_id)
    assert still_there["state"] not in ("DELETING", "DELETED"), (
        f"probe must survive the rejected delete, got state {still_there['state']}"
    )

    # positive control: once ACTIVE, deletion is accepted
    active_state = _poll_until(
        lambda: nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"],
        lambda s: s != "PENDING",
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert active_state == "ACTIVE", f"expected probe to converge to ACTIVE, got {active_state}"
    nm.delete_probe(monitorName=monitor_name, probeId=probe_id)
    # Deleting an ACTIVE probe goes DELETING -> gone: GetProbe never surfaces a lingering
    # DELETED state (confirmed against real AWS), it eventually 404s. Poll until GetProbe
    # itself raises, then assert the specific not-found error.
    final = _poll_until_not_found(
        lambda: nm.get_probe(monitorName=monitor_name, probeId=probe_id),
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert final["Code"] == "ResourceNotFoundException", (
        f"expected the now-ACTIVE probe's delete to converge to a 404 GetProbe, got {final['Code']!r}"
    )
    expected = f"No existing probe {probe_id} found for account {ctx.account} and monitorName {monitor_name}."
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


def _poll_until(probe_fn, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe_fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value: {last!r}")


def _poll_until_not_found(fn, timeout_s=120.0, interval_s=5.0):
    """Poll fn() until it raises a ClientError (any code); return that error. A fn() that
    keeps succeeding forever times out loudly rather than being read as success."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as e:
            return e.response["Error"]
        time.sleep(interval_s)
    raise AssertionError(f"expected the read to start failing within {timeout_s}s; last succeeded with {last!r}")


def _create_vpc_and_subnet(ctx):
    ec2 = ctx.client("ec2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.232.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nm-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.232.1.0/24",
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
