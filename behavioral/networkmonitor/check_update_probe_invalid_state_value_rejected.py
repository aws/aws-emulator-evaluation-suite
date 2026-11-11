"""update-probe-invalid-state-value-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-probe-invalid-state-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateProbe with state ERROR (a ProbeState value that is not settable) fails with
    ValidationException and the exact message and leaves the probe ACTIVE; state INACTIVE is accepted."""
    nm = ctx.client("networkmonitor")
    net = _create_vpc_and_subnet(ctx)
    monitor_name = _create_monitor(ctx)
    probe = nm.create_probe(
        monitorName=monitor_name,
        probe={"sourceArn": net["subnet_arn"], "destination": "203.0.113.70",
               "protocol": "ICMP", "packetSize": 56},
    )
    probe_id = probe["probeId"]
    ctx.on_cleanup(lambda: _delete_probe(ctx, monitor_name, probe_id))

    active_state = _poll_until(
        lambda: nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"],
        lambda s: s != "PENDING",
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert active_state == "ACTIVE"

    err = _error(lambda: nm.update_probe(monitorName=monitor_name, probeId=probe_id, state="ERROR"))
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
    expected = "ERROR is not a valid probe status."
    assert err["Message"] == expected, f"expected message {expected!r}, got {err['Message']!r}"

    unchanged = nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"]
    assert unchanged == "ACTIVE", f"rejected update must not change probe state, got {unchanged}"

    # positive control: a genuinely settable state value is accepted
    nm.update_probe(monitorName=monitor_name, probeId=probe_id, state="INACTIVE")
    final = _poll_until(
        lambda: nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"],
        lambda s: s == "INACTIVE",
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert final == "INACTIVE"


def _error(fn):
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses cannot pass as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


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
        CidrBlock="10.234.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nm-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.234.1.0/24",
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
