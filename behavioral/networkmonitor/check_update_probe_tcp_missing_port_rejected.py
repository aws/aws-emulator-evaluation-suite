"""update-probe-tcp-missing-port-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-probe-tcp-missing-port-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateProbe switching an ICMP probe to TCP without destinationPort fails with ValidationException
    and the exact message and leaves it ICMP; TCP with destinationPort 443 is accepted and reads back."""
    nm = ctx.client("networkmonitor")
    net = _create_vpc_and_subnet(ctx)
    monitor_name = _create_monitor(ctx)
    probe = nm.create_probe(
        monitorName=monitor_name,
        probe={"sourceArn": net["subnet_arn"], "destination": "203.0.113.60",
               "protocol": "ICMP", "packetSize": 56},
    )
    probe_id = probe["probeId"]
    ctx.on_cleanup(lambda: _delete_probe_and_wait(nm, monitor_name, probe_id))

    _poll_until(
        lambda: nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"],
        lambda s: s != "PENDING",
        timeout_s=300.0,
        interval_s=10.0,
    )

    code, message = _error(lambda: nm.update_probe(monitorName=monitor_name, probeId=probe_id, protocol="TCP"))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "Destination port must be provided for TCP protocol."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unchanged = nm.get_probe(monitorName=monitor_name, probeId=probe_id)
    assert unchanged["protocol"] == "ICMP", (
        f"rejected update must not change the protocol, got {unchanged['protocol']}"
    )

    # positive control: TCP with destinationPort together is accepted
    updated = nm.update_probe(monitorName=monitor_name, probeId=probe_id, protocol="TCP", destinationPort=443)
    assert updated["protocol"] == "TCP", f"expected positive control to switch protocol to TCP, got {updated['protocol']!r}"
    assert updated["destinationPort"] == 443, (
        f"expected positive control to set destinationPort 443, got {updated.get('destinationPort')!r}"
    )

    confirmed = nm.get_probe(monitorName=monitor_name, probeId=probe_id)
    assert confirmed["protocol"] == "TCP", (
        f"independent read must reflect the accepted TCP switch, got {confirmed['protocol']!r}"
    )
    assert confirmed["destinationPort"] == 443, (
        f"independent read must reflect the accepted destinationPort, got {confirmed.get('destinationPort')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so an
    emulator accepting what AWS refuses is reported as such."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected UpdateProbe to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe_fn, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe_fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value: {last!r}")


def _delete_probe_and_wait(nm, monitor_name, probe_id, timeout_s=300.0, interval_s=5.0):
    """Teardown: delete the probe once it has left PENDING, then wait until it is gone, so the
    monitor, subnet and VPC deletes that follow find no dependent probe."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    deleted = False
    while time.monotonic() < deadline:
        try:
            state = nm.get_probe(monitorName=monitor_name, probeId=probe_id)["state"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if not deleted and state in ("ACTIVE", "INACTIVE", "ERROR"):
            nm.delete_probe(monitorName=monitor_name, probeId=probe_id)
            deleted = True
        time.sleep(interval_s)
    raise AssertionError(f"probe {probe_id} still present {timeout_s}s after teardown began")


def _retry_dependency(fn, timeout_s=300.0, interval_s=10.0):
    """Teardown: retry an EC2 delete while a released probe ENI still holds the subnet or VPC."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
        time.sleep(interval_s)


def _create_vpc_and_subnet(ctx):
    ec2 = ctx.client("ec2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.233.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nm-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.233.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{
            "ResourceType": "subnet",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nm-subnet-")}],
        }],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

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
