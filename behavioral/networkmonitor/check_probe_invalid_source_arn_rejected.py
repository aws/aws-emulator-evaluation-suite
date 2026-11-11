"""probe-invalid-source-arn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "probe-invalid-source-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateProbe with a well-formed sourceArn that is not a subnet fails with ValidationException and
    the exact message and attaches no probe; the same request with a real subnet ARN succeeds."""
    nm = ctx.client("networkmonitor")
    monitor_name = _create_monitor(ctx)

    # Same account as the monitor, so the refusal is about the resource type, not ownership.
    wrong_type_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:not-a-subnet-topic"
    bad_probe = {"sourceArn": wrong_type_arn, "destination": "203.0.113.10",
                 "protocol": "ICMP", "packetSize": 56}
    code, message = _error(lambda: nm.create_probe(monitorName=monitor_name, probe=bad_probe))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "The specified subnet not-a-subnet-topic does not exist or could not be found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    probes = nm.get_monitor(monitorName=monitor_name).get("probes", [])
    assert probes == [], f"expected no probes after rejected create, found {probes}"

    # positive control: a real subnet ARN is accepted
    net = _create_vpc_and_subnet(ctx)
    good_probe = dict(bad_probe, sourceArn=net["subnet_arn"])
    resp = nm.create_probe(monitorName=monitor_name, probe=good_probe)
    probe_id = resp["probeId"]
    ctx.on_cleanup(lambda: _delete_probe_and_wait(nm, monitor_name, probe_id))

    fetched = nm.get_probe(monitorName=monitor_name, probeId=probe_id)
    assert fetched["sourceArn"] == net["subnet_arn"], (
        f"expected probe {probe_id} sourceArn {net['subnet_arn']!r}, got {fetched.get('sourceArn')!r}")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected CreateProbe to be rejected, but it SUCCEEDED and returned {result!r}")


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
        CidrBlock="10.217.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-nm-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.217.1.0/24",
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
