"""security-group-delete-while-in-use-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


def _test_ami_id(ec2):
    """Return an x86_64 HVM EBS ImageId usable for RunInstances tests."""
    strict = [
        {"Name": "state", "Values": ["available"]},
        {"Name": "architecture", "Values": ["x86_64"]},
        {"Name": "virtualization-type", "Values": ["hvm"]},
        {"Name": "root-device-type", "Values": ["ebs"]},
    ]
    attempts = [
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]}]},
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]}]},
        {"Owners": ["amazon"], "Filters": strict},
    ]
    for kw in attempts:
        images = ec2.describe_images(**kw).get("Images", [])
        if not images:
            continue
        images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
        return images[0]["ImageId"]
    raise AssertionError("could not discover a usable test AMI")


def _wait_instance_state(ec2, instance_id, state, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                last = "__not_yet_visible__"
                time.sleep(3)
                continue
            raise
        reservations = resp.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            last = "__not_yet_visible__"
        else:
            last = reservations[0]["Instances"][0]["State"]["Name"]
        if last == state:
            return last
        time.sleep(3)
    raise AssertionError(
        f"instance {instance_id} did not reach {state!r} within {timeout_s}s (last {last!r})"
    )


def _get_az(ec2, instance_type="t3.micro"):
    """An available AZ that actually offers *instance_type* (falls back to any)."""
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones().get("AvailabilityZones", [])
        if z.get("State", "available") == "available"
        and z.get("ZoneType", "availability-zone") == "availability-zone"
    ]
    if not zones:
        raise AssertionError("no availability zones available")
    try:
        offerings = ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        ).get("InstanceTypeOfferings", [])
        offered = {o["Location"] for o in offerings}
        for z in zones:
            if z in offered:
                return z
    except Exception:
        pass
    return zones[0]


def _terminate_and_wait(ec2, instance_ids):
    """Best-effort teardown: terminate instances then wait for them to reach
    'terminated' so dependent SGs/subnets/VPC become deletable."""
    try:
        ec2.terminate_instances(InstanceIds=instance_ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise
    for iid in instance_ids:
        try:
            _wait_instance_state(ec2, iid, "terminated", timeout_s=120)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise


def _delete_sg_error(ec2, gid):
    """Attempt DeleteSecurityGroup; return the ClientError Error dict. An unexpected
    success raises."""
    try:
        result = ec2.delete_security_group(GroupId=gid)
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected delete_security_group({gid}) to fail, it succeeded: {result!r}")


def _delete_sg_quiet(ec2, gid):
    """Cleanup: delete the group, tolerating a group that is already gone."""
    try:
        ec2.delete_security_group(GroupId=gid)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidGroup.NotFound":
            raise


def _sg_exists(ec2, gid):
    resp = ec2.describe_security_groups(Filters=[{"Name": "group-id", "Values": [gid]}])
    return bool(resp.get("SecurityGroups", []))


def _poll_until_deletable(ec2, gid, timeout_s=60, interval_s=3):
    """Retry the delete until it succeeds (ENI teardown after termination lags a few
    seconds); raise, never return a lingering failure code."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            ec2.delete_security_group(GroupId=gid)
            return
        except ClientError as exc:
            last = exc.response["Error"]["Code"]
        time.sleep(interval_s)
    raise AssertionError(
        f"expected delete_security_group({gid}) to succeed once restored, "
        f"last code={last!r} within {timeout_s}s"
    )

CHECK = "security-group-delete-while-in-use-fails"
GROUP = 'overly-permissive'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSecurityGroup on a group still attached to a running instance must fail
    (overly-permissive check); once the instance is terminated the identical call must
    succeed and the group must no longer be visible."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"] == "available":
            break
        time.sleep(2)

    az = _get_az(ec2)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    # Positive control: an unattached security group deletes cleanly, so the account
    # and credentials are not simply blocked from every DeleteSecurityGroup call.
    control_gid = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-control-"),
        Description="behavioral check sg (unattached control)",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_quiet(ec2, control_gid))
    ec2.delete_security_group(GroupId=control_gid)
    assert not _sg_exists(ec2, control_gid), f"control group {control_gid} still visible after a successful delete"

    gid = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-sg-"),
        Description="behavioral check sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_quiet(ec2, gid))

    ami = _test_ami_id(ec2)
    instance_id = ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        SubnetId=subnet_id, SecurityGroupIds=[gid],
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, [instance_id]))
    _wait_instance_state(ec2, instance_id, "running")

    err = _delete_sg_error(ec2, gid)
    assert err["Code"] == "DependencyViolation", f"expected DependencyViolation, got {err!r}"
    assert err.get("Message") == f"resource {gid} has a dependent object", (
        f"unexpected DependencyViolation message: {err.get('Message')!r}"
    )
    assert _sg_exists(ec2, gid), f"security group {gid} unexpectedly absent after a rejected delete"

    # Restore: terminating the instance tears down its primary ENI, lifting the
    # dependency; the identical delete call must now succeed.
    ec2.terminate_instances(InstanceIds=[instance_id])
    _wait_instance_state(ec2, instance_id, "terminated")
    _poll_until_deletable(ec2, gid)
    assert not _sg_exists(ec2, gid), f"security group {gid} still visible after the restored delete succeeded"


# ===== helpers =====

# Instances and other ENI owners delete asynchronously, so DeleteSubnet / DeleteSecurityGroup /
# DeleteVpc can fail with DependencyViolation until their ENIs go. Wait (bounded) for the ENIs,
# retry DependencyViolation in the same window, and raise naming any ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
