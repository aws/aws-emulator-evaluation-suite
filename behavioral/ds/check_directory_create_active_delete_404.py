"""directory-create-active-delete-404."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "directory-create-active-delete-404"
GROUP = "state-machine"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDirectory -> Active in DescribeDirectories; DeleteDirectory removes it so
    DescribeDirectories no longer lists it and other ops raise EntityDoesNotExistException."""
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_with_two_subnets(ctx)

    # Simple AD (CreateDirectory Size=Small/Large) is no longer open to new customers on
    # real AWS -- use CreateMicrosoftAD, the still-available managed-AD creation path.
    name = f"{ctx.unique_name('sim2real-ds-')}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_ad_password(),
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
    )["DirectoryId"]

    deleted = {"done": False}

    def _cleanup_directory():
        if deleted["done"]:
            return
        try:
            ds.delete_directory(DirectoryId=directory_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DirectoryDoesNotExistException",
                "EntityDoesNotExistException",
            ):
                raise

    ctx.on_cleanup(_cleanup_directory)

    stage = _poll_until(
        lambda: ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]["Stage"],
        lambda s: s in ("Active", "Failed"),
        timeout_s=3600.0,
        interval_s=30.0,
    )
    assert stage == "Active", f"directory reached terminal stage {stage!r} instead of Active"

    ds.delete_directory(DirectoryId=directory_id)
    deleted["done"] = True

    # Once the directory is gone, DescribeDirectories answers an empty list rather than a 404.
    def _gone() -> bool:
        try:
            descs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as err:
            return err.response["Error"]["Code"] == "EntityDoesNotExistException"
        return not descs

    _poll_until(_gone, lambda ok: ok is True, timeout_s=1800.0, interval_s=20.0)

    # A second, unrelated op against the now-deleted directory must also 404.
    other_err = _client_error(lambda: ds.get_snapshot_limits(DirectoryId=directory_id))
    other_code = other_err.response["Error"]["Code"]
    assert other_code == "EntityDoesNotExistException", (
        f"expected EntityDoesNotExistException from GetSnapshotLimits on a deleted "
        f"directory, got {other_code!r}"
    )
    expected_message = (
        f"Directory: '{directory_id}' does not exist. "
        f": RequestId: {other_err.response['ResponseMetadata']['RequestId']}"
    )
    message = other_err.response["Error"].get("Message")
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _client_error(fn):
    """The ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ad_password() -> str:
    return "Sim2Real!" + secrets.token_hex(8) + "Aa1"


def _tag_spec(ctx, resource_type: str, kind: str):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-ds-{kind}-")}],
    }


def _create_vpc_with_two_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.171.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]

    def _cleanup_vpc():
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                raise

    ctx.on_cleanup(_cleanup_vpc)
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    az_names = [az["ZoneName"] for az in azs[:2]]
    if len(az_names) < 2:
        raise AssertionError("region does not have 2 available AZs")

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.171.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet", "subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)

        def _cleanup_subnet(sid=subnet_id):
            try:
                _delete_net(ec2, "delete_subnet", SubnetId=sid)
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
                    raise

        ctx.on_cleanup(_cleanup_subnet)
    return vpc_id, subnet_ids


# EC2 network teardown: a directory, endpoint or instance deletes asynchronously, so its ENIs can hold
# the subnet / VPC (DependencyViolation). Wait for the ENIs to go and retry DependencyViolation inside
# one window shared by the check's network deletes, then raise naming the ENIs; other errors propagate.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
