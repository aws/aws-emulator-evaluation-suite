"""delete-directory-twice-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-directory-twice-not-found"
GROUP = "error-semantics"
SERVICES = ["ds"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting an already-fully-deleted directory returns EntityDoesNotExistException,
    not a silent success and not a generic ClientException."""
    ds = ctx.client("ds")
    directory_id = _create_directory(ctx)
    _wait_for_directory_stage(ctx, directory_id, {"Active"}, timeout_s=2700, interval_s=20)

    # Positive control: deleting an existing, Active directory succeeds.
    ds.delete_directory(DirectoryId=directory_id)

    # Wait for the directory to be fully, irrevocably gone (not merely "Deleting").
    _wait_for_full_removal(ctx, directory_id, timeout_s=2700, interval_s=20)

    # Negative: deleting it again must be rejected with the specific not-found code,
    # not silently accepted and not a generic ClientException.
    err = _client_error(lambda: ds.delete_directory(DirectoryId=directory_id))
    code = err.response["Error"]["Code"]
    assert code == "EntityDoesNotExistException", f"unexpected code: {code}"
    expected_message = (
        f"Directory: '{directory_id}' does not exist. : RequestId: {err.response['ResponseMetadata']['RequestId']}"
    )
    message = err.response["Error"].get("Message")
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Terminal check: an independent read, through a different operation than either
    # delete call, must also see nothing -- the repeated delete did not resurrect or
    # otherwise disturb the directory's absence.
    other_err = _client_error(lambda: ds.get_snapshot_limits(DirectoryId=directory_id))
    other_code = other_err.response["Error"]["Code"]
    assert other_code == "EntityDoesNotExistException", f"unexpected code: {other_code}"
    expected_message = (
        f"Directory: '{directory_id}' does not exist. "
        f": RequestId: {other_err.response['ResponseMetadata']['RequestId']}"
    )
    message = other_err.response["Error"].get("Message")
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return the ClientError it raises. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


def _wait_for_directory_stage(ctx, directory_id, target_stages, timeout_s=2700.0, interval_s=20.0):
    ds = ctx.client("ds")

    def probe():
        descs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        return descs[0]["Stage"] if descs else None

    return _poll_until(probe, lambda s: s in target_stages, timeout_s=timeout_s, interval_s=interval_s)


def _wait_for_full_removal(ctx, directory_id, timeout_s=2700.0, interval_s=20.0):
    ds = ctx.client("ds")

    # Once a directory is gone, DescribeDirectories answers an empty list rather than a 404.
    def probe():
        try:
            descs = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as e:
            return e.response["Error"]["Code"]
        return descs[0]["Stage"] if descs else "absent"

    _poll_until(
        probe, lambda s: s in ("EntityDoesNotExistException", "absent"), timeout_s=timeout_s, interval_s=interval_s
    )


def _create_directory(ctx):
    ds = ctx.client("ds")
    # CreateDirectory provisions Simple AD, which real AWS now rejects for new customers
    # ("Simple AD is no longer open to new customers"). CreateMicrosoftAD is the supported
    # equivalent for exercising the same create -> active -> delete -> not-found lifecycle.
    vpc_id, subnet_ids = _create_vpc_with_two_subnets(ctx)
    name = f"{ctx.unique_name('sim2real-ds-')}.test"
    resp = ds.create_microsoft_ad(
        Name=name,
        Password="Sim2Real-Passw0rd!23",
        Description="sim2real behavioral check: delete-directory-twice-not-found",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
    )
    directory_id = resp["DirectoryId"]

    def _cleanup():
        try:
            _wait_for_directory_stage(ctx, directory_id, {"Active", "Failed", "Impaired"}, timeout_s=1100, interval_s=20)
        except AssertionError:
            pass
        try:
            ds.delete_directory(DirectoryId=directory_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "EntityDoesNotExistException":
                raise

    ctx.on_cleanup(_cleanup)
    return directory_id


def _tag_spec(ctx, resource_type: str, kind: str):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-ds-{kind}-")}],
    }


def _create_vpc_with_two_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.172.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]

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
            CidrBlock=f"10.172.{i}.0/24",
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
