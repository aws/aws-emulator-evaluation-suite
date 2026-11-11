"""remove-region-primary-denied."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "remove-region-primary-denied"
GROUP = "overly-permissive"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real-Region-2024!"
# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveRegion on a directory that never had a Region added fails with DirectoryDoesNotExistException
    and "Directory: '<id>' does not exist." (no replica to remove), the directory stays Active, and a tag
    round-trip on it still succeeds."""
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_with_subnets(ctx)

    name = f"{ctx.unique_name('sim2real-ds-region').rstrip('-').lower()}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_PASSWORD,
        Edition="Enterprise",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))

    _wait_directory_active(ds, directory_id, timeout_s=3600.0)

    # Break exactly one thing: ask the home-Region endpoint to remove its own (primary) Region.
    # AWS rejects this because the primary is not a tracked replica entry.
    code, message, request_id = _error(lambda: ds.remove_region(DirectoryId=directory_id))
    assert code == "DirectoryDoesNotExistException", f"expected DirectoryDoesNotExistException, got {code}"
    assert message == f"Directory: '{directory_id}' does not exist. : RequestId: {request_id}", (
        f"unexpected DirectoryDoesNotExistException message: {message!r}"
    )

    # Effect absent: the directory (and its primary Region) is untouched.
    desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert desc["Stage"] == "Active"

    # Positive control: a different, unrelated write against the very same directory
    # still succeeds normally afterwards - the backend is selectively rejecting the
    # "remove my own primary Region" request, not blanket-failing every call on this
    # DirectoryId (which an emulator that just always raises for RemoveRegion would not
    # distinguish, but which an emulator that fails open on the whole resource also would
    # not catch either).
    ds.add_tags_to_resource(ResourceId=directory_id, Tags=[{"Key": "sim2real-probe", "Value": "ok"}])
    tags_now = ds.list_tags_for_resource(ResourceId=directory_id)["Tags"]
    assert {"Key": "sim2real-probe", "Value": "ok"} in tags_now
    ctx.on_cleanup(lambda: ds.remove_tags_from_resource(ResourceId=directory_id, TagKeys=["sim2real-probe"]))


# ===== helpers =====
def _error(fn):
    """(Error.Code, Error.Message, RequestId) of the refusal fn() must raise; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", ""), err.response["ResponseMetadata"]["RequestId"]
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _create_vpc_with_subnets(ctx, cidr_prefix: str = "10.92"):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock=f"{cidr_prefix}.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
        if a.get("ZoneId") not in _DS_UNSUPPORTED_ZONE_IDS
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"{cidr_prefix}.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")}],
                }
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _wait_directory_active(ds, directory_id, timeout_s=3600.0, interval_s=30.0):
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage == "Active":
            return desc
        if stage == "Failed":
            raise AssertionError(f"directory {directory_id} entered Failed stage")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} did not reach Active (last stage={stage})")


def _delete_directory_and_wait(ds, directory_id, timeout_s=1140.0, interval_s=20.0):
    """Delete the directory and wait until it reads Deleted or is gone; with the 630 s network
    teardown this fits the 1800 s cleanup budget."""
    from botocore.exceptions import ClientError

    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "EntityDoesNotExistException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            found = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if not found or found[0].get("Stage") == "Deleted":
            return
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} still exists {timeout_s:.0f}s after DeleteDirectory")


# AWS-managed ENIs leave a VPC asynchronously after their owner's delete returns, so a network
# delete waits (bounded, within the cleanup budget) for them and retries DependencyViolation, then
# raises naming the ENIs still attached. Teardown-only: run() never calls this.
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
