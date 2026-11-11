"""tag-limit-exceeded-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-limit-exceeded-rejected"
GROUP = "representation"
SERVICES = ["ds"]

DIR_PASSWORD = "Sim2Real!Passw0rd123"
TAG_LIMIT = 50


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddTagsToResource on a directory holding 50 tags is refused TagLimitExceededException.
    The extra tag never appears, and after freeing a slot the same tag is accepted."""
    ds = ctx.client("ds")
    directory_id = _create_microsoft_ad(ctx)
    # AddTagsToResource refuses a directory that is still Creating, so wait for Active first.
    _wait_for_directory_stage(ctx, directory_id, {"Active"}, timeout_s=2700, interval_s=20)

    full_tags = [{"Key": f"sim2real-tag-{i}", "Value": str(i)} for i in range(TAG_LIMIT)]
    ds.add_tags_to_resource(ResourceId=directory_id, Tags=full_tags)

    current = ds.list_tags_for_resource(ResourceId=directory_id)["Tags"]
    assert len(current) == TAG_LIMIT, f"expected exactly {TAG_LIMIT} tags, found {len(current)}"

    overflow_key = "sim2real-tag-overflow"
    code, message, request_id = _error(lambda: ds.add_tags_to_resource(
        ResourceId=directory_id, Tags=[{"Key": overflow_key, "Value": "x"}]
    ))
    assert code == "TagLimitExceededException", f"expected TagLimitExceededException, got {code}"
    expected_message = f"Tag limit exceeded. : RequestId: {request_id}"
    assert message == expected_message, (
        f"the over-limit tag must be refused with ds's exact message {expected_message!r}, got {message!r}"
    )

    after = {t["Key"]: t["Value"] for t in ds.list_tags_for_resource(ResourceId=directory_id)["Tags"]}
    assert overflow_key not in after, "the over-limit tag was applied despite the rejection"
    assert len(after) == TAG_LIMIT, f"tag count drifted after a rejected AddTagsToResource: {len(after)}"

    # positive control: freeing a slot lets a new tag be added on the same directory.
    ds.remove_tags_from_resource(ResourceId=directory_id, TagKeys=["sim2real-tag-0"])
    ds.add_tags_to_resource(ResourceId=directory_id, Tags=[{"Key": overflow_key, "Value": "x"}])
    final = {t["Key"]: t["Value"] for t in ds.list_tags_for_resource(ResourceId=directory_id)["Tags"]}
    assert overflow_key in final, "replacement tag was not applied after freeing a slot"


# ===== helpers =====

def _error(fn):
    """Call fn(); return (Error.Code, Error.Message, RequestId) of the ClientError it must raise.
    ds echoes the refused call's RequestId in its message. An unexpected SUCCESS raises instead of
    returning a falsy sentinel that would read as a code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        request_id = (err.response.get("ResponseMetadata") or {}).get("RequestId")
        return error.get("Code"), error.get("Message") or "", request_id
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe(fn, *gone: str) -> None:
    """Run a teardown step; tolerate only the not-found codes in ``gone`` and raise everything else."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in gone:
            raise


def _wait_for_directory_stage(ctx, directory_id, target_stages, *, timeout_s: float, interval_s: float):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage == "Failed":
            raise AssertionError(f"directory {directory_id} reached Failed while waiting for {target_stages}")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last={stage})")


def _create_vpc_two_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.75.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.75.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")}],
            }],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)

    def _cleanup():
        for sid in subnet_ids:
            _safe(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid), "InvalidSubnetID.NotFound")
        _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound")

    ctx.on_cleanup(_cleanup)
    return vpc_id, subnet_ids


def _create_simple_ad(ctx) -> str:
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_two_subnets(ctx)
    name = f"{ctx.unique_name('sim2realds')}.test"
    directory_id = ds.create_directory(
        Name=name,
        Password=DIR_PASSWORD,
        Size="Small",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
    )["DirectoryId"]

    def _cleanup():
        # Bounded so this wait plus the network window (_NET_TEARDOWN_S) fits the 1800 s cleanup budget.
        try:
            _safe(lambda: _wait_for_directory_stage(
                ctx, directory_id, {"Active", "Impaired", "Inoperable", "Failed"},
                timeout_s=1080, interval_s=2,
            ), "EntityDoesNotExistException")
        except AssertionError:
            pass  # a directory that never settles is still deleted below
        _safe(lambda: ds.delete_directory(DirectoryId=directory_id), "EntityDoesNotExistException")

    ctx.on_cleanup(_cleanup)
    return directory_id


def _create_microsoft_ad(ctx) -> str:
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_two_subnets(ctx)
    name = f"{ctx.unique_name('sim2realds')}.test"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=DIR_PASSWORD,
        Edition="Standard",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
    )["DirectoryId"]

    def _cleanup():
        # Bounded so this wait plus the network window (_NET_TEARDOWN_S) fits the 1800 s cleanup budget.
        try:
            _safe(lambda: _wait_for_directory_stage(
                ctx, directory_id, {"Active", "Impaired", "Inoperable", "Failed"},
                timeout_s=1080, interval_s=2,
            ), "EntityDoesNotExistException")
        except AssertionError:
            pass  # a directory that never settles is still deleted below
        _safe(lambda: ds.delete_directory(DirectoryId=directory_id), "EntityDoesNotExistException")

    ctx.on_cleanup(_cleanup)
    return directory_id


# A deleted directory releases its ENIs asynchronously, so an immediate DeleteSubnet / DeleteVpc
# fails DependencyViolation. Teardown waits (bounded) for the ENIs to go, retries inside one window
# shared by all of a check's network deletes, and raises naming the ENIs still attached.
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
