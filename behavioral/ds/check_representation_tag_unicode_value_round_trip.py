"""representation-tag-unicode-value-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "representation-tag-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real-Ds-Pw9!"
_DIR_ACTIVE_TIMEOUT_S = 3600.0
# Directory Service tag values match ^([\p{L}\p{Z}\p{N}_.:/=+\-@]*)$, which rejects emoji (Unicode
# "Symbol"), so the value uses multi-script Unicode letters instead.
_TAG_VALUE = "\u65e5\u672c\u8a9e \u0422\u0435\u0441\u0442 \u03a9@42.5/dept:x-\u00e9\u00e8"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value containing unicode characters from multiple scripts, written via
    AddTagsToResource, is returned byte-identical by ListTagsForResource."""
    ds = ctx.client("ds")
    vpc = _create_vpc_with_subnets(ctx)
    domain = ctx.unique_name("sim2real-ds-tagrt-").lower() + ".test"

    directory_id = ds.create_microsoft_ad(
        Name=domain,
        Password=_PASSWORD,
        Edition="Standard",
        VpcSettings={"VpcId": vpc["vpc_id"], "SubnetIds": vpc["subnet_ids"]},
    )["DirectoryId"]
    ctx.on_cleanup(lambda: ds.delete_directory(DirectoryId=directory_id))
    _wait_for_directory_stage(ctx, ds, directory_id, {"Active"}, _DIR_ACTIVE_TIMEOUT_S)

    tag_key = "sim2real-unicode-tag"
    ds.add_tags_to_resource(ResourceId=directory_id, Tags=[{"Key": tag_key, "Value": _TAG_VALUE}])

    tags = ds.list_tags_for_resource(ResourceId=directory_id)["Tags"]
    matching = [t for t in tags if t["Key"] == tag_key]
    assert len(matching) == 1, f"expected exactly one {tag_key!r} tag, got {tags!r}"
    assert matching[0]["Value"] == _TAG_VALUE, (
        f"unicode tag value mutated: wrote {_TAG_VALUE!r}, got {matching[0]['Value']!r}"
    )


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_with_subnets(ctx) -> dict:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ds-vpc-")
    vpc_id = ec2.create_vpc(CidrBlock="10.92.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])[
        "Vpc"
    ]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.92.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", f"{name}-{i}")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _wait_for_directory_stage(ctx, ds, directory_id, target_stages, timeout_s, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage in ("Failed", "Inoperable"):
            raise AssertionError(f"directory {directory_id} entered terminal stage {stage}")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stages} within {timeout_s}s "
        f"(last stage={stage})"
    )


# AWS-managed ENIs (e.g. the directory's) leave the VPC asynchronously after their owner is deleted,
# so DeleteSubnet/DeleteVpc can fail with DependencyViolation: wait for the ENIs and retry within one
# bounded window shared by all of a check's network deletes.
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
