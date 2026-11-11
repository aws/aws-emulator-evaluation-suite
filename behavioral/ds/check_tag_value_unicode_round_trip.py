"""tag-value-unicode-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "tag-value-unicode-round-trip"
GROUP = "representation"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tag keys/values containing unicode and special characters written via
    AddTagsToResource are returned byte-identical by ListTagsForResource."""
    ds = ctx.client("ds")
    directory_id = _create_microsoft_ad(ctx)
    _wait_for_stage(ctx, directory_id, "Active")

    # Allowed tag charset per the DS Tag schema: Unicode letters/digits/whitespace plus
    # _ . : / = + - @ (no other punctuation or symbols, so no emoji here: AddTagsToResource
    # rejects a Symbol-category value with ValidationException against pattern
    # ^([\p{L}\p{Z}\p{N}_.:/=+\-@]*)$).
    tag_key = "Ünïcödé_日本語.tag"
    tag_value = "Значение_café/测试:β+42@zone-A"

    ds.add_tags_to_resource(
        ResourceId=directory_id,
        Tags=[
            {"Key": tag_key, "Value": tag_value},
            {"Key": "plain-ascii-key", "Value": "plain ascii value"},
        ],
    )

    tags = ds.list_tags_for_resource(ResourceId=directory_id)["Tags"]
    by_key = {t["Key"]: t["Value"] for t in tags}

    assert tag_key in by_key, f"unicode key not returned; got keys: {list(by_key)}"
    assert by_key[tag_key] == tag_value, (
        f"unicode tag value mutated: wrote {tag_value!r}, got {by_key[tag_key]!r}"
    )
    assert by_key.get("plain-ascii-key") == "plain ascii value", (
        f"plain ascii tag value mutated: wrote 'plain ascii value', "
        f"got {by_key.get('plain-ascii-key')!r}"
    )


# ===== helpers =====
def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "DirectoryDoesNotExistException",
            "EntityDoesNotExistException",
        ):
            raise


def _candidate_az_subnets(ctx):
    """All default-for-az subnets in the shared network (one per AZ the account exposes),
    or a freshly created VPC spanning every available AZ if there is no shared network.
    CreateMicrosoftAD rejects individual AZs as capacity constrained on some accounts,
    so the caller needs more than just the first two AZs to retry against."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
            ]
        )["Subnets"]
        subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
        by_az: dict = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return vpc_id, list(by_az.values())

    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ]
    if len(azs) < 2:
        raise AssertionError("region does not expose two available AZs to place directory subnets")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.93.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")}],
            }
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.93.{i}.0/24",
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


def _is_az_capacity_error(err) -> bool:
    error = err.response.get("Error", {})
    return error.get("Code") == "ClientException" and "capacity constrained" in error.get(
        "Message", ""
    )


def _create_microsoft_ad(ctx, edition="Standard"):
    from botocore.exceptions import ClientError
    from itertools import combinations

    ds = ctx.client("ds")
    vpc_id, subnet_pool = _candidate_az_subnets(ctx)
    name = ctx.unique_name("sim2realdstag").replace("_", "-").rstrip("-") + ".test"

    last_err = None
    for subnet_pair in combinations(subnet_pool, 2):
        try:
            directory_id = ds.create_microsoft_ad(
                Name=name,
                Password="Sim2Real!2024Pw",
                Edition=edition,
                VpcSettings={"VpcId": vpc_id, "SubnetIds": list(subnet_pair)},
            )["DirectoryId"]
        except ClientError as err:
            if _is_az_capacity_error(err):
                last_err = err
                continue
            raise
        ctx.on_cleanup(lambda did=directory_id: _safe(lambda: _delete_directory_and_wait(ds, did)))
        return directory_id

    raise AssertionError(
        f"no pair of AZs among subnets {subnet_pool} supports CreateMicrosoftAD in the "
        f"region (last error: {last_err})"
    )


def _wait_for_stage(ctx, directory_id, target_stage="Active", timeout_s=3600.0, interval_s=30.0):
    import time

    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        last_stage = desc["Stage"]
        if last_stage == target_stage:
            return desc
        if last_stage in ("Failed", "Inoperable"):
            raise AssertionError(f"directory {directory_id} reached terminal stage {last_stage}")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach {target_stage} within {timeout_s}s "
        f"(last stage {last_stage})"
    )


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


def _delete_directory_and_wait(ds, directory_id, timeout_s=1140.0, interval_s=30.0):
    """Delete a directory and wait until it is gone, so its ENIs and security group leave the
    shared network. DeleteDirectory is retried while the directory is still being created or is
    still shared with another account."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            if "shared" in e.response["Error"].get("Message", "").lower():
                try:
                    shared = ds.describe_shared_directories(OwnerDirectoryId=directory_id)["SharedDirectories"]
                except ClientError:
                    shared = []
                for share in shared:
                    try:
                        ds.unshare_directory(
                            DirectoryId=directory_id,
                            UnshareTarget={"Id": share["SharedAccountId"], "Type": "ACCOUNT"},
                        )
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] not in (
                            "DirectoryDoesNotExistException",
                            "EntityDoesNotExistException",
                        ):
                            raise
            elif code not in ("ClientException", "InvalidParameterException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while True:
        try:
            found = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityDoesNotExistException":
                return
            raise
        if not found or found[0].get("Stage") == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} still exists {timeout_s:.0f}s after DeleteDirectory")
        time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
