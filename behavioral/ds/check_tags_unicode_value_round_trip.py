"""tags-unicode-value-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tags-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real!2024Aa"
_ACTIVE_TIMEOUT_S = 2700.0
_SHARED_VPC_TAG_NAME = "sim2real-ds-shared-vpc"

# DS TagValue is constrained to ^([\p{L}\p{Z}\p{N}_.:/=+\-@]*)$ (Unicode letters,
# separators, numbers, plus a small punctuation set) in the directory-service model. Emoji fall
# in the Symbol category, which the pattern excludes, so a value that carries one is rejected
# rather than round-tripped.
_VALID_UNICODE_VALUE = "héllo-世界-Ω"
_EMOJI_VALUE = "héllo-世界-\U0001f680-Ω"


# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A multi-script unicode tag value round-trips byte-for-byte through AddTagsToResource ->
    ListTagsForResource, and a value carrying an emoji (outside the TagValue pattern) is rejected
    with ValidationException and never persisted."""
    ds = ctx.client("ds")
    vpc_id, subnets_by_az = _vpc_and_subnets(ctx)

    name = f"{ctx.unique_name('sim2real-dstags-')}.example.com"
    directory_id = _create_microsoft_ad_avoiding_constrained_azs(ds, name, vpc_id, subnets_by_az)
    ctx.on_cleanup(lambda: _delete_directory(ds, directory_id))

    _wait_directory_stage(ctx, directory_id, {"Active"}, {"Failed"}, _ACTIVE_TIMEOUT_S)

    # positive control: a valid multi-script unicode tag value round-trips unchanged
    ds.add_tags_to_resource(
        ResourceId=directory_id, Tags=[{"Key": "sim2real-unicode", "Value": _VALID_UNICODE_VALUE}]
    )
    tags_after = ds.list_tags_for_resource(ResourceId=directory_id)["Tags"]
    matching = [t for t in tags_after if t["Key"] == "sim2real-unicode"]
    assert len(matching) == 1, f"expected exactly one sim2real-unicode tag, got {matching}"
    assert matching[0]["Value"] == _VALID_UNICODE_VALUE, (
        f"expected tag value {_VALID_UNICODE_VALUE!r} unchanged, got {matching[0]['Value']!r}"
    )

    # negative: a tag value carrying an emoji is outside the TagValue pattern and is
    # rejected, never persisted
    err = _client_error(
        lambda: ds.add_tags_to_resource(
            ResourceId=directory_id,
            Tags=[{"Key": "sim2real-unicode-emoji", "Value": _EMOJI_VALUE}],
        )
    )
    code, message = err.get("Error", {}).get("Code"), err.get("Error", {}).get("Message")
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        f"1 validation error detected: Value '{_EMOJI_VALUE}' at 'tags.1.member.value' failed "
        "to satisfy constraint: Member must satisfy regular expression pattern: "
        "^([\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]*)$"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    tags_after2 = ds.list_tags_for_resource(ResourceId=directory_id)["Tags"]
    assert not any(t["Key"] == "sim2real-unicode-emoji" for t in tags_after2), (
        "emoji tag value was rejected but still persisted"
    )

    ds.delete_directory(DirectoryId=directory_id)
    _wait_directory_stage(ctx, directory_id, {"Deleting", "Deleted"}, set(), 60.0)


# ===== helpers =====
def _client_error(fn):
    """Call fn() and return the refusal's response; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


def _teardown(fn, gone: str) -> None:
    """Run one teardown call: an already-deleted resource (error code `gone`) is fine; any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone:
            raise


# A directory still being created refuses DeleteDirectory; retried in a window that, with the network
# window (_NET_TEARDOWN_S), fits the 1800 s cleanup budget.
_DIR_TEARDOWN_S = 1080.0
_DS_BUSY = {"ClientException", "DirectoryUnavailableException"}


def _delete_directory(ds, directory_id: str) -> None:
    """Teardown: delete the directory unless it is already gone or being deleted; raise any other failure."""
    deadline = time.monotonic() + _DIR_TEARDOWN_S
    while True:
        try:
            desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
            if not desc or desc[0]["Stage"] in ("Deleting", "Deleted"):
                return
            ds.delete_directory(DirectoryId=directory_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "EntityDoesNotExistException":
                return
            if code not in _DS_BUSY or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_microsoft_ad_avoiding_constrained_azs(ds, name: str, vpc_id: str, subnets_by_az: dict[str, str]) -> str:
    azs = list(subnets_by_az)
    last_exc: ClientError | None = None
    for i, az_a in enumerate(azs):
        for az_b in azs[i + 1 :]:
            try:
                return ds.create_microsoft_ad(
                    Name=name,
                    Password=_PASSWORD,
                    Edition="Standard",
                    VpcSettings={
                        "VpcId": vpc_id,
                        "SubnetIds": [subnets_by_az[az_a], subnets_by_az[az_b]],
                    },
                )["DirectoryId"]
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                msg = exc.response.get("Error", {}).get("Message", "")
                if code == "ClientException" and "Availability Zone" in msg:
                    last_exc = exc
                    continue
                raise
    raise AssertionError(f"no pair of AZs in vpc {vpc_id} could host a Microsoft AD directory: {last_exc}")


def _vpc_and_subnets(ctx) -> tuple[str, dict[str, str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [_SHARED_VPC_TAG_NAME]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
    else:
        vpc_id = ec2.create_vpc(
            CidrBlock="10.94.0.0/16",
            TagSpecifications=[
                {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": _SHARED_VPC_TAG_NAME}]}
            ],
        )["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _teardown(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id), "InvalidVpcID.NotFound"))
        ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    network_only = [{"Name": "subnet-id", "Values": ctx.network().subnet_ids}] if vpc_id == ctx.network().vpc_id else []
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}] + network_only)["Subnets"]
    subnets = sorted((x for x in subnets if x.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda x: x["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]]
        for i, az in enumerate(azs):
            if len(by_az) >= 2:
                break
            if az in by_az:
                continue
            try:
                subnet_id = ec2.create_subnet(
                    VpcId=vpc_id,
                    CidrBlock=f"10.94.{i}.0/24",
                    AvailabilityZone=az,
                    TagSpecifications=[
                        {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": _SHARED_VPC_TAG_NAME}]}
                    ],
                )["Subnet"]["SubnetId"]
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "InvalidSubnet.Conflict":
                    continue
                raise
            ctx.on_cleanup(lambda sid=subnet_id: _teardown(
                lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid), "InvalidSubnetID.NotFound"
            ))
            by_az[az] = subnet_id
    if len(by_az) < 2:
        raise AssertionError("could not obtain subnets in 2+ distinct AZs for DS VpcSettings")
    return vpc_id, by_az


def _wait_directory_stage(
    ctx, directory_id: str, terminal_ok: set[str], terminal_bad: set[str], timeout_s: float
) -> str:
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        if desc:
            stage = desc[0]["Stage"]
            if stage in terminal_ok:
                return stage
            if stage in terminal_bad:
                raise AssertionError(f"directory {directory_id} entered stage {stage}")
        time.sleep(2)
    raise AssertionError(f"directory {directory_id} did not reach {terminal_ok} in {timeout_s}s (last={stage})")


# A directory in this VPC deletes asynchronously and leaves its ENIs behind for a while, so an
# immediate DeleteSubnet / DeleteVpc fails with DependencyViolation. Teardown waits (bounded) for the
# ENIs, retries DependencyViolation in one window shared by the check's network deletes, then raises
# naming any ENIs still attached. Teardown-only: run() never calls this.
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
