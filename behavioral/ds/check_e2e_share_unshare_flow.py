"""e2e-share-unshare-flow."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "e2e-share-unshare-flow"
GROUP = "e2e"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ShareDirectory leaves the share PendingAcceptance, UnshareDirectory revokes it, and
    DescribeSharedDirectories reflects each transition (acceptance needs the consumer's credentials).
    """
    ds = ctx.client("ds")
    net = _get_vpc_and_subnets(ctx)
    directory_id = _create_active_microsoft_ad(ctx, net)

    # A documentation placeholder account: HANDSHAKE sharing does not check that the target exists.
    target_account_id = "111122223333"

    shared_directory_id = ds.share_directory(
        DirectoryId=directory_id,
        ShareMethod="HANDSHAKE",
        ShareNotes="sim2real behavioral check",
        ShareTarget={"Id": target_account_id, "Type": "ACCOUNT"},
    )["SharedDirectoryId"]

    def _safe_unshare() -> None:
        try:
            ds.unshare_directory(
                DirectoryId=directory_id,
                UnshareTarget={"Id": target_account_id, "Type": "ACCOUNT"},
            )
        except ClientError as exc:
            # DirectoryNotSharedException: the check already revoked the share.
            if exc.response["Error"]["Code"] not in (
                "DirectoryDoesNotExistException",
                "DirectoryNotSharedException",
                "EntityDoesNotExistException",
            ):
                raise

    ctx.on_cleanup(_safe_unshare)

    def _owner_share_status():
        # Once UnshareDirectory completes, DescribeSharedDirectories filtered by this
        # SharedDirectoryId returns an empty list rather than an entry with ShareStatus "Deleted":
        # the record is dropped from the index, not marked terminal.
        shares = ds.describe_shared_directories(
            OwnerDirectoryId=directory_id, SharedDirectoryIds=[shared_directory_id]
        )["SharedDirectories"]
        return shares[0]["ShareStatus"] if shares else "gone"

    status = _poll_until(
        _owner_share_status,
        lambda s: s in ("PendingAcceptance", "Shared", "ShareFailed"),
        timeout_s=180,
        interval_s=5,
    )
    assert status == "PendingAcceptance", (
        f"expected a HANDSHAKE share to sit PendingAcceptance until the consumer "
        f"account accepts it, got {status!r}"
    )
    shares = ds.describe_shared_directories(
        OwnerDirectoryId=directory_id, SharedDirectoryIds=[shared_directory_id]
    )["SharedDirectories"]
    assert shares[0]["SharedAccountId"] == target_account_id, (
        f"expected SharedAccountId {target_account_id!r}, got {shares[0]['SharedAccountId']!r}"
    )
    assert shares[0]["ShareMethod"] == "HANDSHAKE", (
        f"expected ShareMethod 'HANDSHAKE', got {shares[0]['ShareMethod']!r}"
    )

    ds.unshare_directory(
        DirectoryId=directory_id, UnshareTarget={"Id": target_account_id, "Type": "ACCOUNT"}
    )

    final_status = _poll_until(
        _owner_share_status,
        lambda s: s in ("gone", "Deleted", "ShareFailed"),
        timeout_s=180,
        interval_s=5,
    )
    assert final_status in ("gone", "Deleted"), (
        f"the owner-visible share record should be removed (or marked Deleted) after "
        f"UnshareDirectory, got {final_status!r}"
    )


def _directory_name(ctx: Any, prefix: str) -> str:
    suffix = ctx.unique_name(prefix).rstrip("-")
    return f"{suffix}.test"


def _get_vpc_and_subnets(ctx: Any) -> dict[str, Any]:
    """Every distinct-AZ subnet available, not just two: CreateMicrosoftAD can reject a zone as
    capacity constrained, and the full candidate set lets the create retry past it."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
            "Subnets"
        ]
        subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return {"vpc_id": vpc_id, "subnet_ids": list(by_az.values())}

    name = ctx.unique_name("sim2real-ds-vpc-")
    managed_tags = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "Name", "Value": name}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.98.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": managed_tags}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.98.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": managed_tags}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value: {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _create_active_microsoft_ad(ctx: Any, net: dict[str, Any]) -> str:
    from botocore.exceptions import ClientError

    ds = ctx.client("ds")
    name = _directory_name(ctx, "sim2realdsshare-")
    tags_param = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "Name", "Value": name}]
    candidates = list(net["subnet_ids"])
    directory_id = None
    last_error: Exception | None = None
    while len(candidates) >= 2 and directory_id is None:
        pair = candidates[:2]
        try:
            directory_id = ds.create_microsoft_ad(
                Name=name,
                Password="Sim2Real!2024Pw",
                VpcSettings={"VpcId": net["vpc_id"], "SubnetIds": pair},
                Tags=tags_param,
            )["DirectoryId"]
        except ClientError as exc:
            err = exc.response["Error"]
            # Real AWS rejects a specific AZ as capacity-constrained independent of code
            # correctness (see _get_vpc_and_subnets docstring); drop the named subnet and
            # retry with the next pair. Anything else is a real defect and must raise.
            if err.get("Code") != "ClientException" or "Availability Zone" not in err.get(
                "Message", ""
            ):
                raise
            last_error = exc
            bad = next((s for s in pair if s in err["Message"]), pair[0])
            candidates = [s for s in candidates if s != bad]
    if directory_id is None:
        raise AssertionError(
            f"CreateMicrosoftAD rejected every available subnet as AZ-capacity-constrained "
            f"(tried {net['subnet_ids']}): {last_error}"
        )
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))
    # 2700s, inside the suite's 3000s ceiling, so a genuine stall raises its own AssertionError.
    stage = _poll_until(
        lambda: ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0][
            "Stage"
        ],
        lambda s: s in ("Active", "Failed"),
        timeout_s=2700,
        interval_s=30,
    )
    assert stage == "Active", f"directory reached terminal stage {stage!r}, not Active"
    return directory_id


# EC2 network teardown: a directory or other resource in this VPC deletes asynchronously, so its ENIs
# linger and DeleteSubnet/DeleteSecurityGroup/DeleteVpc fail with DependencyViolation until they go.
# Wait (bounded, shared by all of one check's network deletes) and retry, then raise naming the ENIs.
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
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in (
                        "DirectoryDoesNotExistException",
                        "EntityDoesNotExistException",
                    ):
                        raise
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
