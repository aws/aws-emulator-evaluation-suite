"""ip-routes-cidr-preserved."""
from __future__ import annotations

import itertools
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "ip-routes-cidr-preserved"
GROUP = "representation"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CIDR blocks added via AddIpRoutes are persisted exactly as submitted (no
    normalization) and returned unchanged by ListIpRoutes, on an Active Managed Microsoft AD."""
    ds = ctx.client("ds")
    net = _get_vpc_and_subnets(ctx)
    directory_id = _create_active_directory(ctx, net)

    # Directory Service can refuse an RFC 1918 route as "overlap with IP ranges which are already ...
    # managed by AWS Directory Services", so the route uses the RFC 6598 shared space 100.64.0.0/10;
    # the octet is derived per run so concurrent runs do not collide.
    octet = 220 + (int(ctx.unique_name("")[-6:-4] or "0", 16) % 30)
    cidr = f"100.64.{octet}.0/24"
    description = "sim2real-test-route"
    ds.add_ip_routes(
        DirectoryId=directory_id,
        IpRoutes=[{"CidrIp": cidr, "Description": description}],
    )
    ctx.on_cleanup(
        lambda: ds.remove_ip_routes(DirectoryId=directory_id, CidrIps=[cidr])
    )

    def _route_status():
        routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
        match = [r for r in routes if r["CidrIp"] == cidr]
        return match[0]["IpRouteStatusMsg"] if match else None

    status = _poll_until(
        _route_status, lambda s: s in ("Added", "AddFailed"), timeout_s=180, interval_s=5
    )
    assert status == "Added", f"route ended in status {status!r}"

    routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
    matching = [r for r in routes if r["CidrIp"] == cidr]
    all_cidrs = [r["CidrIp"] for r in routes]
    assert len(matching) == 1, (
        f"expected exactly one route for {cidr!r}, found {len(matching)}; "
        f"all returned CidrIp values: {all_cidrs}"
    )
    assert matching[0]["Description"] == description, (
        f"description was altered by the service: sent {description!r}, "
        f"got {matching[0]['Description']!r}"
    )


# ===== helpers =====
def _directory_name(ctx: Any, prefix: str) -> str:
    suffix = ctx.unique_name(prefix).rstrip("-")
    return f"{suffix}.test"


def _get_vpc_and_subnets(ctx: Any) -> dict[str, Any]:
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
    vpc_id = ec2.create_vpc(
        CidrBlock="10.95.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    # Not every AZ Describe returns as available also supports Directory Service --
    # CreateMicrosoftAD can reject one as capacity-constrained -- so every AZ is kept
    # here, and _create_active_directory retries across AZ pairs on that error.
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.95.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}
            ],
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


def _create_active_directory(ctx: Any, net: dict[str, Any]) -> str:
    ds = ctx.client("ds")
    # Simple AD (CreateDirectory) is closed to new customers ("ClientException: Simple AD is no
    # longer open to new customers"), so the prerequisite directory is AWS Managed Microsoft AD.
    subnet_ids = net["subnet_ids"]
    pairs = list(itertools.combinations(subnet_ids, 2)) if len(subnet_ids) > 2 else [tuple(subnet_ids)]
    directory_id = None
    last_exc: ClientError | None = None
    for pair in pairs:
        try:
            directory_id = ds.create_microsoft_ad(
                Name=_directory_name(ctx, "sim2realdsroute-"),
                Password="Sim2Real!2024Pw",
                Edition="Standard",
                VpcSettings={"VpcId": net["vpc_id"], "SubnetIds": list(pair)},
            )["DirectoryId"]
            break
        except ClientError as exc:
            # A specific AZ can be capacity-constrained for Directory Service even
            # though EC2 reports it available. Retry with a different AZ pair.
            if "Failed to locate Availability Zone" in str(exc):
                last_exc = exc
                continue
            raise
    if directory_id is None:
        raise last_exc
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))
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
