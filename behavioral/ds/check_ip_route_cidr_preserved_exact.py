"""ip-route-cidr-preserved-exact."""
from __future__ import annotations

import itertools
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "ip-route-cidr-preserved-exact"
GROUP = "representation"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real!2024Aa"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddIpRoutes' CIDR and description are returned unchanged by ListIpRoutes.

    AddIpRoutes needs an Active directory, so this provisions a Standard Managed Microsoft AD.
    """
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _vpc_and_subnets(ctx)

    name = f"{ctx.unique_name('sim2real-dsroute-')}.example.com"
    directory_id = _create_microsoft_ad(ctx, ds, name, vpc_id, subnet_ids)
    ctx.on_cleanup(lambda: _delete_directory(ctx, directory_id))

    stage = _wait_directory_stage(ctx, directory_id, {"Active", "Failed"}, timeout_s=2700.0)
    assert stage == "Active", f"directory did not reach Active (got {stage})"

    cidr = "203.0.113.0/24"
    description = "sim2real behavioral ip route"
    ds.add_ip_routes(DirectoryId=directory_id, IpRoutes=[{"CidrIp": cidr, "Description": description}])

    routes = _poll_until(
        lambda: ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"],
        lambda routes: any(r["CidrIp"] == cidr and r["IpRouteStatusMsg"] == "Added" for r in routes),
        timeout_s=180.0,
        interval_s=5.0,
    )
    matches = [r for r in routes if r["CidrIp"] == cidr]
    assert len(matches) == 1, f"expected exactly one route for {cidr}, got {matches}"
    assert matches[0]["IpRouteStatusMsg"] == "Added", f"route never reached Added, got {matches[0]}"
    assert matches[0]["Description"] == description, (
        f"expected description {description!r} unchanged, got {matches[0]['Description']!r}"
    )


# ===== helpers =====
def _vpc_and_subnets(ctx) -> tuple[str, list[str]]:
    """The shared network's subnets (one per AZ) if it has 2+; otherwise a VPC created for this check.

    A freshly provisioned account may have no shared network at all, so DS's VpcSettings
    prerequisite is created in-check rather than assumed. Every distinct-AZ subnet is
    returned, not just two -- `CreateMicrosoftAD` rejects a subnet in a capacity-constrained AZ,
    so the caller needs more than one candidate pair to retry against.
    """
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return vpc_id, list(by_az.values())

    name = ctx.unique_name("sim2real-dsroute-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.96.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.96.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    if len(subnet_ids) < 2:
        raise AssertionError(f"region has fewer than 2 availability zones (got {azs})")
    return vpc_id, subnet_ids


def _create_microsoft_ad(ctx, ds, name: str, vpc_id: str, subnet_ids: list[str]) -> str:
    """CreateMicrosoftAD, retrying across distinct-AZ subnet pairs.

    Real AWS rejects a subnet whose AZ it considers capacity-constrained for DS with
    `ClientException: Failed to locate Availability Zone: <az> ... capacity constrained`. That
    rejection is synchronous and cheap to retry against a different pair; it is not this check's
    subject.
    """
    last_err: ClientError | None = None
    for pair in itertools.combinations(subnet_ids, 2):
        try:
            return ds.create_microsoft_ad(
                Name=name,
                Password=_PASSWORD,
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": list(pair)},
                Tags=[{"Key": "sim2real-owner", "Value": "behavioral-check"}],
            )["DirectoryId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ClientException" or (
                "Availability Zone" not in str(exc)
            ):
                raise
            last_err = exc
    raise AssertionError(f"no usable AZ pair among {subnet_ids} for CreateMicrosoftAD: {last_err}")


def _wait_directory_stage(ctx, directory_id: str, terminal_stages: set[str], timeout_s: float) -> str:
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        if desc:
            stage = desc[0]["Stage"]
            if stage in terminal_stages:
                return stage
        time.sleep(2)
    raise AssertionError(f"directory {directory_id} did not reach {terminal_stages} in {timeout_s}s (last={stage})")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


def _delete_directory(ctx, directory_id: str, timeout_s: float = 1140.0) -> None:
    """Delete the directory and wait until it is gone; with the network teardown it fits the
    1800 s cleanup budget. DeleteDirectory is retried while the directory is still being created."""
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "EntityDoesNotExistException":
                return
            if code not in ("ClientException", "InvalidParameterException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while True:
        try:
            desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityDoesNotExistException":
                return
            raise
        if not desc or desc[0]["Stage"] == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} still exists {timeout_s:.0f}s after DeleteDirectory")
        time.sleep(2)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
