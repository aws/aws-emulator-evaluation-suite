"""representation-ip-route-cidr-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "representation-ip-route-cidr-preserved"
GROUP = "representation"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real-Ds-Pw9!"
_DIR_ACTIVE_TIMEOUT_S = 3600.0
_ROUTE_TIMEOUT_S = 600.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CIDR block added via AddIpRoutes is returned with identical prefix notation by
    ListIpRoutes, with no normalization or truncation."""
    ds = ctx.client("ds")
    vpc = _create_vpc_with_subnets(ctx)
    domain = ctx.unique_name("sim2real-ds-iproute-").lower() + ".test"

    directory_id = ds.create_microsoft_ad(
        Name=domain,
        Password=_PASSWORD,
        Edition="Standard",
        VpcSettings={"VpcId": vpc["vpc_id"], "SubnetIds": vpc["subnet_ids"]},
        Tags=[{"Key": "Name", "Value": domain}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: ds.delete_directory(DirectoryId=directory_id))
    _wait_for_directory_stage(ctx, ds, directory_id, {"Active"}, _DIR_ACTIVE_TIMEOUT_S)

    cidr = "203.0.113.0/28"
    ds.add_ip_routes(DirectoryId=directory_id, IpRoutes=[{"CidrIp": cidr, "Description": "sim2real"}])

    route = _wait_for_ip_route(ctx, ds, directory_id, cidr, _ROUTE_TIMEOUT_S)
    all_routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
    matches = [r for r in all_routes if r["CidrIp"] == cidr]
    assert len(matches) == 1, (
        f"expected exactly one route matching {cidr!r}, found {[r['CidrIp'] for r in all_routes]}"
    )
    assert route["CidrIp"] == cidr, f"CIDR drifted: wrote {cidr!r}, ListIpRoutes returned {route['CidrIp']!r}"
    assert route["IpRouteStatusMsg"] == "Added", (
        f"expected route status Added, got {route['IpRouteStatusMsg']!r}"
    )


# ===== helpers =====


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_with_subnets(ctx) -> dict:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ds-vpc-")
    vpc_id = ec2.create_vpc(CidrBlock="10.94.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])[
        "Vpc"
    ]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.94.{i}.0/24",
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


def _wait_for_ip_route(ctx, ds, directory_id, cidr, timeout_s, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    matches = []
    while time.monotonic() < deadline:
        routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
        matches = [r for r in routes if r["CidrIp"] == cidr]
        if matches and matches[0]["IpRouteStatusMsg"] in ("Added", "AddFailed"):
            if matches[0]["IpRouteStatusMsg"] == "AddFailed":
                raise AssertionError(f"route {cidr} entered AddFailed")
            return matches[0]
        time.sleep(interval_s)
    raise AssertionError(f"route {cidr} never reached Added within {timeout_s}s (matches={matches})")


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
