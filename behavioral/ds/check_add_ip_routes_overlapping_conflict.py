"""add-ip-routes-overlapping-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-ip-routes-overlapping-conflict"
GROUP = "concurrency"
SERVICES = ["ds"]

_DS_PASSWORD = "Sim2Real-Test-Pwd-1!"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddIpRoutes with a CIDR duplicating an existing route is rejected with ClientException,
    while a distinct CIDR still succeeds and the conflict clears once the existing route is removed."""
    _ds_slow_gate(ctx)

    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_for_directory(ctx)
    directory_id = _create_microsoft_ad(ctx, vpc_id, subnet_ids)
    _wait_for_stage(ctx, directory_id, {"Active"}, timeout_s=2700.0, interval_s=30.0)

    first_cidr = "203.0.113.0/24"  # RFC 5737 TEST-NET-3, safe non-routable range
    ds.add_ip_routes(DirectoryId=directory_id, IpRoutes=[{"CidrIp": first_cidr}])
    _wait_ip_route_status(ctx, directory_id, first_cidr, "Added", timeout_s=180.0)

    code, message, request_id = _error_code_and_message(
        lambda: ds.add_ip_routes(DirectoryId=directory_id, IpRoutes=[{"CidrIp": first_cidr}])
    )
    # Confirmed against real AWS: re-adding a CIDR that already has an "Added" route on the
    # directory is rejected as ClientException, not EntityAlreadyExistsException.
    assert code == "ClientException", (
        f"expected ClientException re-adding an existing route CIDR, got {code}: {message}"
    )
    expected_message = (
        f"The IP route(s) [{first_cidr}] already exist. If you want to recreate them, please delete "
        f"the existing routes first. : RequestId: {request_id}"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # effect absent: the route was not duplicated/merged into a second entry, and the
    # existing entry's own status is unaffected by the rejected duplicate
    routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
    matching = [r for r in routes if r["CidrIp"] == first_cidr]
    assert len(matching) == 1, f"expected exactly one route entry for {first_cidr}, found {matching}"
    assert matching[0]["IpRouteStatusMsg"] == "Added", (
        f"expected the existing route's status to be unaffected by the rejected duplicate, got {matching[0]}"
    )

    # positive control: a distinct, non-overlapping CIDR is accepted normally
    second_cidr = "198.51.100.0/24"  # RFC 5737 TEST-NET-2
    ds.add_ip_routes(DirectoryId=directory_id, IpRoutes=[{"CidrIp": second_cidr}])
    _wait_ip_route_status(ctx, directory_id, second_cidr, "Added", timeout_s=180.0)

    # restore leg: the conflict is a function of current directory state, not the CIDR
    # itself -- once the existing route is actually removed, the identical add call is no
    # longer a conflict and must succeed again
    ds.remove_ip_routes(DirectoryId=directory_id, CidrIps=[first_cidr])
    _wait_ip_route_absent(ctx, directory_id, first_cidr, timeout_s=180.0)

    ds.add_ip_routes(DirectoryId=directory_id, IpRoutes=[{"CidrIp": first_cidr}])
    _wait_ip_route_status(ctx, directory_id, first_cidr, "Added", timeout_s=180.0)


# ===== helpers =====


def _ds_slow_gate(ctx) -> None:
    # AWS Managed Microsoft AD provisioning takes ~20-45 minutes and bills for the directory's
    # lifetime; the check creates one rather than skipping.
    return


def _error_code_and_message(fn):
    """Return (Error.Code, Error.Message, RequestId) of the ClientError fn() raises; raise if
    the call succeeds."""
    try:
        fn()
    except ClientError as e:
        err = e.response["Error"]
        request_id = (e.response.get("ResponseMetadata") or {}).get("RequestId")
        return err["Code"], err.get("Message"), request_id
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _create_vpc_for_directory(ctx):
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.190.0.0/16",
        TagSpecifications=[
            {
                "ResourceType": "vpc",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")}],
            }
        ],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones(
            Filters=[{"Name": "zone-type", "Values": ["availability-zone"]}]
        )["AvailabilityZones"]
        if az["State"] == "available"
    ][:2]
    if len(azs) < 2:
        raise AssertionError(f"region {ctx.region} does not expose 2 available AZs required for a DS directory VPC")

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.190.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")}],
                }
            ],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _create_microsoft_ad(ctx, vpc_id, subnet_ids, edition: str = "Standard") -> str:
    ds = ctx.client("ds")
    name = f"{ctx.unique_name('sim2real-ds-')}.test"
    resp = ds.create_microsoft_ad(
        Name=name,
        Password=_DS_PASSWORD,
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition=edition,
    )
    directory_id = resp["DirectoryId"]
    ctx.on_cleanup(lambda: _delete_directory_best_effort(ctx, directory_id))
    return directory_id


def _delete_directory_best_effort(ctx, directory_id) -> None:
    # Bounded so this wait and the 630 s network teardown fit the 1800 s cleanup budget.
    ds = ctx.client("ds")
    deadline = time.monotonic() + 1140.0
    while True:
        try:
            ds.delete_directory(DirectoryId=directory_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityDoesNotExistException":
                return
            # A directory still being created refuses DeleteDirectory with ClientException.
            if code != "ClientException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    _wait_for_stage(ctx, directory_id, {"Deleted"}, timeout_s=max(deadline - time.monotonic(), 0.0), interval_s=2.0)


def _wait_for_stage(ctx, directory_id, target_stages, timeout_s=2700.0, interval_s=30.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityDoesNotExistException" and "Deleted" in target_stages:
                return "Deleted"
            raise
        if desc:
            stage = desc[0]["Stage"]
            if stage in target_stages:
                return stage
            if stage == "Failed":
                raise AssertionError(f"directory {directory_id} entered Failed stage while waiting for {target_stages}")
        elif "Deleted" in target_stages:
            return "Deleted"
        if time.monotonic() >= deadline:
            raise AssertionError(f"directory {directory_id} did not reach {target_stages} within {timeout_s}s")
        time.sleep(interval_s)


def _wait_ip_route_status(ctx, directory_id, cidr, expected_status, timeout_s=180.0, interval_s=5.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
        for route in routes:
            if route["CidrIp"] == cidr and route["IpRouteStatusMsg"] == expected_status:
                return route
        time.sleep(interval_s)
    raise AssertionError(f"route {cidr} on {directory_id} never reached status {expected_status!r}")


def _wait_ip_route_absent(ctx, directory_id, cidr, timeout_s=180.0, interval_s=5.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
        if not any(route["CidrIp"] == cidr for route in routes):
            return
        time.sleep(interval_s)
    raise AssertionError(f"route {cidr} on {directory_id} was not removed within {timeout_s}s")


# Subnet / VPC deletes fail with DependencyViolation while a deleted directory's ENIs linger: wait
# (bounded) for the ENIs to go, retry DependencyViolation in one window shared by all of a check's
# network deletes, then raise naming the ENIs still attached.
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
