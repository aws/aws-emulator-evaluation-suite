"""add-ip-routes-duplicate-cidr-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-ip-routes-duplicate-cidr-rejected"
GROUP = "data-plane"
SERVICES = ["ds"]

_STRONG_PASSWORD = "Sim2Real-Test-Passw0rd1!"

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddIpRoutes for a CIDR already added fails with ClientException "The IP route(s) [<cidr>] already
    exist. ..." and keeps one route for it, while a distinct new CIDR still reaches Added."""
    vpc_id, subnet_ids = _create_vpc_with_subnets(ctx)
    directory_id, _domain = _create_microsoft_ad(ctx, vpc_id, subnet_ids)
    _wait_for_directory_stage(ctx, directory_id, {"Active"})

    ds = ctx.client("ds")
    # TEST-NET-3 (RFC 5737): a documentation-only range no VPC CIDR or peering/TGW attachment
    # occupies, unlike a private range, which AddIpRoutes rejects with ClientException "already
    # correctly managed by AWS Directory Services" whenever it overlaps the VPC's own CIDR.
    cidr = "203.0.113.0/24"
    ds.add_ip_routes(DirectoryId=directory_id, IpRoutes=[{"CidrIp": cidr, "Description": "r1"}])
    _poll_until(
        lambda: ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"],
        lambda routes: any(r["CidrIp"] == cidr and r["IpRouteStatusMsg"] == "Added" for r in routes),
        timeout_s=300.0,
        interval_s=10.0,
    )

    # The directory can still be applying the first route after it reads Added; AWS then
    # answers "An update is already in progress", so the duplicate add waits that out.
    busy = f"An update is already in progress for directory {directory_id}."
    deadline = time.monotonic() + min(600.0, ctx.time_left())
    while True:
        code, message, request_id = _error_code(
            lambda: ds.add_ip_routes(
                DirectoryId=directory_id, IpRoutes=[{"CidrIp": cidr, "Description": "r1-dup"}]
            )
        )
        if not message.startswith(busy) or time.monotonic() > deadline:
            break
        time.sleep(2)
    expected = (
        f"The IP route(s) [{cidr}] already exist. If you want to recreate them, please delete the "
        f"existing routes first. : RequestId: {request_id}"
    )
    assert code == "ClientException" and message == expected, (
        f"expected a ClientException {expected!r} for a duplicate route, "
        f"got code={code!r} message={message!r}"
    )

    routes_after = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
    matching = [r for r in routes_after if r["CidrIp"] == cidr]
    assert len(matching) == 1, f"expected exactly one route for {cidr}, got {matching}"

    # Positive control: a genuinely new CIDR is still accepted (TEST-NET-2, same rationale).
    other_cidr = "198.51.100.0/24"
    ds.add_ip_routes(
        DirectoryId=directory_id, IpRoutes=[{"CidrIp": other_cidr, "Description": "r2"}]
    )
    final_routes = _poll_until(
        lambda: ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"],
        lambda routes: any(
            r["CidrIp"] == other_cidr and r["IpRouteStatusMsg"] == "Added" for r in routes
        ),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert any(r["CidrIp"] == other_cidr and r["IpRouteStatusMsg"] == "Added" for r in final_routes), (
        f"expected {other_cidr} to be Added after the duplicate rejection, got {final_routes}"
    )


# ===== helpers =====
def _tag_spec(resource_type: str, name: str):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _create_vpc_with_subnets(ctx):
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS:
                by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return vpc_id, list(by_az.values())[:2]

    name = ctx.unique_name("sim2real-ds-net-")
    vpc_id = ec2.create_vpc(CidrBlock="10.72.0.0/16", TagSpecifications=_tag_spec("vpc", name))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones()["AvailabilityZones"]
        if az["ZoneId"] not in _DS_UNSUPPORTED_ZONE_IDS
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not expose two available AZs to place directory subnets")
    subnet_ids = []
    for i, az in enumerate(azs):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.72.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet", f"{name}-{i}"),
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
    return vpc_id, subnet_ids


def _create_microsoft_ad(ctx, vpc_id, subnet_ids):
    ds = ctx.client("ds")
    base = ctx.unique_name("sim2realds")
    domain_name = f"{base}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=domain_name,
        Password=_STRONG_PASSWORD,
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Edition="Standard",
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))
    return directory_id, domain_name


def _wait_for_directory_stage(ctx, directory_id, target_stages, timeout_s=3600.0, interval_s=30.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        last = desc["Stage"]
        if last in target_stages:
            return desc
        if last in ("Failed", "Inoperable"):
            raise AssertionError(f"directory {directory_id} entered terminal failure stage {last}")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} stuck at {last}, expected one of {target_stages}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn):
    """Return (code, message, RequestId) of the rejection fn raises; an unexpected success raises.
    A duplicate AddIpRoutes answers ClientException, not the modeled EntityAlreadyExistsException."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message", ""), request_id
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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


def _delete_directory_and_wait(ds, directory_id, timeout_s=1140.0, interval_s=2.0):
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
