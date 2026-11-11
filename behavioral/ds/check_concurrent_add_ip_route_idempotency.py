"""concurrent-add-ip-route-idempotency."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "concurrent-add-ip-route-idempotency"
GROUP = "concurrency"
SERVICES = ["ds"]

_DS_PASSWORD = "Sim2Real-Test-P@ssw0rd1"
_TEST_CIDR = "198.51.100.0/24"  # TEST-NET-2, RFC 5737 documentation range


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent AddIpRoutes calls for the identical CIDR on one directory yield exactly one
    success and one rejection, and ListIpRoutes stores the route exactly once."""
    ds = ctx.client("ds")
    directory_id, _vpc_id, _subnet_ids = _create_microsoft_ad(ctx)
    _wait_for_stage(ctx, directory_id, "Active")

    def add_route():
        try:
            ds.add_ip_routes(
                DirectoryId=directory_id,
                IpRoutes=[{"CidrIp": _TEST_CIDR, "Description": "sim2real-concurrent-route"}],
            )
            return ("ok", None, None)
        except ClientError as err:
            request_id = (err.response.get("ResponseMetadata") or {}).get("RequestId")
            return (err.response["Error"]["Code"], err.response["Error"].get("Message"), request_id)

    ctx.on_cleanup(lambda: _safe_remove_route(ds, directory_id))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: add_route(), range(2)))

    codes = [code for code, _msg, _rid in results]
    oks = [c for c in codes if c == "ok"]
    losers = [(c, m, r) for c, m, r in results if c != "ok"]
    assert len(oks) == 1, f"expected exactly one winning AddIpRoutes call, got {codes}"
    assert len(losers) == 1, f"expected exactly one losing AddIpRoutes call, got {codes}"
    # AWS rejects the loser with the duplicate-route conflict or a directory-busy ClientException,
    # depending on where it lands relative to the winner's in-flight update.
    code, message, request_id = losers[0]
    if code == "ClientException":
        # The loser meets either the stored duplicate or the winner's in-flight update.
        duplicate = (
            f"The IP route(s) [{_TEST_CIDR}] already exist. If you want to recreate them, please delete "
            f"the existing routes first. : RequestId: {request_id}"
        )
        busy = (
            f"An update is already in progress for directory {directory_id}. Please wait until this update "
            f"is complete before making another change. : RequestId: {request_id}"
        )
        maintenance = (
            f"The directory is currently unavailable for updates. The directory {directory_id} is under "
            f"maintenance. Please retry the operation after a few minutes. : RequestId: {request_id}"
        )
        if message.startswith("The IP route(s)"):
            expected = duplicate
        elif message.startswith("The directory is currently unavailable"):
            expected = maintenance
        else:
            expected = busy
        assert message == expected, f"unexpected ClientException message: {message!r}"
    else:
        assert code == "EntityAlreadyExistsException", (
            f"unexpected loser error code {code!r} (message={message!r}, results={results})"
        )

    # AddIpRoutes is async (IpRouteStatusMsg starts "Adding"); wait for the winning route to
    # reach a terminal status before judging it, rather than reading mid-transition state.
    status = _wait_for_route_status(ds, directory_id, _TEST_CIDR, {"Added", "AddFailed"})
    assert status == "Added", f"expected the winning route to reach Added, got {status!r}"

    routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
    matching = [r for r in routes if r["CidrIp"] == _TEST_CIDR]
    assert len(matching) == 1, routes  # stored exactly once, not duplicated by the race


# ===== helpers =====
def _safe_remove_route(ds, directory_id, timeout_s=600.0, interval_s=15.0):
    """Remove the route, retrying while the directory reports an in-flight update or maintenance."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ds.remove_ip_routes(DirectoryId=directory_id, CidrIps=[_TEST_CIDR])
            return
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] in ("DirectoryDoesNotExistException", "EntityDoesNotExistException"):
                return
            busy = error["Code"] == "ClientException" and error.get("Message", "").startswith(
                ("An update is already in progress for directory", "The directory is currently unavailable")
            )
            if not busy or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _wait_for_route_status(ds, directory_id, cidr, target_statuses, timeout_s=180.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        routes = ds.list_ip_routes(DirectoryId=directory_id)["IpRoutesInfo"]
        matching = [r for r in routes if r["CidrIp"] == cidr]
        last = matching[0]["IpRouteStatusMsg"] if matching else None
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"route {cidr} did not reach {target_statuses} within {timeout_s}s (last={last})")


def _two_az_subnets(ctx):
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
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return vpc_id, list(by_az.values())[:2]

    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"][:2]
    ]
    if len(azs) < 2:
        raise AssertionError("region does not expose two available AZs to place directory subnets")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.90.0.0/16",
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
            CidrBlock=f"10.90.{i}.0/24",
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


def _create_microsoft_ad(ctx, edition="Standard"):
    ds = ctx.client("ds")
    vpc_id, subnet_ids = _two_az_subnets(ctx)
    label = "".join(c for c in ctx.unique_name("sim2realds").lower() if c.isalnum() or c == "-")
    label = label.strip("-") or "sim2realds"
    name = f"{label}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=name,
        Password=_DS_PASSWORD,
        Edition=edition,
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Tags=[{"Key": "sim2real", "Value": "ds-behavioral"}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))
    return directory_id, vpc_id, subnet_ids


def _wait_for_stage(ctx, directory_id, target_stage="Active", timeout_s=3600.0, interval_s=30.0):
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
