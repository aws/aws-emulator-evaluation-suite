"""enable-radius-twice-rejected."""
from __future__ import annotations

import itertools
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "enable-radius-twice-rejected"
GROUP = "error-semantics"
SERVICES = ["ds"]

_DS_PASSWORD = "Sim2Real-Test-P@ssw0rd1"
_RADIUS_SETTINGS = {
    "RadiusServers": ["203.0.113.5"],
    "RadiusPort": 1812,
    "RadiusTimeout": 5,
    "RadiusRetries": 3,
    "SharedSecret": "Sim2RealRadiusSecret1",
    "AuthenticationProtocol": "PAP",
    "DisplayLabel": "sim2real-radius",
}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second EnableRadius while RADIUS is enabled fails with a RADIUS ClientException and leaves
    RadiusServers unchanged; disabling then re-enabling RADIUS still succeeds.

    Reference: https://docs.aws.amazon.com/directoryservice/latest/devguide/API_EnableRadius.html"""
    ds = ctx.client("ds")
    directory_id, _vpc_id, _subnet_ids = _create_microsoft_ad(ctx)
    _wait_for_stage(ctx, directory_id, "Active")

    ds.enable_radius(DirectoryId=directory_id, RadiusSettings=_RADIUS_SETTINGS)
    ctx.on_cleanup(lambda: _safe_disable_radius(ds, directory_id))

    # The model also lists EntityAlreadyExistsException, but AWS answers a duplicate with
    # ClientException, and it is not a transient lock.
    detail = _error_detail(lambda: ds.enable_radius(DirectoryId=directory_id, RadiusSettings=_RADIUS_SETTINGS))
    assert detail["Code"] == "ClientException", detail
    assert "radius" in (detail.get("Message") or "").lower(), (
        f"ClientException message does not reference RADIUS: {detail.get('Message')!r}"
    )
    expected_message = (
        "Could not enable radius as it is already enabled or currently being configured for "
        f"directory: {directory_id} : RequestId: {detail['RequestId']}"
    )
    assert detail.get("Message") == expected_message, (
        f"expected {expected_message!r}, got {detail.get('Message')!r}"
    )

    # RadiusStatus is not asserted: the RFC 5737 server is unreachable, so AWS settles it to
    # "Failed" asynchronously. RadiusServers is set synchronously and is stable evidence.
    desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert desc["RadiusSettings"]["RadiusServers"] == _RADIUS_SETTINGS["RadiusServers"], desc.get(
        "RadiusSettings"
    )

    # DisableRadius refuses a RadiusStatus of "Creating" ("radius is not enabled"); with the
    # unreachable server the status settles at "Failed", which DisableRadius accepts.
    _wait_for_radius_terminal(ctx, directory_id)

    ds.disable_radius(DirectoryId=directory_id)
    _wait_for_radius_absent(ctx, directory_id)
    ds.enable_radius(DirectoryId=directory_id, RadiusSettings=_RADIUS_SETTINGS)

    final = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert final["RadiusSettings"]["RadiusServers"] == _RADIUS_SETTINGS["RadiusServers"], final.get(
        "RadiusSettings"
    )


def _safe_disable_radius(ds, directory_id, timeout_s=600.0):
    """DisableRadius refuses ("radius is not enabled") while RadiusStatus is still "Creating";
    retry that refusal every 2 s until RADIUS settles, and stop once no RADIUS settings remain."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ds.disable_radius(DirectoryId=directory_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("DirectoryDoesNotExistException", "EntityDoesNotExistException"):
                return
            if code != "ClientException" or "radius is not enabled" not in exc.response["Error"].get("Message", ""):
                raise
            desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
            if not desc or not (desc[0].get("RadiusSettings") or {}).get("RadiusServers"):
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _error_detail(fn):
    """The ClientError's Error dict plus its RequestId; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return {**err.response["Error"], "RequestId": err.response["ResponseMetadata"]["RequestId"]}
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _wait_for_radius_terminal(ctx, directory_id, timeout_s=600.0, interval_s=15.0):
    """Wait for RadiusStatus to leave "Creating"; "Completed" and "Failed" are both terminal
    states DisableRadius accepts."""
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        last = desc.get("RadiusStatus")
        if last in ("Completed", "Failed"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"RadiusStatus for {directory_id} was still {last!r} after {timeout_s}s")


def _wait_for_radius_absent(ctx, directory_id, timeout_s=180.0, interval_s=10.0):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        if not desc.get("RadiusSettings") or not desc["RadiusSettings"].get("RadiusServers"):
            return
        time.sleep(interval_s)
    raise AssertionError(f"RADIUS settings for {directory_id} were never cleared after DisableRadius")


_AZ_CAPACITY_MARKER = "Failed to locate Availability Zone"


def _default_vpc_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None, []
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
    return vpc_id, list(by_az.values())


def _fresh_vpc_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
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


def _attempt_create_microsoft_ad(ds, name, edition, vpc_id, subnet_ids):
    """Try every 2-subnet (2-AZ) combination, skipping only Directory Service's refusal for
    AZs it cannot place directories in."""
    last_err = None
    for pair in itertools.combinations(subnet_ids, 2):
        try:
            directory_id = ds.create_microsoft_ad(
                Name=name,
                Password=_DS_PASSWORD,
                Edition=edition,
                VpcSettings={"VpcId": vpc_id, "SubnetIds": list(pair)},
            )["DirectoryId"]
        except ClientError as err:
            if _AZ_CAPACITY_MARKER not in err.response["Error"].get("Message", ""):
                raise
            last_err = err
            continue
        return directory_id, list(pair)
    return None, last_err


def _create_microsoft_ad(ctx, edition="Standard"):
    ds = ctx.client("ds")
    label = "".join(c for c in ctx.unique_name("sim2realds").lower() if c.isalnum() or c == "-")
    label = label.strip("-") or "sim2realds"
    name = f"{label}.example.com"

    default_vpc_id, default_subnets = _default_vpc_az_subnets(ctx)
    if default_vpc_id and len(default_subnets) >= 2:
        directory_id, result = _attempt_create_microsoft_ad(
            ds, name, edition, default_vpc_id, default_subnets
        )
        if directory_id:
            ctx.on_cleanup(lambda did=directory_id: _delete_directory_and_wait(ds, did))
            return directory_id, default_vpc_id, result

    # Every shared-network AZ pair was refused (or it lacks 2 AZs): retry in a fresh VPC spanning all AZs.
    vpc_id, subnet_ids = _fresh_vpc_az_subnets(ctx)
    directory_id, result = _attempt_create_microsoft_ad(ds, name, edition, vpc_id, subnet_ids)
    if directory_id:
        ctx.on_cleanup(lambda did=directory_id: _delete_directory_and_wait(ds, did))
        return directory_id, vpc_id, result

    raise AssertionError(
        f"CreateMicrosoftAD was capacity-constrained in every candidate AZ pair: {result}"
    )


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


# Asynchronously deleted resources (load balancers, directories, endpoints, ...) leave ENIs in the
# subnet / security group for a while, so an immediate delete fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry DependencyViolation in the same window, then raise naming the
# ENIs still attached. The window is shared by all of one check's network deletes.
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
