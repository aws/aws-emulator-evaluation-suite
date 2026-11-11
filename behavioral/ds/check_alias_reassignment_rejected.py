"""alias-reassignment-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "alias-reassignment-rejected"
GROUP = "state-machine"
SERVICES = ["ds"]

DIR_PASSWORD = "Sim2Real!Passw0rd123"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After CreateAlias the directory's AccessUrl starts with the alias; a second CreateAlias fails with
    InvalidParameterException "The directory in the request already has an alias. ..." and the AccessUrl
    is unchanged."""
    ds = ctx.client("ds")
    directory_id = _create_microsoft_ad(ctx)
    _wait_for_active(ctx, directory_id)

    first_alias = ctx.unique_name("sim2realalias").replace("_", "").lower()
    resp = ds.create_alias(DirectoryId=directory_id, Alias=first_alias)
    assert resp["Alias"] == first_alias, f"expected Alias={first_alias!r}, got {resp.get('Alias')!r}"

    desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    access_url = desc.get("AccessUrl") or ""
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", access_url), (
        f"AccessUrl is not a well-formed host: {access_url!r}"
    )
    assert access_url.split(".", 1)[0] == first_alias, (
        f"AccessUrl {access_url!r} does not lead with the alias {first_alias!r}"
    )

    second_alias = ctx.unique_name("sim2realalias2").replace("_", "").lower()
    code, message, request_id = _error_code(
        lambda: ds.create_alias(DirectoryId=directory_id, Alias=second_alias)
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    expected = (
        "The directory in the request already has an alias. That alias must be deleted before a new "
        f"alias can be created. : RequestId: {request_id}"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    desc_after = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert desc_after.get("AccessUrl") == access_url, (
        f"AccessUrl changed after rejected re-aliasing: {desc_after.get('AccessUrl')!r}"
    )


# ===== helpers =====

def _error_code(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message, RequestId). An unexpected success
    raises, so a target accepting a call AWS refuses is reported as such, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        request_id = (e.response.get("ResponseMetadata") or {}).get("RequestId")
        return e.response["Error"]["Code"], e.response["Error"].get("Message", ""), request_id
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    """Run a network teardown delete: an already-gone VPC or subnet is fine, anything else raises."""
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
            raise


def _default_vpc_azs_and_subnets(ctx):
    """All (AZ -> subnet_id) in the run's shared network, one entry per AZ with an available
    subnet -- prefer this over creating a dedicated VPC, which counts against the account's
    VPC quota. Returns (vpc_id, {az: subnet_id}); ({}} empty) if there is no shared network."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None, {}
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az: dict[str, str] = {}
    for s in subnets:
        if s["State"] == "available":
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    return vpc_id, by_az


def _dedicated_vpc_azs_and_subnets(ctx):
    """Fallback when there is no default VPC: a dedicated VPC with one subnet per available AZ."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.68.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ]
    by_az: dict[str, str] = {}
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.68.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")}],
            }],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))
        by_az[az] = subnet_id
    return vpc_id, by_az


def _create_microsoft_ad(ctx) -> str:
    # Simple AD (CreateDirectory Size=Small/Large) is no longer open to new customers
    # (real AWS rejects it with ClientException) -- use CreateMicrosoftAD instead. Some AZs in
    # a region are capacity-constrained for Directory Service on a given account (observed:
    # CreateMicrosoftAD's own ClientException naming the AZ), so try every AZ pair rather than
    # assuming the first two subnets found both work.
    ds = ctx.client("ds")
    vpc_id, by_az = _default_vpc_azs_and_subnets(ctx)
    if vpc_id is None or len(by_az) < 2:
        vpc_id, by_az = _dedicated_vpc_azs_and_subnets(ctx)
    azs = list(by_az)
    if len(azs) < 2:
        raise AssertionError("fewer than 2 availability zones with a usable subnet; cannot create a directory")

    pairs = [(azs[i], azs[j]) for i in range(len(azs)) for j in range(i + 1, len(azs))]
    last_error = None
    for az_a, az_b in pairs:
        name = f"{ctx.unique_name('sim2realds')}.test"
        try:
            directory_id = ds.create_microsoft_ad(
                Name=name,
                Password=DIR_PASSWORD,
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": [by_az[az_a], by_az[az_b]]},
            )["DirectoryId"]
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            msg = e.response.get("Error", {}).get("Message", "")
            if code != "ClientException" or "Availability Zone" not in msg:
                raise
            last_error = e
            continue
        ctx.on_cleanup(lambda did=directory_id: _cleanup_delete_directory(ctx, did))
        return directory_id
    raise AssertionError(f"CreateMicrosoftAD failed for every AZ pair tried ({len(pairs)}): {last_error}")


def _wait_for_active(ctx, directory_id: str, *, timeout_s: float = 2700.0, interval_s: float = 30.0) -> None:
    """CreateAlias is rejected with InvalidParameterException on a directory that has not
    yet reached Active, so the positive control needs an Active directory to be meaningful."""
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    last_stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        last_stage = desc["Stage"]
        if last_stage == "Active":
            return
        if last_stage == "Failed":
            raise AssertionError(f"directory {directory_id} entered Failed stage while waiting for Active")
        time.sleep(interval_s)
    raise AssertionError(
        f"directory {directory_id} did not reach Active within {timeout_s}s; last stage {last_stage!r}"
    )


def _cleanup_delete_directory(ctx, directory_id: str) -> None:
    ds = ctx.client("ds")
    deadline = time.monotonic() + 1140  # with the 630 s network teardown, fits the 1800 s cleanup budget
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        if desc["Stage"] in {"Active", "Impaired", "Inoperable", "Failed"}:
            break
        time.sleep(30)
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityDoesNotExistException":
            raise


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
