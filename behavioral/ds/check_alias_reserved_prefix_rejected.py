"""alias-reserved-prefix-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "alias-reserved-prefix-rejected"
GROUP = "server-side"
SERVICES = ["ds"]

DIR_PASSWORD = "Sim2Real!Passw0rd123"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAlias with a 'd-'-prefixed alias fails with ValidationException and the exact AliasName
    pattern message (`(?!D-|d-)`) and attaches no alias, while a valid alias on the same directory
    succeeds, so the rejection is specific to the prefix."""
    ds = ctx.client("ds")
    directory_id = _create_microsoft_ad(ctx)

    bad_alias = f"d-{ctx.unique_name('').replace('-', '').lower()[:10]}"
    code, message = _error_code(lambda: ds.create_alias(DirectoryId=directory_id, Alias=bad_alias))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        f"1 validation error detected: Value '{bad_alias}' at 'alias' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: ^(?!D-|d-)([\\da-zA-Z]+)([-]*[\\da-zA-Z])*"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert desc.get("Alias") != bad_alias, "the rejected reserved-prefix alias was applied anyway"
    assert desc.get("Alias") in (None, "", directory_id), (
        f"directory unexpectedly already had an alias set: {desc.get('Alias')}"
    )

    # positive control: a syntactically valid alias on the same directory succeeds.
    good_alias = ctx.unique_name("sim2real-ds-alias-").lower().replace("_", "-")
    resp = ds.create_alias(DirectoryId=directory_id, Alias=good_alias)
    assert resp["Alias"] == good_alias, f"expected {good_alias}, got {resp.get('Alias')}"


# ===== helpers =====

def _error_code(fn):
    """Call fn(); return the rejection's (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    """Run a network teardown delete: an already-gone VPC or subnet is fine, anything else raises."""
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
            raise


def _wait_for_directory_stage(ctx, directory_id, target_stages, *, timeout_s: float, interval_s: float):
    ds = ctx.client("ds")
    deadline = time.monotonic() + timeout_s
    stage = None
    while time.monotonic() < deadline:
        desc = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
        stage = desc["Stage"]
        if stage in target_stages:
            return desc
        if stage == "Failed":
            raise AssertionError(f"directory {directory_id} reached Failed while waiting for {target_stages}")
        time.sleep(interval_s)
    raise AssertionError(f"directory {directory_id} did not reach {target_stages} within {timeout_s}s (last={stage})")


def _default_vpc_subnets(ctx):
    """Prefer the run's shared network (already DNS-enabled, with a subnet per AZ) over
    creating a dedicated one, which would count against the account's VPC quota."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_az = {}
    for s in subnets:
        if s["State"] == "available":
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        return None
    return vpc_id, subnet_ids


def _create_vpc_two_subnets(ctx):
    default = _default_vpc_subnets(ctx)
    if default is not None:
        return default

    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.67.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-vpc-")}],
        }],
    )["Vpc"]["VpcId"]
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.67.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")}],
            }],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)

    def _cleanup():
        for sid in subnet_ids:
            _safe(lambda sid=sid: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    ctx.on_cleanup(_cleanup)
    return vpc_id, subnet_ids


def _create_microsoft_ad(ctx) -> str:
    """Some accounts have an AZ with no Directory Service capacity (real AWS rejects the
    subnet pair with ClientException "... capacity constrained ..."); retry across the
    account's other AZ pairs rather than assuming any 2 AZs work."""
    from botocore.exceptions import ClientError

    ds = ctx.client("ds")
    vpc_id, subnet_ids = _create_vpc_two_subnets(ctx)
    name = f"{ctx.unique_name('sim2realds')}.test"

    remaining = list(subnet_ids)
    directory_id = None
    last_err = None
    while len(remaining) >= 2:
        pair = remaining[:2]
        try:
            directory_id = ds.create_microsoft_ad(
                Name=name,
                Password=DIR_PASSWORD,
                Edition="Standard",
                VpcSettings={"VpcId": vpc_id, "SubnetIds": pair},
            )["DirectoryId"]
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "ClientException" or "capacity constrained" not in err.response["Error"].get("Message", ""):
                raise
            last_err = err
            remaining = remaining[1:]
    if directory_id is None:
        raise AssertionError(
            f"no 2 AZs with Directory Service capacity among {len(subnet_ids)} candidate subnets ({last_err})"
        )

    def _cleanup():
        # Bounded so this wait and the 630 s network teardown fit the 1800 s cleanup budget; the
        # delete then reports any refusal itself.
        try:
            _wait_for_directory_stage(
                ctx, directory_id, {"Active", "Impaired", "Inoperable", "Failed"},
                timeout_s=1140, interval_s=20,
            )
        except AssertionError:
            pass
        try:
            ds.delete_directory(DirectoryId=directory_id)
        except ClientError as err:
            if err.response["Error"]["Code"] != "EntityDoesNotExistException":
                raise

    ctx.on_cleanup(_cleanup)

    # CreateAlias itself requires the directory to be Active ("The directory must be active
    # before an alias can be created for it"), independent of the reserved-prefix rule under
    # test -- so the positive control at the end of run() needs an Active directory too.
    _wait_for_directory_stage(ctx, directory_id, {"Active"}, timeout_s=2700, interval_s=20)
    return directory_id


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
