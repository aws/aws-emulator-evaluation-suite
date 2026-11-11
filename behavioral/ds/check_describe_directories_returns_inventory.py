"""describe-directories-returns-inventory."""
from __future__ import annotations

import itertools
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "describe-directories-returns-inventory"
GROUP = 'lifecycle'
SERVICES = ['ds']

DIR_PASSWORD = "Sim2Real!Passw0rd123"
# Fixed prefix: Managed Microsoft AD can take 20-45 minutes to reach Active, so a run that times
# out leaves a still-provisioning directory that the next run adopts by name instead of creating
# another billable one.
_NAME_PREFIX = "sim2realds-inv-"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new MicrosoftAD directory appears in unfiltered and id-filtered DescribeDirectories by id,
    Name and Type; after DeleteDirectory both reads omit it, the filtered one as an empty list."""
    ds = ctx.client("ds")

    directory_id, name = _find_pending_directory(ds)
    if directory_id is None:
        vpc_id, az_to_subnet = _provision_network(ctx)
        azs = sorted(az_to_subnet)
        assert len(azs) >= 2, (
            f"need subnets in at least 2 AZs to create a directory, found {azs}"
        )

        name = f"{ctx.unique_name(_NAME_PREFIX)}.test"
        az_capacity_misses = []
        for az_a, az_b in itertools.combinations(azs, 2):
            subnet_ids = [az_to_subnet[az_a], az_to_subnet[az_b]]
            try:
                directory_id = ds.create_microsoft_ad(
                    Name=name, Password=DIR_PASSWORD, Edition="Standard",
                    VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
                )["DirectoryId"]
                break
            except ClientError as exc:
                err = exc.response.get("Error", {})
                # DS reports a per-AZ capacity constraint here; try another AZ pair.
                if err.get("Code") == "ClientException" and "Availability Zone" in (
                    err.get("Message") or ""
                ):
                    az_capacity_misses.append((az_a, az_b, err.get("Message")))
                    continue
                raise
        assert directory_id is not None, (
            f"CreateMicrosoftAD failed for every AZ pair tried out of {azs}: {az_capacity_misses}"
        )

    # Registered immediately, before any assertion below can fail.
    def _reap():
        try:
            ds.delete_directory(DirectoryId=directory_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DirectoryDoesNotExistException",
                "EntityDoesNotExistException",
            ):
                raise
        # With the 630 s network teardown this fits the 1800 s cleanup budget.
        if not _poll_to_gone(ds, directory_id, timeout_s=1140.0, interval_s=30.0):
            raise AssertionError(f"directory {directory_id} still exists 1140s after DeleteDirectory")

    ctx.on_cleanup(_reap)

    unfiltered = ds.describe_directories()["DirectoryDescriptions"]
    by_id = {d["DirectoryId"]: d for d in unfiltered}
    assert directory_id in by_id, (
        f"newly created directory {directory_id} missing from the unfiltered "
        f"DescribeDirectories inventory {sorted(by_id)} -- a stub that always answers with an "
        f"empty list would pass this check without this assertion"
    )
    assert by_id[directory_id].get("Name") == name, by_id[directory_id]
    assert by_id[directory_id].get("Type") == "MicrosoftAD", by_id[directory_id]

    scoped = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
    assert len(scoped) == 1 and scoped[0].get("DirectoryId") == directory_id, (
        f"DescribeDirectories(DirectoryIds=[{directory_id}]) must return exactly that "
        f"directory, got {scoped}"
    )

    # DS refuses DeleteDirectory while a directory is still Requested/Creating.
    desc = _poll_to_terminal(ds, directory_id, timeout_s=2650.0, interval_s=30.0)
    assert desc is not None and desc.get("Stage") == "Active", (
        f"directory {directory_id} must reach Stage Active before DeleteDirectory will accept "
        f"it, got {(desc or {}).get('Stage')!r}"
    )

    ds.delete_directory(DirectoryId=directory_id)
    gone = _poll_to_gone(ds, directory_id, timeout_s=300.0, interval_s=15.0)
    assert gone, (
        f"DescribeDirectories(DirectoryIds=[{directory_id}]) never emptied after DeleteDirectory"
    )

    # A deleted id yields an empty list, not an error (only a never-issued id raises).
    scoped_after = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"]
    assert scoped_after == [], (
        f"DescribeDirectories(DirectoryIds=[{directory_id}]) must report an EMPTY list for a "
        f"directory that existed and was deleted -- ds does not raise for this id, only for one "
        f"it never issued -- got {scoped_after}"
    )
    after = {d["DirectoryId"] for d in ds.describe_directories()["DirectoryDescriptions"]}
    assert directory_id not in after, (
        f"{directory_id} still present in the unfiltered inventory after DeleteDirectory: {after}"
    )


def _find_pending_directory(ds):
    """An undeleted directory from an earlier run of this check, matched by _NAME_PREFIX."""
    for d in ds.describe_directories().get("DirectoryDescriptions", []):
        name = d.get("Name") or ""
        if name.startswith(_NAME_PREFIX) and d.get("Stage") != "Deleted":
            return d["DirectoryId"], name
    return None, None


def _describe_one(ds, directory_id):
    """The DirectoryDescription for directory_id, or None once it is gone."""
    try:
        found = ds.describe_directories(DirectoryIds=[directory_id])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in {
            "EntityDoesNotExistException", "DirectoryDoesNotExistException",
        }:
            return None
        raise
    descriptions = found.get("DirectoryDescriptions") or []
    return descriptions[0] if descriptions else None


def _poll_to_terminal(ds, directory_id, *, timeout_s: float, interval_s: float):
    terminal = {"Active", "Inoperable", "Impaired", "Failed", "Deleted"}
    deadline = time.monotonic() + timeout_s
    desc = _describe_one(ds, directory_id)
    while desc is not None and desc.get("Stage") not in terminal:
        if time.monotonic() >= deadline:
            return desc
        time.sleep(interval_s)
        desc = _describe_one(ds, directory_id)
    return desc


def _poll_to_gone(ds, directory_id, *, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while _describe_one(ds, directory_id) is not None:
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval_s)
    return True


def _default_vpc_all_subnets(ctx):
    """The shared network's VPC and one subnet per usable AZ, or None if fewer than 2 AZs.

    Every AZ is returned so the caller can route around a capacity-constrained one."""
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
    if len(by_az) < 2:
        return None
    return vpc_id, by_az


def _provision_network(ctx):
    """A VPC with a subnet in up to 4 AZs, more than the 2 CreateMicrosoftAD needs, so the
    caller can retry past a capacity-constrained AZ."""
    default = _default_vpc_all_subnets(ctx)
    if default is not None:
        return default

    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.69.0.0/16",
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
    ][:4]
    az_to_subnet = {}
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.69.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{
                "ResourceType": "subnet",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ds-subnet-")}],
            }],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        az_to_subnet[az] = subnet_id

    def _cleanup_vpc():
        for sid in subnet_ids:
            try:
                _delete_net(ec2, "delete_subnet", SubnetId=sid)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
                    raise
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                raise

    ctx.on_cleanup(_cleanup_vpc)
    return vpc_id, az_to_subnet


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
