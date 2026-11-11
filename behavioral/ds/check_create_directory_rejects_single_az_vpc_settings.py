"""create-directory-rejects-single-az-vpc-settings."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-directory-rejects-single-az-vpc-settings"
GROUP = 'input-validation'
SERVICES = ['ds']
# EC2 only builds the (free) VPC and subnets the refused CreateMicrosoftAD calls name.

_VALID_NAME_SUFFIX = ".example.com"
_VALID_SHORT_NAME = "SIM2REAL"
_VALID_PASSWORD = "Sim2Real#Pass99"


# ===== helpers =====
def _directory_gone(ds, directory_id) -> bool:
    """True once DescribeDirectories reports the directory id as nonexistent."""
    try:
        ds.describe_directories(DirectoryIds=[directory_id])
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") == "EntityDoesNotExistException"
    return False


def _poll(fn, pred, *, timeout_s: float, interval_s: float = 15.0):
    """Poll fn() until pred(result) is true or the deadline passes. Returns the last result."""
    deadline = time.monotonic() + timeout_s
    while True:
        result = fn()
        if pred(result):
            return result
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)


def _create_refused(ctx, ds, kwargs):
    """CreateMicrosoftAD(**kwargs) expecting refusal; return (code, message, request_id).

    An unexpected acceptance raises, after registering a delete-and-poll-to-gone cleanup (it is
    registered after the subnets, and ctx.on_cleanup is LIFO, so the directory is reaped before
    the subnets and VPC it holds ENIs in).
    """
    try:
        created = ds.create_microsoft_ad(**kwargs)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = (exc.response.get("ResponseMetadata") or {}).get("RequestId")
        return err.get("Code"), err.get("Message") or "", request_id

    directory_id = created.get("DirectoryId")
    if directory_id:
        def _reap(did=directory_id):
            try:
                ds.delete_directory(DirectoryId=did)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "DirectoryDoesNotExistException",
                    "EntityDoesNotExistException",
                ):
                    raise
                return
            # With the 630 s network teardown this fits the 1800 s cleanup budget.
            if not _poll(lambda: _directory_gone(ds, did), bool, timeout_s=1140.0, interval_s=30.0):
                raise AssertionError(f"directory {did} still exists 1140s after DeleteDirectory")

        ctx.on_cleanup(_reap)
    raise AssertionError(
        f"CreateMicrosoftAD unexpectedly succeeded with VpcSettings={kwargs.get('VpcSettings')!r}: "
        f"DirectoryId={directory_id!r}"
    )


def _tags(ctx, resource_type, name):
    """TagSpecifications so the resource is attributable the instant it exists."""
    return [{
        "ResourceType": resource_type,
        "Tags": [
            {"Key": "Name", "Value": name},
            {"Key": "sim2real", "Value": "behavioral"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
    }]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateMicrosoftAD refuses VpcSettings with two subnets in the same AZ with ClientException
    naming the two-AZ rule, and a malformed subnet id earlier with ValidationException, so the
    Multi-AZ requirement and its ordering after input validation are both pinned by message."""
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-")

    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones().get("AvailabilityZones", [])
        if z.get("State") in (None, "available")
    ]
    if not zones:
        raise AssertionError("no availability zones reported by ec2.describe_availability_zones")
    single_az = zones[0]

    vpc = ec2.create_vpc(
        CidrBlock="10.240.0.0/16", TagSpecifications=_tags(ctx, "vpc", name)
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_ids = []
    for offset, cidr in ((1, "10.240.1.0/24"), (2, "10.240.2.0/24")):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr,
            AvailabilityZone=single_az,
            TagSpecifications=_tags(ctx, "subnet", f"{name}-{offset}"),
        )["Subnet"]
        subnet_ids.append(subnet["SubnetId"])
        ctx.on_cleanup(lambda sid=subnet["SubnetId"]: _delete_net(ec2, "delete_subnet", SubnetId=sid))

    # Control: the substrate is real and genuinely single-AZ, so any refusal below is about
    # topology and not about unresolvable ids.
    described = ec2.describe_subnets(SubnetIds=subnet_ids)["Subnets"]
    assert len(described) == 2, f"expected our 2 subnets back, got {described}"
    assert {s["AvailabilityZone"] for s in described} == {single_az}, (
        f"setup is wrong: subnets must be in exactly one AZ, got "
        f"{[s['AvailabilityZone'] for s in described]}"
    )
    assert {s["VpcId"] for s in described} == {vpc_id}, (
        f"setup is wrong: both subnets must be in {vpc_id}, got {described}"
    )

    base = dict(
        Name=name + _VALID_NAME_SUFFIX,
        ShortName=_VALID_SHORT_NAME,
        Password=_VALID_PASSWORD,
        Edition="Standard",
    )

    # Leg 1 — two real subnets, one AZ. Refused by resource semantics.
    same_az, same_az_message, same_az_request_id = _create_refused(
        ctx, ds, dict(base, VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids})
    )
    assert same_az == "ClientException", (
        f"CreateMicrosoftAD with both subnets in {single_az} must be refused with "
        f"ClientException — ds directories are Multi-AZ by requirement — got {same_az}"
    )
    assert same_az_message == (
        f"Invalid subnet ID(s). The two subnets must be in different Availability Zones. "
        f": RequestId: {same_az_request_id}"
    ), (
        f"the refusal must name the AZ-topology rule specifically (not a generic or "
        f"account-level refusal), got {same_az_message!r}"
    )

    # Leg 2 — break exactly one thing differently: a subnet id that is not well formed.
    malformed, malformed_message, _ = _create_refused(
        ctx,
        ds,
        dict(
            base,
            VpcSettings={"VpcId": vpc_id, "SubnetIds": [subnet_ids[0], "subnet-not-hex"]},
        ),
    )
    assert malformed == "ValidationException", (
        f"CreateMicrosoftAD with SubnetIds=['{subnet_ids[0]}', 'subnet-not-hex'] must be refused "
        f"by input validation with ValidationException, got {malformed}"
    )
    assert malformed_message == (
        f"1 validation error detected: Value '[{subnet_ids[0]}, subnet-not-hex]' at "
        f"'vpcSettings.subnetIds' failed to satisfy constraint: Member must satisfy constraint: "
        f"[Member must satisfy regular expression pattern: "
        f"^(subnet-[0-9a-f]{{8}}|subnet-[0-9a-f]{{17}})$, Member must not be null]"
    ), (
        f"the validation refusal must name the offending member 'vpcSettings.subnetIds', got "
        f"{malformed_message!r}"
    )

    # The two stages must be distinguishable, not one blanket refusal.
    assert same_az != malformed, (
        f"a same-AZ topology and a malformed subnet id must not produce the same error code "
        f"({same_az!r}) — they are refused at different stages"
    )

    # Effect absent: no directory, and the substrate is untouched (so cleanup will succeed).
    leaked = [
        d.get("DirectoryId")
        for d in ds.describe_directories().get("DirectoryDescriptions", [])
        if (d.get("Name") or "") == name + _VALID_NAME_SUFFIX
    ]
    assert not leaked, f"refused CreateMicrosoftAD calls must create nothing, found {leaked}"
    still_there = ec2.describe_subnets(SubnetIds=subnet_ids)["Subnets"]
    assert len(still_there) == 2, (
        f"the refused CreateMicrosoftAD calls must not have consumed our subnets, got "
        f"{still_there}"
    )
    for subnet in still_there:
        assert subnet.get("AvailableIpAddressCount", 0) > 0, (
            f"subnet {subnet['SubnetId']} lost addresses to a refused CreateMicrosoftAD: "
            f"{subnet.get('AvailableIpAddressCount')} — a refusal must not allocate ENIs"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
