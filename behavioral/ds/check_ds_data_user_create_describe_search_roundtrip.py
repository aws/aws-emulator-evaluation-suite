"""ds-data-user-create-describe-search-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ds-data-user-create-describe-search-roundtrip"
GROUP = 'directory-data'
SERVICES = ['ds']
# Also calls ds-data (the Directory Service Data API -- a separate signed endpoint) and ec2
# (to read the network a directory is placed in).

_PASSWORD = "Sim2Real#Pass99"
_CREATE_TERMINAL = {"Active", "Inoperable", "Impaired", "Failed", "Deleted"}



# ===== helpers =====
def _refusal(fn, what: str) -> dict:
    """The refusal fn() raised, flattened. Never returns a falsy sentinel on success.

    An unexpected SUCCESS is the strongest signal available -- a target accepting a request real
    AWS refuses -- so it raises rather than returning "", which would degrade it into an
    error-code mismatch that reads like a naming difference.

    The whole ``exc.response`` is merged over the ``Error`` sub-dict rather than returning ``Error``
    alone because the ds-data exceptions declare MODELLED members beside Message -- AccessDeniedException
    has a ``Reason`` enum (IAM_AUTH / DIRECTORY_AUTH / DATA_DISABLED) that restJson1 puts at the TOP
    LEVEL of the parsed response rather than inside ``Error``. Reading only ``Error`` therefore
    silently loses the one field that separates two refusals sharing a code, and a diagnostic that
    reads ``Error`` alone will report ``Reason: None`` for a refusal that carries one -- which is
    exactly the false measurement this helper exists to prevent.
    """
    try:
        result = fn()
    except ClientError as exc:
        return {**exc.response, **(exc.response.get("Error") or {})}
    raise AssertionError(
        f"{what} SUCCEEDED where real AWS refuses it; the response was {result!r}"
    )


def _fields(response: dict) -> dict:
    """A boto3 response without its per-call envelope, so two reads can be compared.

    ``ResponseMetadata`` carries a fresh RequestId and header set on every call, so comparing two
    raw responses for equality can never succeed and would silently turn an "unchanged object"
    assertion into a tautological failure.
    """
    return {k: v for k, v in response.items() if k != "ResponseMetadata"}


def _poll(fn, pred, *, timeout_s: float, interval_s: float = 20.0):
    """Poll fn() until pred(result) is true or the deadline passes. Returns the last result."""
    deadline = time.monotonic() + timeout_s
    while True:
        result = fn()
        if pred(result):
            return result
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)


def _describe(ds, directory_id: str):
    """The DirectoryDescription for directory_id, or None once it is gone."""
    try:
        found = ds.describe_directories(DirectoryIds=[directory_id])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "EntityDoesNotExistException":
            return None
        raise
    descriptions = found.get("DirectoryDescriptions") or []
    return descriptions[0] if descriptions else None


def _pages(fn, key: str, **kwargs) -> list:
    """Every item under `key` across EVERY page of a ds-data List*/Search* operation.

    Paginated because every membership assertion below is over a directory whose page size is the
    service's choice; a partially-read page turns a fidelity check into a flake. ds-data declares
    no botocore paginators, so the NextToken loop is explicit.
    """
    items, token = [], None
    while True:
        page = fn(**({**kwargs, "NextToken": token} if token else kwargs))
        items.extend(page.get(key) or [])
        token = page.get("NextToken")
        if not token:
            return items


def _own_vpc_subnets(ctx, ec2) -> tuple:
    """A VPC this check creates, with two subnets in DISTINCT available AZs.

    -> (vpc_id, [subnet_id, subnet_id], cidr_block)

    A Managed Microsoft AD needs two subnets in distinct availability zones. The AZs are DERIVED
    from what the region offers rather than hardcoded, because an AZ name is a per-account alias.
    Teardown runs after the directory's own (cleanups unwind in reverse), and waits for the
    directory's service-created ENIs to leave before deleting each subnet and the VPC.
    """
    tags = [{"Key": "Name", "Value": ctx.unique_name("sim2real-dsdata-")},
            {"Key": "sim2real-check", "Value": CHECK}]
    cidr = "10.183.0.0/16"
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr, TagSpecifications=[{"ResourceType": "vpc", "Tags": tags}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z.get("ZoneType", "availability-zone") == "availability-zone"
    )
    assert len(zones) >= 2, (
        f"a directory is Multi-AZ by requirement and needs two available zones; the region offers "
        f"{zones!r}"
    )
    subnet_ids = []
    for i, zone in enumerate(zones[:2]):
        sid = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.183.{i}.0/24", AvailabilityZone=zone,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda _s=sid: _delete_net(ec2, "delete_subnet", SubnetId=_s))
    return vpc_id, subnet_ids, cidr


# EC2 network teardown waits for the directory's AWS-managed ENIs to leave before it deletes:
# DeleteDirectory returns while its ENIs still sit in the subnets, so an immediate DeleteSubnet /
# DeleteVpc fails with DependencyViolation. Wait (bounded) for the ENIs, retry DependencyViolation
# inside the same window, and raise a final failure naming the ENIs.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and time.monotonic() < deadline:
        time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") != "DependencyViolation":
                raise
            if time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        time.sleep(10)


def _net_enis(client, flt):
    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt).get("NetworkInterfaces") or []
    except ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [e["NetworkInterfaceId"] for e in enis]


#: Bounded wait for DeleteDirectory to finish (a Managed AD takes ~10 minutes to delete), so the
#: network teardown that unwinds after it starts only once the directory's ENIs are being released.
_DIRECTORY_DELETE_S = 1200.0


def _delete_directory_and_wait(ds, directory_id: str) -> None:
    """Teardown: delete the directory and wait (bounded) until DescribeDirectories forgets it."""
    try:
        ds.delete_directory(DirectoryId=directory_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityDoesNotExistException":
            raise
    deadline = time.monotonic() + _DIRECTORY_DELETE_S
    while True:
        desc = _describe(ds, directory_id)
        if desc is None or desc.get("Stage") == "Deleted":
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"directory {directory_id} still at Stage {desc.get('Stage')!r} "
                f"{_DIRECTORY_DELETE_S:.0f}s after DeleteDirectory"
            )
        time.sleep(20)


def _delete_user_if_present(dsdata, directory_id: str, sam: str) -> None:
    """Teardown: delete the user unless the body already did."""
    try:
        dsdata.delete_user(DirectoryId=directory_id, SAMAccountName=sam)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _provision_directory(ctx, ds, ec2, *, enable_data_access: bool) -> tuple:
    """A Standard AWS Managed Microsoft AD, Active, in a VPC this check creates.

    -> (directory_id, fqdn, description, subnet_ids, vpc_id)

    A Managed AD bills per hour from creation until DeleteDirectory completes, so the teardown is
    registered immediately after the create and before any assertion can fail.
    """
    vpc_id, subnet_ids, vpc_cidr = _own_vpc_subnets(ctx, ec2)
    name = ctx.unique_name("sim2real-behav-")
    fqdn = f"{name}.example.com"

    directory_id = ds.create_microsoft_ad(
        Name=fqdn, ShortName="SIM2REAL", Password=_PASSWORD, Edition="Standard",
        Description=f"sim2real behavioral {CHECK}",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Tags=[{"Key": "sim2real", "Value": "behavioral"},
              {"Key": "sim2real-check", "Value": CHECK}],
    )["DirectoryId"]
    # Registered immediately: a Managed AD bills until DeleteDirectory completes.
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))

    # A Managed AD create takes roughly 25-40 minutes, longer with several creates in flight at
    # once. The deadline has to clear the slowest create rather than the typical one, because a
    # poll that gives up early records a FAIL against a directory that was merely still being
    # built -- which reads exactly like a fidelity finding and is not one.
    desc = _poll(
        lambda: _describe(ds, directory_id) or {},
        lambda d: d.get("Stage") in _CREATE_TERMINAL,
        timeout_s=3600.0,
        interval_s=20.0,
    )
    assert desc.get("Stage") == "Active", (
        f"the directory must reach Stage 'Active' before anything below is meaningful, got "
        f"{desc.get('Stage')!r} (StageReason={desc.get('StageReason')!r})"
    )
    assert (desc.get("VpcSettings") or {}).get("VpcId") == vpc_id, (
        f"the directory must have been placed in the VPC that was asked for, got "
        f"{desc.get('VpcSettings')!r} for {vpc_id!r} ({vpc_cidr})"
    )

    if enable_data_access:
        ds.enable_directory_data_access(DirectoryId=directory_id)
        ctx.on_cleanup(lambda: ds.disable_directory_data_access(DirectoryId=directory_id))
        status = _poll(
            lambda: ds.describe_directory_data_access(
                DirectoryId=directory_id).get("DataAccessStatus"),
            lambda s: s in ("Enabled", "Failed"),
            # EnableDirectoryDataAccess reaches 'Enabled' in seconds; 300s is a wide bound still
            # far inside the check's budget.
            timeout_s=300.0,
            interval_s=15.0,
        )
        assert status == "Enabled", (
            f"EnableDirectoryDataAccess must drive DataAccessStatus to 'Enabled' before the "
            f"ds-data endpoint will answer, it reached {status!r}"
        )

    return directory_id, fqdn, desc, subnet_ids, vpc_id


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A ds-data user is a real AD object: DescribeUser, SearchUsers and ListUsers all return it
    under the directory's base DN, and DeleteUser makes all three forget it.
    """
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    directory_id, fqdn, _desc, _subnets, _vpc = _provision_directory(
        ctx, ds, ec2, enable_data_access=True)

    dsdata = ctx.client("ds-data")
    sam = "sim2realUser1"
    email = f"{sam}@{fqdn}"
    base_dn = "DC=" + ",DC=".join(fqdn.split("."))

    created = dsdata.create_user(
        DirectoryId=directory_id, SAMAccountName=sam, GivenName="Sim", Surname="Real",
        EmailAddress=email,
        OtherAttributes={"description": {"S": "sim2real-behavioral-roundtrip"}},
    )
    ctx.on_cleanup(lambda: _delete_user_if_present(dsdata, directory_id, sam))
    assert created.get("SAMAccountName") == sam, (
        f"CreateUser must echo the sAMAccountName it wrote, got {created!r}"
    )
    assert created.get("DirectoryId") == directory_id, (
        f"CreateUser must echo the directory it wrote into, got {created!r}"
    )

    # --- Projection 1: DescribeUser reads the object back out of Active Directory.
    desc = dsdata.describe_user(
        DirectoryId=directory_id, SAMAccountName=sam, OtherAttributes=["description"])
    assert desc.get("SAMAccountName") == sam, f"{desc!r}"
    assert desc.get("GivenName") == "Sim", (
        f"the GivenName that was written must come back from the directory, got {desc!r}"
    )
    assert desc.get("Surname") == "Real", (
        f"the Surname that was written must come back from the directory, got {desc!r}"
    )
    assert desc.get("EmailAddress") == email, (
        f"the EmailAddress that was written must come back from the directory, expected "
        f"{email!r}, got {desc.get('EmailAddress')!r}"
    )
    # MEASURED, and the opposite of the obvious expectation: a user created through ds-data comes
    # back Enabled=False. CreateUser takes no password, and Active Directory will not activate an
    # account that has none -- so the flag reports a real AD precondition rather than echoing the
    # request. An emulator that defaults the field to True fails here.
    assert desc.get("Enabled") is False, (
        f"a ds-data CreateUser sets no password, so Active Directory must leave the account "
        f"INACTIVE -- Enabled must be False, got {desc!r}"
    )
    assert desc.get("UserPrincipalName") == f"{sam}@{fqdn.upper()}", (
        f"the UPN is DERIVED by Active Directory -- CreateUser never sent one -- as the "
        f"sAMAccountName against the UPPERCASED domain name, expected "
        f"{sam}@{fqdn.upper()!r}, got {desc.get('UserPrincipalName')!r}"
    )
    assert desc.get("Realm") == fqdn, (
        f"the directory must report the realm it resolved the object in, expected {fqdn!r}, got "
        f"{desc.get('Realm')!r}"
    )
    assert (desc.get("SID") or "").startswith("S-1-5-21-"), (
        f"a real Active Directory object carries a domain SID (S-1-5-21-<domain>-<rid>), got "
        f"{desc.get('SID')!r}"
    )
    # The DN is not an echo: Active Directory derived it from its own naming context, which is
    # why it is the single strongest assertion in this check.
    dn = desc.get("DistinguishedName") or ""
    assert dn.endswith(base_dn), (
        f"DistinguishedName {dn!r} must sit under the directory's own base DN {base_dn!r} -- it is "
        f"derived by Active Directory from the domain name, not echoed from the request"
    )
    assert dn.startswith(f"CN={sam},"), (
        f"a user object's DN must be rooted at its own CN, got {dn!r}"
    )
    # Measured: the object lands in OU=Users under the delegated OU named after the NetBIOS
    # ShortName -- a placement Active Directory made, which no request field asked for.
    assert f",OU=Users,OU=SIM2REAL," in dn, (
        f"a Managed Microsoft AD places a ds-data user in OU=Users under the delegated OU named "
        f"after the directory's NetBIOS name, got {dn!r}"
    )
    other = desc.get("OtherAttributes") or {}
    # Measured: written as "description", returned under the CANONICAL LDAP display name
    # "Description". The service resolves the case-insensitive attribute name against the AD schema
    # and answers with the schema's spelling, which is a directory-side normalisation rather than an
    # echo of the request key.
    assert other.get("Description", {}).get("S") == "sim2real-behavioral-roundtrip", (
        f"the custom attribute written as 'description' must come back under the canonical schema "
        f"name 'Description' with the value that was stored, got {other!r}"
    )

    # --- Projection 2: SearchUsers finds it through the directory's own index.
    found = _pages(dsdata.search_users, "Users", DirectoryId=directory_id,
                   SearchString=sam, SearchAttributes=["SAMAccountName"])
    assert [u.get("SAMAccountName") for u in found] == [sam], (
        f"SearchUsers on the exact sAMAccountName must return exactly our one user, got {found!r}"
    )
    assert found[0].get("SID") == desc.get("SID"), (
        f"the search projection and the describe projection must be the same directory object: "
        f"{found[0].get('SID')!r} != {desc.get('SID')!r}"
    )
    assert found[0].get("GivenName") == "Sim" and found[0].get("Surname") == "Real", (
        f"the search projection must carry the names the directory stored, got {found[0]!r}"
    )

    # --- Projection 3: the paginated inventory enumerates it.
    listed = {u.get("SAMAccountName") for u in _pages(
        dsdata.list_users, "Users", DirectoryId=directory_id)}
    assert sam in listed, (
        f"{sam!r} is missing from the paginated ListUsers inventory of {len(listed)} users: "
        f"{sorted(listed)!r}"
    )

    # --- And all three forget it together. A delete that only unlinks one view is the divergence
    # an emulator with three independent stores would show.
    dsdata.delete_user(DirectoryId=directory_id, SAMAccountName=sam)
    gone = _refusal(
        lambda: dsdata.describe_user(DirectoryId=directory_id, SAMAccountName=sam),
        "DescribeUser on a deleted user",
    )
    _assert_user_not_found(gone, sam, "DescribeUser on a deleted user", expected_message=f"User not found in directory {directory_id}.")
    assert _pages(dsdata.search_users, "Users", DirectoryId=directory_id, SearchString=sam,
                  SearchAttributes=["SAMAccountName"]) == [], (
        f"SearchUsers must stop finding {sam!r} once it is deleted"
    )
    listed_after = {u.get("SAMAccountName") for u in _pages(
        dsdata.list_users, "Users", DirectoryId=directory_id)}
    assert sam not in listed_after, (
        f"{sam!r} survived DeleteUser in the paginated inventory: {sorted(listed_after)!r}"
    )


    # A deleted user is unusable, not just unlisted: a mutation on it is refused as not-found.
    dead_update = _refusal(
        lambda: dsdata.update_user(DirectoryId=directory_id, SAMAccountName=sam, GivenName="x"),
        "UpdateUser on a deleted user",
    )
    _assert_user_not_found(dead_update, sam, "UpdateUser on a deleted user", expected_message=f"User not found in directory {directory_id}.")


def _assert_user_not_found(err: dict, sam: str, what: str, expected_message) -> None:
    """ResourceNotFoundException, HTTP 404 (its modelled httpError), and the exact message."""
    assert err.get("Code") == "ResourceNotFoundException", (
        f"{what} must raise ResourceNotFoundException, got {err.get('Code')!r}"
    )
    status = (err.get("ResponseMetadata") or {}).get("HTTPStatusCode")
    assert status == 404, f"{what} must answer HTTP 404, got {status!r}"
    message = err.get("Message") or ""
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
