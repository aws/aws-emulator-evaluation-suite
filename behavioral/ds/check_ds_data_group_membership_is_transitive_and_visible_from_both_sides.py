"""ds-data-group-membership-is-transitive-and-visible-from-both-sides."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "ds-data-group-membership-is-transitive-and-visible-from-both-sides"
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


def _default_vpc_subnets(ec2, *, ctx) -> tuple:
    """The account's shared network and two of its subnets in DISTINCT AZs.

    -> (vpc_id, [subnet_id, subnet_id], cidr_block)

    The VPC is only read, never mutated: each directory gets its own service-created ENIs and
    ``<directory-id>_controllers`` security group. The AZs are derived from what the account
    offers, because an AZ name maps to a different physical zone in every account.
    """
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, (
        "the run has no shared network, and a Managed Microsoft AD requires a VPC with two "
        "subnets in distinct availability zones"
    )
    vpc = vpcs[0]
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "vpc-id", "Values": [vpc["VpcId"]]},
        {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
    ])["Subnets"]
    subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
    by_zone: dict = {}
    for subnet in sorted(subnets, key=lambda x: x["SubnetId"]):
        by_zone.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    zones = sorted(by_zone)
    assert len(zones) >= 2, (
        f"a directory is Multi-AZ by requirement and needs two available zones with a subnet in "
        f"each; the shared network {vpc['VpcId']!r} offers {by_zone!r}"
    )
    return vpc["VpcId"], [by_zone[z] for z in zones[:2]], vpc["CidrBlock"]


def _provision_directory(ctx, ds, ec2, *, enable_data_access: bool) -> tuple:
    """A Standard AWS Managed Microsoft AD, Active, in the account's default VPC.

    -> (directory_id, fqdn, description, subnet_ids, vpc_id)

    A Managed AD bills per hour from creation until DeleteDirectory completes, so the teardown is
    registered immediately after the create and before any assertion can fail. It is the ONLY
    resource this helper creates: the VPC and its subnets already existed and are left untouched.
    """
    vpc_id, subnet_ids, vpc_cidr = _default_vpc_subnets(ec2, ctx=ctx)
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

    # A create takes ~25-55 min (longest with several in flight), so the deadline clears the slowest
    # create: giving up early would fail a directory that is merely still being built.
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
            # EnableDirectoryDataAccess reaches 'Enabled' within seconds; 300 s leaves a wide margin.
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
    """AddGroupMember writes an AD membership edge visible from both ends (ListGroupMembers and
    ListGroupsForMember, with USER/GROUP MemberType), nesting group A in B makes A a member of B,
    and RemoveGroupMember retracts the edge from both views.
    """
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    directory_id, fqdn, _desc, _subnets, _vpc = _provision_directory(
        ctx, ds, ec2, enable_data_access=True)

    dsdata = ctx.client("ds-data")
    sam = "sim2realMember"
    group_a = "sim2realGroupA"
    group_b = "sim2realGroupB"

    dsdata.create_user(DirectoryId=directory_id, SAMAccountName=sam, GivenName="Sim",
                       Surname="Real", EmailAddress=f"{sam}@{fqdn}")
    ctx.on_cleanup(lambda: _ignore_absent(lambda: dsdata.delete_user(DirectoryId=directory_id, SAMAccountName=sam)))
    for group in (group_a, group_b):
        dsdata.create_group(DirectoryId=directory_id, SAMAccountName=group)
        ctx.on_cleanup(
            lambda g=group: dsdata.delete_group(DirectoryId=directory_id, SAMAccountName=g))

    # user -> A, then A -> B. The second edge is what makes the graph two levels deep.
    dsdata.add_group_member(DirectoryId=directory_id, GroupName=group_a, MemberName=sam)
    ctx.on_cleanup(lambda: _ignore_absent(lambda: dsdata.remove_group_member(
        DirectoryId=directory_id, GroupName=group_a, MemberName=sam)))
    dsdata.add_group_member(DirectoryId=directory_id, GroupName=group_b, MemberName=group_a)
    ctx.on_cleanup(lambda: _ignore_absent(lambda: dsdata.remove_group_member(
        DirectoryId=directory_id, GroupName=group_b, MemberName=group_a)))

    # --- Side 1: the group's own member list.
    members_a = _pages(dsdata.list_group_members, "Members", DirectoryId=directory_id,
                       SAMAccountName=group_a)
    assert [m.get("SAMAccountName") for m in members_a] == [sam], (
        f"ListGroupMembers on {group_a!r} must return exactly the one user just added, got "
        f"{members_a!r}"
    )
    assert members_a[0].get("MemberType") == "USER", (
        f"the directory classifies the edge, and a user member must be typed USER, got "
        f"{members_a[0]!r}"
    )
    assert (members_a[0].get("SID") or "").startswith("S-1-"), (
        f"a real Active Directory member carries a Windows SID, got {members_a[0]!r}"
    )

    members_b = _pages(dsdata.list_group_members, "Members", DirectoryId=directory_id,
                       SAMAccountName=group_b)
    assert [m.get("SAMAccountName") for m in members_b] == [group_a], (
        f"ListGroupMembers on {group_b!r} must return the nested group {group_a!r}, got "
        f"{members_b!r}"
    )
    assert members_b[0].get("MemberType") == "GROUP", (
        f"a nested group member must be typed GROUP, not USER -- that distinction is the "
        f"directory's, got {members_b[0]!r}"
    )

    # --- Side 2: the member's own group list. This is the inverse index an API-layer-only
    # implementation does not maintain.
    for_user = _pages(dsdata.list_groups_for_member, "Groups", DirectoryId=directory_id,
                      SAMAccountName=sam)
    groups_of_user = {g.get("SAMAccountName") for g in for_user}
    assert group_a in groups_of_user, (
        f"ListGroupsForMember on {sam!r} must report {group_a!r}: the same edge read from the "
        f"other end, got {sorted(groups_of_user)!r}"
    )
    # Measured: Active Directory also reports the automatic primary group every user belongs to. It
    # is not an edge this check wrote, which is exactly why it is asserted -- an implementation that
    # only replays the memberships it was told about does not have it.
    assert "Domain Users" in groups_of_user, (
        f"a real AD user is implicitly a member of the built-in 'Domain Users' group, which nothing "
        f"here created, got {sorted(groups_of_user)!r}"
    )
    ours = [g for g in for_user if g.get("SAMAccountName") == group_a][0]
    assert ours.get("GroupType") == "Security" and ours.get("GroupScope") == "Global", (
        f"CreateGroup passed neither GroupType nor GroupScope, so the directory must have applied "
        f"its own defaults (Security / Global), got {ours!r}"
    )
    groups_of_a = {g.get("SAMAccountName") for g in _pages(
        dsdata.list_groups_for_member, "Groups", DirectoryId=directory_id,
        SAMAccountName=group_a)}
    assert group_b in groups_of_a, (
        f"ListGroupsForMember on the nested group {group_a!r} must report its parent {group_b!r}, "
        f"got {sorted(groups_of_a)!r}"
    )

    # --- Retract exactly one edge; both views must forget it, and only it.
    dsdata.remove_group_member(DirectoryId=directory_id, GroupName=group_a, MemberName=sam)
    after_members = _pages(dsdata.list_group_members, "Members", DirectoryId=directory_id,
                           SAMAccountName=group_a)
    assert after_members == [], (
        f"the membership survived RemoveGroupMember on the group side: {after_members!r}"
    )
    after_groups = {g.get("SAMAccountName") for g in _pages(
        dsdata.list_groups_for_member, "Groups", DirectoryId=directory_id, SAMAccountName=sam)}
    assert after_groups == {"Domain Users"}, (
        f"after the one edge is retracted the user must be left in exactly its automatic primary "
        f"group -- neither {group_a!r} nor anything else: {sorted(after_groups)!r}"
    )
    still_nested = {g.get("SAMAccountName") for g in _pages(
        dsdata.list_groups_for_member, "Groups", DirectoryId=directory_id,
        SAMAccountName=group_a)}
    assert group_b in still_nested, (
        f"removing user->{group_a} must not disturb the {group_a}->{group_b} edge, got "
        f"{sorted(still_nested)!r}"
    )


def _delete_directory_and_wait(ds, directory_id, timeout_s=1500.0, interval_s=30.0):
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


def _ignore_absent(call):
    """Run a teardown call; a resource the check body already removed is not a failure."""
    from botocore.exceptions import ClientError

    try:
        call()
    except ClientError as e:
        if e.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "EntityDoesNotExistException",
        ):
            raise

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
