"""ds-data-concurrent-group-member-adds-all-land-exactly-once."""
from __future__ import annotations

import concurrent.futures
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "ds-data-concurrent-group-member-adds-all-land-exactly-once"
GROUP = 'concurrency'
SERVICES = ['ds']
# Also calls ds-data (the Directory Service Data API, a separate signed endpoint) and ec2.

_PASSWORD = "Sim2Real#Pass99"
_CREATE_TERMINAL = {"Active", "Inoperable", "Impaired", "Failed", "Deleted"}


def _refusal(fn, what: str) -> dict:
    """The refusal fn() raised, with the whole response merged over Error; raises on success.

    ds-data puts modelled members such as AccessDeniedException's Reason at the top level."""
    try:
        result = fn()
    except ClientError as exc:
        return {**exc.response, **(exc.response.get("Error") or {})}
    raise AssertionError(
        f"{what} SUCCEEDED where real AWS refuses it; the response was {result!r}"
    )


def _fields(response: dict) -> dict:
    """A boto3 response without ResponseMetadata (fresh per call), so two reads can be compared."""
    return {k: v for k, v in response.items() if k != "ResponseMetadata"}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(fn, pred, *, timeout_s: float, interval_s: float = 2.0):
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
    """Every item under `key` across every page of a ds-data List*/Search* operation.

    ds-data declares no botocore paginators, so the NextToken loop is explicit."""
    items, token = [], None
    while True:
        page = fn(**({**kwargs, "NextToken": token} if token else kwargs))
        items.extend(page.get(key) or [])
        token = page.get("NextToken")
        if not token:
            return items


def _default_vpc_subnets(ec2, *, ctx) -> tuple:
    """(vpc_id, [subnet_id, subnet_id], cidr_block) of the shared network, subnets in distinct AZs.

    The shared network avoids the default 5-VPC quota; it is not mutated, so concurrent use is safe."""
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
    """(directory_id, fqdn, description, subnet_ids, vpc_id) of a new Active Standard Managed AD.

    A Managed AD bills hourly until deleted, so its teardown is registered right after the create."""
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
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))

    # Creation can take ~40 minutes, and longer than 55 with several creates in flight.
    desc = _poll(
        lambda: _describe(ds, directory_id) or {},
        lambda d: d.get("Stage") in _CREATE_TERMINAL,
        timeout_s=_budget_s(ctx, 3600.0),
        interval_s=2.0,
    )
    if desc.get("Stage") not in _CREATE_TERMINAL and _budget_spent(ctx):
        raise TimeoutError(f"directory {directory_id} leaving creation: the run budget ended first; not graded")
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
            # EnableDirectoryDataAccess typically reaches 'Enabled' in about 15s.
            timeout_s=_budget_s(ctx, 300.0),
            interval_s=1.0,
        )
        if status not in ("Enabled", "Failed") and _budget_spent(ctx):
            raise TimeoutError(f"directory {directory_id} data access settling: the run budget ended first; not graded")
        assert status == "Enabled", (
            f"EnableDirectoryDataAccess must drive DataAccessStatus to 'Enabled' before the "
            f"ds-data endpoint will answer, it reached {status!r}"
        )

    return directory_id, fqdn, desc, subnet_ids, vpc_id


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Eight concurrent AddGroupMember calls on one group all land: ListGroupMembers returns exactly
    those eight users once each, and ListGroupsForMember reports the group for every one of them."""
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    directory_id, fqdn, _desc, _subnets, _vpc = _provision_directory(
        ctx, ds, ec2, enable_data_access=True)

    dsdata = ctx.client("ds-data")
    group = "sim2realRaceGrp"
    user_sams = [f"sim2realRace{n}" for n in range(8)]

    dsdata.create_group(DirectoryId=directory_id, SAMAccountName=group)
    ctx.on_cleanup(lambda: dsdata.delete_group(DirectoryId=directory_id, SAMAccountName=group))
    for sam in user_sams:
        dsdata.create_user(DirectoryId=directory_id, SAMAccountName=sam, GivenName="Race",
                           Surname=sam, EmailAddress=f"{sam}@{fqdn}")
        ctx.on_cleanup(
            lambda s=sam: dsdata.delete_user(DirectoryId=directory_id, SAMAccountName=s))

    # Registered before the concurrent writes and last, so LIFO removes memberships before users/group.
    for sam in user_sams:
        ctx.on_cleanup(lambda s=sam: dsdata.remove_group_member(
            DirectoryId=directory_id, GroupName=group, MemberName=s))

    def _add(sam):
        try:
            dsdata.add_group_member(DirectoryId=directory_id, GroupName=group, MemberName=sam)
            return sam, None
        except ClientError as exc:
            return sam, exc.response.get("Error", {}) or {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(user_sams)) as pool:
        outcomes = list(pool.map(_add, user_sams))

    errors = [(sam, err) for sam, err in outcomes if err is not None]
    assert errors == [], (
        f"every concurrent AddGroupMember must be accepted -- none of these is a throttle the "
        f"botocore standard retry mode would have absorbed: {errors!r}"
    )

    members = _pages(dsdata.list_group_members, "Members", DirectoryId=directory_id,
                     SAMAccountName=group)
    member_sams = [m.get("SAMAccountName") for m in members]
    assert sorted(member_sams) == sorted(user_sams), (
        f"the group's membership after eight concurrent adds must be exactly the eight submitted "
        f"users: {sorted(member_sams)!r} != {sorted(user_sams)!r}"
    )
    assert len(member_sams) == len(set(member_sams)), (
        f"a concurrent add must not double-write an edge: {sorted(member_sams)!r}"
    )
    assert {m.get("MemberType") for m in members} == {"USER"}, (
        f"every member here is a user, so the directory must type all eight edges USER, got "
        f"{[(m.get('SAMAccountName'), m.get('MemberType')) for m in members]!r}"
    )
    assert len({m.get("SID") for m in members}) == len(user_sams), (
        f"eight distinct users must carry eight distinct SIDs: "
        f"{[(m.get('SAMAccountName'), m.get('SID')) for m in members]!r}"
    )

    # A lost update under contention shows up in the inverse index.
    missing = []
    for sam in user_sams:
        groups_of = {g.get("SAMAccountName") for g in _pages(
            dsdata.list_groups_for_member, "Groups", DirectoryId=directory_id,
            SAMAccountName=sam)}
        if group not in groups_of:
            missing.append((sam, sorted(groups_of)))
    assert missing == [], (
        f"ListGroupMembers reported these users as members but ListGroupsForMember does not -- "
        f"the two projections disagree after the race: {missing!r}"
    )


def _delete_directory_and_wait(ds, directory_id, timeout_s=1500.0, interval_s=2.0):
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
