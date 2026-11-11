"""disable-directory-data-access-recloses-the-door-without-losing-contents."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "disable-directory-data-access-recloses-the-door-without-losing-contents"
GROUP = "directory-data"
SERVICES = ["ds"]
# Also drives ds-data, a separate signed endpoint (restJson1).

_PASSWORD = "Sim2Real#Pass99"
_CREATE_TERMINAL = {"Active", "Inoperable", "Impaired", "Failed", "Deleted"}
_DIRECTORY_DEADLINE_S = 3600.0
_ENABLE_DEADLINE_S = 300.0
_DISABLE_DEADLINE_S = 900.0
_READ_BACK_DEADLINE_S = 120.0
# The refusal wording for a never-enabled directory; only a diagnostic reference in a message.
_NEVER_ENABLED_MESSAGE = ("DS Data feature is not enabled on this directory. This feature must "
                          "first be enabled by calling the EnableDirectoryDataAccess API.")


def _refusal(fn, what: str) -> dict:
    """The refusal fn() raised, flattened over exc.response; raises on an unexpected success.

    ds-data's AccessDeniedException ``Reason`` sits at the top level of the response, not in Error.
    """
    try:
        result = fn()
    except ClientError as exc:
        return {**exc.response, **(exc.response.get("Error") or {})}
    raise AssertionError(
        f"{what} SUCCEEDED where real AWS refuses it; the response was {result!r}"
    )


def _poll(fn, pred, *, timeout_s: float, interval_s: float, what: str):
    """Poll fn() until pred(result); raises on timeout, naming what it waited for."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observation was {last!r}"
            )
        time.sleep(interval_s)


def _describe_directory(ds, directory_id: str):
    try:
        found = ds.describe_directories(DirectoryIds=[directory_id])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "EntityDoesNotExistException":
            return None
        raise
    descriptions = found.get("DirectoryDescriptions") or []
    return descriptions[0] if descriptions else None


def _pages(fn, key: str, **kwargs) -> list:
    """Every item under `key` across every page of a ds-data List* operation.
    ds-data declares no botocore paginators, so the NextToken loop is explicit."""
    items: list = []
    token = None
    while True:
        page = fn(**({**kwargs, "NextToken": token} if token else kwargs))
        items.extend(page.get(key) or [])
        token = page.get("NextToken")
        if not token:
            return items


def _default_vpc_subnets(ec2, *, ctx) -> tuple:
    """The account's shared VPC and two of its subnets in distinct AZs (a Managed AD needs two).
    Reusing one VPC avoids the five-VPC account quota."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, (
        "expected this account to have a shared network, got none; a Managed Microsoft AD requires a "
        "VPC with two subnets in distinct availability zones"
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
        f"expected >= 2 available zones with a subnet in each, got {len(zones)}: {by_zone!r} in "
        f"{vpc['VpcId']!r}"
    )
    return vpc["VpcId"], [by_zone[z] for z in zones[:2]]


def _data_access(ds, directory_id: str):
    return ds.describe_directory_data_access(DirectoryId=directory_id).get("DataAccessStatus")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Disabling data access refuses every ds-data call (DATA_DISABLED) while the directory stays
    Active, and re-enabling brings back the same user, group, membership and SIDs.
    A CreateUser refused while disabled leaves no user behind.
    """
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "expected STS to report the caller account id, got an empty value"

    vpc_id, subnet_ids = _default_vpc_subnets(ec2, ctx=ctx)
    fqdn = f"{ctx.unique_name('sim2real-behav-')}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=fqdn, ShortName="SIM2REAL", Password=_PASSWORD, Edition="Standard",
        Description=f"sim2real behavioral {CHECK}",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Tags=[{"Key": "sim2real", "Value": "behavioral"},
              {"Key": "sim2real-check", "Value": CHECK}],
    )["DirectoryId"]
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))
    created = _poll(
        lambda: _describe_directory(ds, directory_id) or {},
        lambda d: d.get("Stage") in _CREATE_TERMINAL,
        timeout_s=_DIRECTORY_DEADLINE_S, interval_s=20.0,
        what=f"directory {directory_id} to reach a terminal creation stage",
    )
    assert created.get("Stage") == "Active", (
        f"expected the directory to reach Stage 'Active', got {created.get('Stage')!r} "
        f"(StageReason={created.get('StageReason')!r})"
    )

    ds.enable_directory_data_access(DirectoryId=directory_id)
    opened = _poll(
        lambda: _data_access(ds, directory_id),
        lambda s: s in ("Enabled", "Failed"),
        timeout_s=_ENABLE_DEADLINE_S, interval_s=10.0,
        what=f"DataAccessStatus on {directory_id} to settle after EnableDirectoryDataAccess",
    )
    assert opened == "Enabled", (
        f"expected EnableDirectoryDataAccess to drive DataAccessStatus to 'Enabled', got {opened!r}"
    )

    dsdata = ctx.client("ds-data")
    user = ctx.unique_name("s2rSurv")[:20]
    group = ctx.unique_name("s2rGrpSurv")[:20]
    ctx.on_cleanup(lambda: _ignore_absent(lambda: dsdata.delete_user(DirectoryId=directory_id, SAMAccountName=user)))
    ctx.on_cleanup(lambda: _ignore_absent(lambda: dsdata.delete_group(DirectoryId=directory_id, SAMAccountName=group)))

    dsdata.create_user(DirectoryId=directory_id, SAMAccountName=user, GivenName="Sim",
                       Surname="Survivor", EmailAddress=f"{user}@{fqdn}")
    dsdata.create_group(DirectoryId=directory_id, SAMAccountName=group)
    dsdata.add_group_member(DirectoryId=directory_id, GroupName=group, MemberName=user)

    before_user = dsdata.describe_user(DirectoryId=directory_id, SAMAccountName=user)
    before_group = dsdata.describe_group(DirectoryId=directory_id, SAMAccountName=group)
    user_sid = before_user.get("SID")
    group_sid = before_group.get("SID")
    assert (user_sid or "").startswith("S-1-"), (
        f"expected a real Active Directory user to carry a Windows SID starting 'S-1-', got "
        f"{user_sid!r} for {user!r}"
    )
    assert (group_sid or "").startswith("S-1-"), (
        f"expected a real Active Directory group to carry a Windows SID starting 'S-1-', got "
        f"{group_sid!r} for {group!r}"
    )
    assert group_sid != user_sid, (
        f"expected the group and the user to have distinct SIDs, both are {user_sid!r}"
    )
    before_members = [m.get("SAMAccountName") for m in _pages(
        dsdata.list_group_members, "Members", DirectoryId=directory_id, SAMAccountName=group)]
    assert before_members == [user], (
        f"expected ListGroupMembers on {group!r} to return exactly the one user just added, expected "
        f"[{user!r}], got {before_members!r}"
    )

    ds.disable_directory_data_access(DirectoryId=directory_id)
    shut = _poll(
        lambda: _data_access(ds, directory_id),
        lambda s: s in ("Disabled", "Failed"),
        timeout_s=_DISABLE_DEADLINE_S, interval_s=15.0,
        what=f"DataAccessStatus on {directory_id} to settle after DisableDirectoryDataAccess",
    )
    assert shut == "Disabled", (
        f"expected DisableDirectoryDataAccess to drive DataAccessStatus to 'Disabled', got {shut!r}"
    )

    # The gate is on the directory, not the operation: a read and a write get the same refusal.
    refused_read = _refusal(
        lambda: dsdata.describe_user(DirectoryId=directory_id, SAMAccountName=user),
        f"DescribeUser for {user!r} after the data plane was disabled again",
    )
    assert refused_read.get("Code") == "AccessDeniedException", (
        f"expected ds-data to refuse a read against a re-disabled directory with "
        f"AccessDeniedException, got {refused_read!r}"
    )
    assert refused_read.get("Reason") == "DATA_DISABLED", (
        f"expected the refusal to name the DISABLED DATA PLANE as its reason rather than an IAM or "
        f"directory authentication problem, got Reason={refused_read.get('Reason')!r} in "
        f"{refused_read!r}"
    )
    withheld = ctx.unique_name("s2rNope")[:20]
    ctx.on_cleanup(lambda: _ignore_absent(lambda: dsdata.delete_user(DirectoryId=directory_id, SAMAccountName=withheld)))
    refused_write = _refusal(
        lambda: dsdata.create_user(
            DirectoryId=directory_id, SAMAccountName=withheld, GivenName="Sim", Surname="Nope"),
        f"CreateUser for {withheld!r} after the data plane was disabled again",
    )
    assert refused_write.get("Code") == refused_read.get("Code"), (
        f"expected a read and a write against the same shut directory to be refused with the "
        f"IDENTICAL code, got {refused_write.get('Code')!r} for the write and "
        f"{refused_read.get('Code')!r} for the read"
    )
    assert refused_write.get("Message") == refused_read.get("Message"), (
        f"expected a read and a write against the same shut directory to carry the IDENTICAL "
        f"diagnostic — the gate is on the directory, not the operation — got "
        f"{refused_write.get('Message')!r} != {refused_read.get('Message')!r} "
        f"(for reference, the NEVER-enabled wording measured was "
        f"{_NEVER_ENABLED_MESSAGE!r})"
    )
    refused_list = _refusal(
        lambda: dsdata.list_users(DirectoryId=directory_id),
        "ListUsers after the data plane was disabled again",
    )
    assert refused_list.get("Code") == refused_read.get("Code"), (
        f"expected the inventory read to be refused with the same code as the object read, got "
        f"{refused_list.get('Code')!r} against {refused_read.get('Code')!r}"
    )

    during = _describe_directory(ds, directory_id) or {}
    assert during.get("Stage") == "Active", (
        f"expected the directory to remain Stage 'Active' while its data plane is disabled — the "
        f"gate is on the data plane, not the directory — got {during.get('Stage')!r} "
        f"(StageReason={during.get('StageReason')!r})"
    )

    ds.enable_directory_data_access(DirectoryId=directory_id)
    reopened = _poll(
        lambda: _data_access(ds, directory_id),
        lambda s: s in ("Enabled", "Failed"),
        timeout_s=_ENABLE_DEADLINE_S, interval_s=10.0,
        what=f"DataAccessStatus on {directory_id} to settle after the second "
             f"EnableDirectoryDataAccess",
    )
    assert reopened == "Enabled", (
        f"expected the second EnableDirectoryDataAccess to drive DataAccessStatus back to 'Enabled', "
        f"got {reopened!r}"
    )

    after_user = _poll(
        lambda: dsdata.describe_user(DirectoryId=directory_id, SAMAccountName=user),
        lambda u: u.get("SAMAccountName") == user,
        timeout_s=_READ_BACK_DEADLINE_S, interval_s=5.0,
        what=f"ds-data DescribeUser to answer for {user!r} again once the door is reopened",
    )
    assert after_user.get("SID") == user_sid, (
        f"expected the user to survive a disable/re-enable cycle as the SAME Active Directory "
        f"object — a SID is minted by AD and cannot be re-derived — expected SID {user_sid!r}, got "
        f"{after_user.get('SID')!r}"
    )
    assert after_user.get("EmailAddress") == before_user.get("EmailAddress"), (
        f"expected the user's attributes to survive the cycle, expected EmailAddress "
        f"{before_user.get('EmailAddress')!r}, got {after_user.get('EmailAddress')!r}"
    )
    assert after_user.get("Enabled") == before_user.get("Enabled"), (
        f"expected the user's Enabled state to survive the cycle unchanged, expected "
        f"{before_user.get('Enabled')!r}, got {after_user.get('Enabled')!r}"
    )
    after_group = dsdata.describe_group(DirectoryId=directory_id, SAMAccountName=group)
    assert after_group.get("SID") == group_sid, (
        f"expected the group to survive the cycle as the same object, expected SID {group_sid!r}, "
        f"got {after_group.get('SID')!r}"
    )
    after_members = [m.get("SAMAccountName") for m in _pages(
        dsdata.list_group_members, "Members", DirectoryId=directory_id, SAMAccountName=group)]
    assert after_members == before_members, (
        f"expected the membership edge to survive the cycle, expected {before_members!r}, got "
        f"{after_members!r}"
    )
    # The inverse projection of the same edge.
    after_groups = {g.get("SAMAccountName") for g in _pages(
        dsdata.list_groups_for_member, "Groups", DirectoryId=directory_id, SAMAccountName=user)}
    assert group in after_groups, (
        f"expected ListGroupsForMember on {user!r} to still report {group!r} after the cycle — the "
        f"inverse projection of the same surviving edge — got {sorted(after_groups)!r}"
    )
    inventory = {u.get("SAMAccountName") for u in _pages(
        dsdata.list_users, "Users", DirectoryId=directory_id)}
    assert user in inventory, (
        f"expected {user!r} to be back in the paginated ListUsers inventory after the cycle, got "
        f"{sorted(inventory)!r}"
    )
    # Only observable now: a disabled directory cannot be enumerated.
    assert withheld not in inventory, (
        f"expected the CreateUser refused while the data plane was disabled to have created nothing, "
        f"but {withheld!r} is in the paginated ListUsers inventory of {len(inventory)} users: "
        f"{sorted(inventory)!r}"
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
                except ClientError as share_err:
                    if share_err.response["Error"]["Code"] != "EntityDoesNotExistException":
                        raise
                    shared = []
                for share in shared:
                    try:
                        ds.unshare_directory(
                            DirectoryId=directory_id,
                            UnshareTarget={"Id": share["SharedAccountId"], "Type": "ACCOUNT"},
                        )
                    except ClientError as unshare_err:
                        if unshare_err.response["Error"]["Code"] not in (
                            "EntityDoesNotExistException",
                            "DirectoryNotSharedException",
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
