"""reset-user-password-enables-the-ds-data-user-it-names."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "reset-user-password-enables-the-ds-data-user-it-names"
GROUP = "directory-data"
SERVICES = ["ds"]
# Also calls ds-data (the Directory Service Data API — a separate signed endpoint, restJson1 against
# awsJson1_1 for ds) and ec2 (to read the VPC substrate a directory requires).

_PASSWORD = "Sim2Real#Pass99"
_RESET_PASSWORD = "Sim2Real#Reset77"
_BAD_PASSWORD = "abc"
_SHARED_TAG_KEY = "sim2real-ds-shared"
_SHARED_TAG_VALUE = "behavioral-shared-mad"
_CREATE_TERMINAL = {"Active", "Inoperable", "Impaired", "Failed", "Deleted"}
# A Standard MicrosoftAD takes ~40 min to reach Active and longer with several creates in flight.
# The deadline clears the slowest create: giving up early fails a directory still being built.
_DIRECTORY_DEADLINE_S = 3600.0
_DATA_ACCESS_DEADLINE_S = 300.0
_RESET_VISIBLE_DEADLINE_S = 120.0


# ===== helpers =====
# _poll RAISES on timeout rather than returning its last value: a poll that returns silently turns a
# timeout into whatever the next assertion happens to say.
def _refusal(fn, what: str) -> dict:
    """The refusal fn() raised, flattened. Never returns a falsy sentinel on success.

    An unexpected SUCCESS is the strongest signal available — a target accepting a request real AWS
    refuses — so it raises rather than returning "", which would disguise over-permissiveness as an
    error-code mismatch that reads like a naming difference.

    The whole ``exc.response`` is merged over the ``Error`` sub-dict because the ds-data exceptions
    declare MODELLED members beside Message (AccessDeniedException carries a ``Reason`` enum) that
    restJson1 puts at the TOP LEVEL of the parsed response rather than inside ``Error``.
    """
    try:
        result = fn()
    except ClientError as exc:
        return {**exc.response, **(exc.response.get("Error") or {})}
    raise AssertionError(
        f"{what} SUCCEEDED where real AWS refuses it; the response was {result!r}"
    )


def _poll(fn, pred, *, timeout_s: float, interval_s: float, what: str):
    """Poll fn() until pred(result). RAISES on timeout, naming what it was waiting for."""
    deadline = time.monotonic() + timeout_s
    last = None
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

    ds-data declares no botocore paginators, so the NextToken loop is explicit. A partially read
    page would turn an inventory assertion into a flake.
    """
    items: list = []
    token = None
    while True:
        page = fn(**({**kwargs, "NextToken": token} if token else kwargs))
        items.extend(page.get(key) or [])
        token = page.get("NextToken")
        if not token:
            return items


def _default_vpc_subnets(ec2, *, ctx) -> tuple:
    """The account's shared network and two of its subnets in DISTINCT AZs -> (vpc_id, [id, id]).

    Nothing here mutates the VPC. The AZ is DERIVED from what the account offers rather than
    hardcoded, because an AZ name is a per-account alias for a different physical zone.
    """
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, (
        "expected the run to have a shared network, got none; a Managed Microsoft AD requires a "
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
        f"expected >= 2 available zones with a subnet in each (a directory is Multi-AZ by "
        f"requirement), got {len(zones)}: {by_zone!r} in {vpc['VpcId']!r}"
    )
    return vpc["VpcId"], [by_zone[z] for z in zones[:2]]


def _adopt_or_create_directory(ctx, ds, ec2) -> tuple:
    """An Active Standard AWS Managed Microsoft AD -> (directory_id, fqdn).

    Create-or-adopt: a Managed AD takes ~40 minutes to provision and bills per hour, so a directory
    tagged as shared is reused. Only a directory this call CREATED is registered for teardown;
    deleting an adopted one would take out every concurrent check sharing it.
    """
    for existing in ds.describe_directories().get("DirectoryDescriptions") or []:
        if existing.get("Type") != "MicrosoftAD" or not existing.get("DirectoryId"):
            continue
        listed = ds.list_tags_for_resource(ResourceId=existing["DirectoryId"]).get("Tags") or []
        if {"Key": _SHARED_TAG_KEY, "Value": _SHARED_TAG_VALUE} not in listed:
            continue
        adopted = _poll(
            lambda did=existing["DirectoryId"]: _describe_directory(ds, did) or {},
            lambda d: d.get("Stage") in _CREATE_TERMINAL,
            timeout_s=_DIRECTORY_DEADLINE_S, interval_s=20.0,
            what=f"the adopted shared directory {existing['DirectoryId']} to leave its "
                 f"transient creation stages",
        )
        assert adopted.get("Stage") == "Active", (
            f"expected the adopted shared directory {existing['DirectoryId']!r} to be Stage "
            f"'Active', got {adopted.get('Stage')!r} (StageReason={adopted.get('StageReason')!r})"
        )
        return existing["DirectoryId"], adopted["Name"]

    vpc_id, subnet_ids = _default_vpc_subnets(ec2, ctx=ctx)
    fqdn = f"{ctx.unique_name('sim2real-behav-')}.example.com"
    directory_id = ds.create_microsoft_ad(
        Name=fqdn, ShortName="SIM2REAL", Password=_PASSWORD, Edition="Standard",
        Description=f"sim2real behavioral {CHECK}",
        VpcSettings={"VpcId": vpc_id, "SubnetIds": subnet_ids},
        Tags=[{"Key": "sim2real", "Value": "behavioral"},
              {"Key": "sim2real-check", "Value": CHECK},
              {"Key": _SHARED_TAG_KEY, "Value": _SHARED_TAG_VALUE}],
    )["DirectoryId"]
    # Registered immediately, before any assertion can fail: a Managed AD bills per hour.
    ctx.on_cleanup(lambda: _delete_directory_and_wait(ds, directory_id))

    created = _poll(
        lambda: _describe_directory(ds, directory_id) or {},
        lambda d: d.get("Stage") in _CREATE_TERMINAL,
        timeout_s=_DIRECTORY_DEADLINE_S, interval_s=20.0,
        what=f"the new directory {directory_id} to reach a terminal creation stage",
    )
    assert created.get("Stage") == "Active", (
        f"expected the new directory to reach Stage 'Active', got {created.get('Stage')!r} "
        f"(StageReason={created.get('StageReason')!r})"
    )
    return directory_id, fqdn


def _require_data_access(ctx, ds, directory_id: str) -> None:
    """Drive DataAccessStatus to Enabled, idempotently, and only undo what this call did.

    EnableDirectoryDataAccess is a per-directory singleton. On an adopted directory it may already
    be Enabled, in which case this must not register a Disable teardown — that would break every
    concurrent check using the same directory's data plane.
    """
    status = ds.describe_directory_data_access(DirectoryId=directory_id).get("DataAccessStatus")
    if status != "Enabled":
        ds.enable_directory_data_access(DirectoryId=directory_id)
        ctx.on_cleanup(lambda: ds.disable_directory_data_access(DirectoryId=directory_id))
    reached = _poll(
        lambda: ds.describe_directory_data_access(
            DirectoryId=directory_id).get("DataAccessStatus"),
        lambda s: s in ("Enabled", "Failed"),
        timeout_s=_DATA_ACCESS_DEADLINE_S, interval_s=15.0,
        what=f"DataAccessStatus on {directory_id} to leave its transient states",
    )
    assert reached == "Enabled", (
        f"expected DataAccessStatus 'Enabled' before the ds-data endpoint will answer, got "
        f"{reached!r} (it was {status!r} before this check touched it)"
    )


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """ResetUserPassword on ds enables the disabled user ds-data created (DescribeUser flips Enabled
    False -> True); a name the directory lacks is refused until ds-data mints it, and a password
    failing the complexity policy is refused."""
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "expected STS to report the caller account id, got an empty value"

    directory_id, fqdn = _adopt_or_create_directory(ctx, ds, ec2)
    _require_data_access(ctx, ds, directory_id)
    dsdata = ctx.client("ds-data")

    subject = ctx.unique_name("s2rRst")[:20]
    absent = ctx.unique_name("s2rGone")[:20]
    # Registered BEFORE the calls that must fail, so a target that wrongly ACCEPTS them still has
    # its teardown wired: the AssertionError _refusal raises would otherwise abort first.
    for name in (subject, absent):
        ctx.on_cleanup(
            lambda n=name: dsdata.delete_user(DirectoryId=directory_id, SAMAccountName=n))

    # --- (1) The subject exists and, as ds-data mints it, is DISABLED.
    dsdata.create_user(DirectoryId=directory_id, SAMAccountName=subject, GivenName="Sim",
                       Surname="Real", EmailAddress=f"{subject}@{fqdn}")
    minted = dsdata.describe_user(DirectoryId=directory_id, SAMAccountName=subject)
    assert minted.get("SAMAccountName") == subject, (
        f"expected ds-data DescribeUser to return the user just created, expected SAMAccountName "
        f"{subject!r}, got {minted!r}"
    )
    assert minted.get("Enabled") is False, (
        f"expected a ds-data CreateUser to land DISABLED (Enabled is False) so the reset below has "
        f"something to flip, got Enabled={minted.get('Enabled')!r} for {subject!r}"
    )

    # --- (2) THE JOIN. The ds control plane resets a password for a name only ds-data ever wrote.
    ds.reset_user_password(DirectoryId=directory_id, UserName=subject,
                           NewPassword=_RESET_PASSWORD)

    # --- (3) TERMINAL READ, at the other endpoint, through a different operation than the mutation.
    flipped = _poll(
        lambda: dsdata.describe_user(DirectoryId=directory_id, SAMAccountName=subject),
        lambda u: u.get("Enabled") is True,
        timeout_s=_RESET_VISIBLE_DEADLINE_S, interval_s=5.0,
        what=f"ds-data DescribeUser to report Enabled True for {subject!r} after the ds "
             f"ResetUserPassword, which the model documents as enabling a disabled user",
    )
    assert flipped.get("Enabled") is True, (
        f"expected ds-data DescribeUser to report Enabled True after ResetUserPassword — the model "
        f"documents 'Disabled users will become enabled' — got Enabled={flipped.get('Enabled')!r} "
        f"for {subject!r}"
    )
    # The reset changed the password and the enablement, and NOTHING else about the object. A target
    # that reprovisions the user instead of modifying it would mint a fresh SID.
    assert flipped.get("SID") == minted.get("SID"), (
        f"expected ResetUserPassword to modify the existing object, not replace it: the Windows SID "
        f"must be unchanged, expected {minted.get('SID')!r}, got {flipped.get('SID')!r}"
    )
    assert flipped.get("EmailAddress") == minted.get("EmailAddress"), (
        f"expected the attributes ds-data wrote to survive a control-plane password reset, expected "
        f"EmailAddress {minted.get('EmailAddress')!r}, got {flipped.get('EmailAddress')!r}"
    )

    # --- (4) NEGATIVE A, all six beats. A name this directory does not hold.
    inventory = {u.get("SAMAccountName") for u in _pages(
        dsdata.list_users, "Users", DirectoryId=directory_id)}
    assert absent not in inventory, (
        f"the negative below requires {absent!r} to be genuinely absent, but it is already in the "
        f"paginated ds-data ListUsers inventory of {len(inventory)} users"
    )
    refused = _refusal(
        lambda: ds.reset_user_password(DirectoryId=directory_id, UserName=absent,
                                       NewPassword=_RESET_PASSWORD),
        f"ResetUserPassword for {absent!r}, a user ds-data does not hold",
    )
    assert refused.get("Code") == "UserDoesNotExistException", (
        f"expected ResetUserPassword for a name the directory does not hold to be refused with "
        f"UserDoesNotExistException, got {refused!r}"
    )
    expected_absent = (
        f"User: {absent} does not exist. : RequestId: "
        f"{(refused.get('ResponseMetadata') or {}).get('RequestId')}"
    )
    assert refused.get("Message") == expected_absent, (
        f"expected ResetUserPassword for {absent!r} to be refused with {expected_absent!r}, got "
        f"{refused.get('Message')!r}"
    )
    still_absent = {u.get("SAMAccountName") for u in _pages(
        dsdata.list_users, "Users", DirectoryId=directory_id)}
    assert absent not in still_absent, (
        f"expected the refused ResetUserPassword to create nothing, but {absent!r} is in the "
        f"ds-data ListUsers inventory of {len(still_absent)} users"
    )
    # RESTORE: mint exactly the missing thing through the OTHER API, and demand the identical call.
    dsdata.create_user(DirectoryId=directory_id, SAMAccountName=absent, GivenName="Sim",
                       Surname="Restored", EmailAddress=f"{absent}@{fqdn}")
    restored = _poll(
        lambda: _refusal_or_ok(
            lambda: ds.reset_user_password(DirectoryId=directory_id, UserName=absent,
                                           NewPassword=_RESET_PASSWORD)),
        lambda outcome: outcome is None,
        timeout_s=_RESET_VISIBLE_DEADLINE_S, interval_s=5.0,
        what=f"the byte-identical ResetUserPassword for {absent!r} to succeed now that ds-data has "
             f"created it — the restore beat that proves the refusal was a real directory lookup",
    )
    assert restored is None, (
        f"expected the identical ResetUserPassword to succeed once ds-data created {absent!r}, got "
        f"the refusal {restored!r}"
    )
    reenabled = dsdata.describe_user(DirectoryId=directory_id, SAMAccountName=absent)
    assert reenabled.get("Enabled") is True, (
        f"expected the restored user to be Enabled True after its own reset, got "
        f"Enabled={reenabled.get('Enabled')!r} for {absent!r}"
    )

    # --- (5) NEGATIVE B, always-invalid input, so no restore beat by construction. The positive
    # control is the compliant reset in step (2), on this very directory.
    weak = _refusal(
        lambda: ds.reset_user_password(DirectoryId=directory_id, UserName=subject,
                                       NewPassword=_BAD_PASSWORD),
        f"ResetUserPassword for {subject!r} with a {len(_BAD_PASSWORD)}-character all-lowercase "
        f"password, which cannot satisfy the directory's complexity policy",
    )
    assert weak.get("Code") == "InvalidPasswordException", (
        f"expected a password failing the directory's complexity policy to be refused with "
        f"InvalidPasswordException, got {weak!r}"
    )
    expected_weak = (
        "Could not reset user password, because the password does not meet the complexity "
        f"requirements. : RequestId: {(weak.get('ResponseMetadata') or {}).get('RequestId')}"
    )
    assert weak.get("Message") == expected_weak, (
        f"expected the weak-password ResetUserPassword to be refused with {expected_weak!r}, got "
        f"{weak.get('Message')!r}"
    )
    assert weak.get("Code") != refused.get("Code"), (
        f"expected a complexity refusal and a missing-user refusal to be DIFFERENT codes — an "
        f"emulator with one catch-all error for ResetUserPassword must not pass both — got "
        f"{weak.get('Code')!r} for both"
    )
    # The rejected weak reset left the subject exactly as the accepted reset had left it.
    unchanged = dsdata.describe_user(DirectoryId=directory_id, SAMAccountName=subject)
    assert unchanged.get("Enabled") is True, (
        f"expected the refused weak-password reset to leave the subject enabled by the earlier "
        f"successful reset, got Enabled={unchanged.get('Enabled')!r} for {subject!r}"
    )
    assert unchanged.get("SID") == minted.get("SID"), (
        f"expected the refused weak-password reset to leave the object untouched, expected SID "
        f"{minted.get('SID')!r}, got {unchanged.get('SID')!r}"
    )


def _refusal_or_ok(fn):
    """None if fn() succeeded, else the flattened refusal. For a poll whose success IS the target.

    Deliberately NOT _refusal: here a success is the awaited outcome rather than a defect, so this
    must be able to report "not yet" without raising. It never returns a falsy value for a refusal —
    the flattened dict always carries at least Code — so `outcome is None` cannot be satisfied by a
    refusal, and the poll's own timeout raises.
    """
    try:
        fn()
    except ClientError as exc:
        return {**exc.response, **(exc.response.get("Error") or {})}
    return None


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

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
