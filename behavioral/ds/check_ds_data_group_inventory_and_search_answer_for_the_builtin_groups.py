"""ds-data-group-inventory-and-search-answer-for-the-builtin-groups."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where Directory Service cannot place domain controllers (CreateMicrosoftAD: "Failed to
# locate Availability Zone"); subnets there are never offered to it. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "ds-data-group-inventory-and-search-answer-for-the-builtin-groups"
GROUP = "directory-data"
SERVICES = ["ds"]
# Also drives ds-data (a separate signed endpoint, restJson1). SERVICES omits it because the
# manifest resolves services from the DIRECTORY name.

_PASSWORD = "Sim2Real#Pass99"
_SHARED_TAG_KEY = "sim2real-ds-shared"
_SHARED_TAG_VALUE = "behavioral-shared-mad"
_CREATE_TERMINAL = {"Active", "Inoperable", "Impaired", "Failed", "Deleted"}
_DIRECTORY_DEADLINE_S = 3600.0
_DATA_ACCESS_DEADLINE_S = 300.0
_VISIBLE_DEADLINE_S = 120.0
# Fixed, non-adjustable Windows well-known RIDs — part of the Active Directory contract, identical in
# every domain. NOT quotas, so pinning them is correct.
_DOMAIN_USERS_RID = "513"
_DOMAIN_ADMINS_RID = "512"
# A group attribute that IS a valid LDAP display name (User+Group, per the AWS Directory Service Data
# attribute table) but is not in the searchable allowlist, so it draws Reason
# INVALID_ATTRIBUTE_FOR_SEARCH rather than INVALID_ATTRIBUTE_NAME: 'Cn' is Searchable: No in that
# table, unlike a name the table has no entry for at all (such as 'whenCreated', which is not a valid
# LDAP display name here and draws INVALID_ATTRIBUTE_NAME instead).
_UNSEARCHABLE = "Cn"


# ===== self-contained helpers =====
def _refusal(fn, what: str) -> dict:
    """The refusal fn() raised, flattened over exc.response. RAISES on an unexpected success rather
    than returning a falsy sentinel, which would let an over-permissive target turn acceptance
    into an error-code mismatch. The whole response is merged over the Error sub-dict because
    ds-data's exceptions declare modelled members (a ``Reason`` enum) that restJson1 puts at the TOP
    LEVEL of the parsed response, not inside Error."""
    try:
        result = fn()
    except ClientError as exc:
        return {**exc.response, **(exc.response.get("Error") or {})}
    raise AssertionError(
        f"{what} SUCCEEDED where real AWS refuses it; the response was {result!r}"
    )


def _poll(fn, pred, *, timeout_s: float, interval_s: float, what: str):
    """Poll fn() until pred(result). RAISES on timeout, naming what it waited for."""
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
    """Every item under `key` across EVERY page of a ds-data List*/Search* operation. ds-data
    declares no botocore paginators, so the NextToken loop is explicit; a partially read page would
    silently shrink the inventory these assertions are computed from."""
    items: list = []
    token = None
    while True:
        page = fn(**({**kwargs, "NextToken": token} if token else kwargs))
        items.extend(page.get(key) or [])
        token = page.get("NextToken")
        if not token:
            return items


def _domain_sid(sid: str) -> str:
    """The domain portion of a Windows SID — everything before the final RID component.

    Every security principal in one domain shares this prefix, which is what makes it a derivation
    rather than a literal: no value is written into this file.
    """
    assert sid and sid.startswith("S-1-") and sid.count("-") >= 3, (
        f"expected a Windows SID of the form 'S-1-5-21-<domain>-<rid>', got {sid!r}"
    )
    return sid.rsplit("-", 1)[0]


def _default_vpc_subnets(ec2, *, ctx) -> tuple:
    """The account's shared network and two subnets in DISTINCT AZs, derived not hardcoded. The default
    VPC because a new-account VPC quota is five and a Managed AD needs two AZs, so per-check VPCs cap
    concurrency at four."""
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


def _adopt_or_create_directory(ctx, ds, ec2) -> tuple:
    """An Active Standard AWS Managed Microsoft AD -> (directory_id, fqdn). Create-or-adopt, so
    this works on a fresh account that has nothing AND on a re-run against one that already has a
    shared directory. Only a directory this call CREATED is registered for teardown; an adopted one
    is shared with other checks."""
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
            what=f"the adopted shared directory {existing['DirectoryId']} to leave its transient "
                 f"creation stages",
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
    """Drive DataAccessStatus to Enabled idempotently, and only undo what this call did — the toggle
    is a per-directory singleton four shipped checks depend on."""
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListGroups and SearchGroups answer out of a real Active Directory, not a store of what the API
    was told: the inventory holds built-in groups nothing created, each carrying its fixed Windows
    well-known RID, and every group shares one domain SID that SearchGroups' own equality match agrees with."""
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "expected STS to report the caller account id, got an empty value"

    directory_id, fqdn = _adopt_or_create_directory(ctx, ds, ec2)
    _require_data_access(ctx, ds, directory_id)
    dsdata = ctx.client("ds-data")

    mine = ctx.unique_name("s2rGrpInv")[:64]
    ctx.on_cleanup(lambda: dsdata.delete_group(DirectoryId=directory_id, SAMAccountName=mine))
    dsdata.create_group(DirectoryId=directory_id, SAMAccountName=mine)

    # --- (1) The inventory, read to the last page, must contain the group just created AND the
    # built-ins that nothing here created.
    listed = _poll(
        lambda: _pages(dsdata.list_groups, "Groups", DirectoryId=directory_id),
        lambda groups: mine in {g.get("SAMAccountName") for g in groups},
        timeout_s=_VISIBLE_DEADLINE_S, interval_s=5.0,
        what=f"the paginated ds-data ListGroups inventory to contain the group {mine!r} just created",
    )
    by_name = {g.get("SAMAccountName"): g for g in listed}
    assert mine in by_name, (
        f"expected the paginated ListGroups inventory to contain {mine!r}, got "
        f"{sorted(by_name)!r}"
    )
    assert "Domain Users" in by_name, (
        f"expected the inventory of a real Active Directory to contain the built-in 'Domain Users' "
        f"group, which nothing in this check created, got {sorted(by_name)!r}"
    )
    assert "Domain Admins" in by_name, (
        f"expected the inventory of a real Active Directory to contain the built-in 'Domain Admins' "
        f"group, which nothing in this check created, got {sorted(by_name)!r}"
    )

    # --- (2) The built-ins carry their fixed Windows well-known RIDs.
    domain_users_sid = by_name["Domain Users"].get("SID") or ""
    domain_admins_sid = by_name["Domain Admins"].get("SID") or ""
    assert domain_users_sid.endswith(f"-{_DOMAIN_USERS_RID}"), (
        f"expected 'Domain Users' to carry the fixed well-known RID {_DOMAIN_USERS_RID} — a Windows "
        f"constant, identical in every Active Directory — got SID {domain_users_sid!r}"
    )
    assert domain_admins_sid.endswith(f"-{_DOMAIN_ADMINS_RID}"), (
        f"expected 'Domain Admins' to carry the fixed well-known RID {_DOMAIN_ADMINS_RID}, got SID "
        f"{domain_admins_sid!r}"
    )

    # --- (3) THE DERIVATION. One domain, one domain SID, shared by what AD built and what we built.
    domain = _domain_sid(domain_users_sid)
    assert _domain_sid(domain_admins_sid) == domain, (
        f"expected every built-in group to share ONE domain SID, got {_domain_sid(domain_admins_sid)!r}"
        f" for 'Domain Admins' against {domain!r} for 'Domain Users'"
    )
    mine_sid = by_name[mine].get("SID") or ""
    assert _domain_sid(mine_sid) == domain, (
        f"expected the group this check created to be minted INSIDE the same domain as the built-ins "
        f"— every security principal in one domain shares its domain SID — expected prefix "
        f"{domain!r}, got {mine_sid!r}"
    )
    assert mine_sid not in (domain_users_sid, domain_admins_sid), (
        f"expected the created group to get its own RID rather than reusing a built-in's SID, got "
        f"{mine_sid!r}"
    )

    # --- (4) SearchGroups is an equality filter over the attribute it is told to use, and it agrees
    # with the inventory. The terminal read is through a DIFFERENT operation than the one that built
    # the inventory above.
    def _search(**kwargs) -> list:
        return _pages(dsdata.search_groups, "Groups", DirectoryId=directory_id, **kwargs)

    exact = _search(SearchString=mine, SearchAttributes=["SAMAccountName"])
    assert [g.get("SAMAccountName") for g in exact] == [mine], (
        f"expected SearchGroups on the whole sAMAccountName to return exactly {mine!r}, got {exact!r}"
    )
    assert exact[0].get("SID") == mine_sid, (
        f"expected the search index and the inventory to agree on the identity of {mine!r}, expected "
        f"SID {mine_sid!r} from ListGroups, got {exact[0].get('SID')!r} from SearchGroups"
    )
    builtin = _search(SearchString="Domain Users", SearchAttributes=["SAMAccountName"])
    assert [g.get("SAMAccountName") for g in builtin] == ["Domain Users"], (
        f"expected SearchGroups to find the built-in 'Domain Users' as well as the groups this check "
        f"created, got {builtin!r}"
    )
    assert builtin[0].get("SID") == domain_users_sid, (
        f"expected SearchGroups and ListGroups to agree on the built-in group's SID, expected "
        f"{domain_users_sid!r}, got {builtin[0].get('SID')!r}"
    )
    # Equality, not prefix. A substring index would return the group here.
    prefix = mine[:len(mine) // 2]
    assert len(prefix) >= 4, (
        f"expected the derived prefix of {mine!r} to be long enough to be a meaningful probe, got "
        f"{prefix!r}"
    )
    assert _search(SearchString=prefix, SearchAttributes=["SAMAccountName"]) == [], (
        f"expected SearchGroups to match whole values and not prefixes, but a search for the "
        f"{len(prefix)}-character prefix {prefix!r} of {mine!r} returned matches"
    )

    # --- (5) The realm is echoed, and it is the directory's own.
    page = dsdata.search_groups(
        DirectoryId=directory_id, SearchString=mine, SearchAttributes=["SAMAccountName"])
    assert page.get("Realm") == fqdn, (
        f"expected SearchGroups to echo the directory's own realm, expected {fqdn!r}, got "
        f"{page.get('Realm')!r}"
    )
    assert page.get("DirectoryId") == directory_id, (
        f"expected SearchGroups to echo the directory it searched, expected {directory_id!r}, got "
        f"{page.get('DirectoryId')!r}"
    )

    # --- (6) NEGATIVE, always-invalid input so no restore beat by construction. The positive control
    # is the successful equality search on this same wiring in step (4).
    refused = _refusal(
        lambda: dsdata.search_groups(
            DirectoryId=directory_id, SearchString=mine, SearchAttributes=[_UNSEARCHABLE]),
        f"SearchGroups over {_UNSEARCHABLE!r}, an attribute Active Directory does not index for "
        f"search",
    )
    assert refused.get("Code") == "ValidationException", (
        f"expected an unsearchable attribute to be refused with ValidationException, got {refused!r}"
    )
    assert refused.get("Reason") == "INVALID_ATTRIBUTE_FOR_SEARCH", (
        f"expected the refusal to name the unsearchable ATTRIBUTE as its reason rather than a "
        f"generic validation failure — the code alone is shared with every other ds-data validation "
        f"refusal — got Reason={refused.get('Reason')!r} in {refused!r}"
    )
    assert refused.get("Message") == f"Attribute '{_UNSEARCHABLE}' cannot be searched.", (
        f"expected the refusal to name the offending attribute in the wording measured for "
        f"the USER search family, got {refused.get('Message')!r}"
    )
    # The refused search changed nothing: the inventory is exactly what it was.
    after = {g.get("SAMAccountName") for g in _pages(
        dsdata.list_groups, "Groups", DirectoryId=directory_id)}
    assert after == set(by_name), (
        f"expected a refused SearchGroups to leave the group inventory untouched, expected "
        f"{sorted(by_name)!r}, got {sorted(after)!r}"
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

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
