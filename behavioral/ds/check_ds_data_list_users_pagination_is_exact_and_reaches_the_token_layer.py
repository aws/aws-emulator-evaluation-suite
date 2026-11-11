"""ds-data-list-users-pagination-is-exact-and-reaches-the-token-layer."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "ds-data-list-users-pagination-is-exact-and-reaches-the-token-layer"
GROUP = "directory-data"
SERVICES = ["ds"]
# Also drives ds-data (a separate signed endpoint, restJson1).

_PASSWORD = "Sim2Real#Pass99"
_SHARED_TAG_KEY = "sim2real-ds-shared"
_SHARED_TAG_VALUE = "behavioral-shared-mad"
_CREATE_TERMINAL = {"Active", "Inoperable", "Impaired", "Failed", "Deleted"}
_DIRECTORY_DEADLINE_S = 3600.0
_DATA_ACCESS_DEADLINE_S = 300.0
_VISIBLE_DEADLINE_S = 180.0
_USERS_TO_CREATE = 5
# MaxResults has the modelled range 1..250, a fixed API constant rather than a quota.
_MAX_RESULTS_MIN = 1
_MAX_RESULTS_MAX = 250
# Satisfies the modelled length 1..6144 so the request reaches the service, not botocore validation.
_FABRICATED_TOKEN = "c2ltMnJlYWwtbm90LWEtcmVhbC1uZXh0LXRva2Vu"
# Absolute stop so a target that always returns a token cannot spin forever.
_PAGE_LIMIT = 500


def _refusal(fn, what: str) -> dict:
    """The error fn() raised, flattened over exc.response; raises if fn() succeeds.

    restJson1 puts ds-data's modelled ``Reason`` at the top level of the response, not in Error."""
    try:
        result = fn()
    except ClientError as exc:
        return {**exc.response, **(exc.response.get("Error") or {})}
    raise AssertionError(
        f"{what} SUCCEEDED where real AWS refuses it; the response was {result!r}"
    )


def _poll(fn, pred, *, timeout_s: float, interval_s: float, what: str):
    """Poll fn() until pred(result); raise on timeout, naming what it waited for."""
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


def _walk(fn, key: str, **kwargs) -> list:
    """Every raw page (not item) of a ds-data List* operation, in order, bounded by _PAGE_LIMIT."""
    pages: list = []
    token = None
    while True:
        page = fn(**({**kwargs, "NextToken": token} if token else kwargs))
        pages.append(page)
        token = page.get("NextToken")
        if not token:
            return pages
        assert len(pages) < _PAGE_LIMIT, (
            f"expected the paginated walk to terminate, but the target handed back a NextToken on "
            f"all {len(pages)} pages (limit {_PAGE_LIMIT}); last page carried "
            f"{len(page.get(key) or [])} items"
        )


def _names(pages: list, key: str) -> list:
    """Every sAMAccountName across `pages`, in page order, with duplicates preserved."""
    return [item.get("SAMAccountName") for page in pages for item in (page.get(key) or [])]


def _default_vpc_subnets(ec2, *, ctx) -> tuple:
    """The shared network's VPC and two subnets in distinct AZs, as a Managed AD requires."""
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
        f"expected >= 2 available zones with a subnet in each, got {len(zones)}: {by_zone!r} in "
        f"{vpc['VpcId']!r}"
    )
    return vpc["VpcId"], [by_zone[z] for z in zones[:2]]


def _adopt_or_create_directory(ctx, ds, ec2) -> tuple:
    """Adopt the shared Active Managed Microsoft AD, or create one -> (directory_id, fqdn).

    Only a directory this call created is torn down; an adopted one is shared with other checks."""
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
    """Drive DataAccessStatus to Enabled idempotently, undoing only what this call changed."""
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """ds-data ListUsers at MaxResults=1 yields exactly the unpaginated inventory, a replayed NextToken
    returns the same page, MaxResults=250 returns it in one page, and a fabricated token on a reachable
    directory is refused with ValidationException "Invalid parameter: NextToken." (INVALID_NEXT_TOKEN)."""
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "expected STS to report the caller account id, got an empty value"

    directory_id, fqdn = _adopt_or_create_directory(ctx, ds, ec2)
    _require_data_access(ctx, ds, directory_id)
    dsdata = ctx.client("ds-data")

    stem = ctx.unique_name("s2rPg")[:12]
    created = [f"{stem}{index}"[:20] for index in range(_USERS_TO_CREATE)]
    assert len(set(created)) == _USERS_TO_CREATE, (
        f"expected {_USERS_TO_CREATE} distinct sAMAccountNames after truncation to the modelled "
        f"20-character ceiling, got {created!r}"
    )
    for name in created:
        ctx.on_cleanup(
            lambda n=name: dsdata.delete_user(DirectoryId=directory_id, SAMAccountName=n))
    for name in created:
        dsdata.create_user(DirectoryId=directory_id, SAMAccountName=name, GivenName="Sim",
                           Surname="Paged", EmailAddress=f"{name}@{fqdn}")

    # The reference inventory from one unpaginated read; every count below derives from it.
    reference_pages = _poll(
        lambda: _walk(dsdata.list_users, "Users", DirectoryId=directory_id),
        lambda pages: set(created) <= set(_names(pages, "Users")),
        timeout_s=_VISIBLE_DEADLINE_S, interval_s=5.0,
        what=f"all {_USERS_TO_CREATE} created users to become visible to ds-data ListUsers",
    )
    reference = _names(reference_pages, "Users")
    assert len(reference) == len(set(reference)), (
        f"expected the default-page-size inventory to list each user once, got {len(reference)} "
        f"entries for {len(set(reference))} distinct names; duplicates: "
        f"{sorted(n for n in set(reference) if reference.count(n) > 1)!r}"
    )
    total = len(set(reference))
    assert set(created) <= set(reference), (
        f"expected the inventory to contain all {_USERS_TO_CREATE} users this check created, missing "
        f"{sorted(set(created) - set(reference))!r} from an inventory of {total}"
    )
    assert total > _MAX_RESULTS_MIN, (
        f"expected the inventory ({total} users) to exceed MaxResults={_MAX_RESULTS_MIN} so the walk "
        f"below genuinely spans multiple pages; a single-page walk would make every paging assertion "
        f"vacuous"
    )

    paged = _walk(dsdata.list_users, "Users", DirectoryId=directory_id,
                  MaxResults=_MAX_RESULTS_MIN)
    walked = _names(paged, "Users")
    assert sorted(walked) == sorted(reference), (
        f"expected paginating at MaxResults={_MAX_RESULTS_MIN} to yield exactly the same multiset of "
        f"users as one unpaginated read — no losses, no duplicates — expected {sorted(reference)!r}, "
        f"got {sorted(walked)!r} across {len(paged)} pages"
    )
    for index, page in enumerate(paged):
        held = page.get("Users") or []
        assert len(held) <= _MAX_RESULTS_MIN, (
            f"expected page {index + 1} of {len(paged)} to honour MaxResults="
            f"{_MAX_RESULTS_MIN} as a ceiling, got {len(held)} users: "
            f"{[u.get('SAMAccountName') for u in held]!r}"
        )
        assert page.get("Realm") == fqdn, (
            f"expected every page to echo the directory's own realm, expected {fqdn!r}, got "
            f"{page.get('Realm')!r} on page {index + 1}"
        )
    assert not (paged[-1].get("NextToken") or None), (
        f"expected the final page of the walk to carry no NextToken, got "
        f"{paged[-1].get('NextToken')!r} on page {len(paged)} of {len(paged)}"
    )
    assert len(paged) >= total, (
        f"expected at least {total} pages to deliver {total} users at MaxResults="
        f"{_MAX_RESULTS_MIN} — a target that ignores the page size returns them all at once — got "
        f"{len(paged)} pages"
    )

    # A token names a position, not a cursor that advances on read.
    first = dsdata.list_users(DirectoryId=directory_id, MaxResults=_MAX_RESULTS_MIN)
    token = first.get("NextToken")
    assert token, (
        f"expected the first page at MaxResults={_MAX_RESULTS_MIN} of a {total}-user inventory to "
        f"carry a NextToken, got {first!r}"
    )
    replays = []
    for attempt in range(3):
        replay = dsdata.list_users(
            DirectoryId=directory_id, MaxResults=_MAX_RESULTS_MIN, NextToken=token)
        replays.append([u.get("SAMAccountName") for u in replay.get("Users") or []])
        assert replays[attempt] == replays[0], (
            f"expected replaying the IDENTICAL NextToken to return the IDENTICAL page — a token that "
            f"names a server-side cursor advancing on read fails here — attempt {attempt + 1} "
            f"returned {replays[attempt]!r} against {replays[0]!r} on attempt 1"
        )

    assert total < _MAX_RESULTS_MAX, (
        f"expected the inventory ({total} users) to fit inside the modelled MaxResults maximum of "
        f"{_MAX_RESULTS_MAX} so a single-page read is the correct expectation; it does not, and this "
        f"leg needs rethinking rather than relaxing"
    )
    whole = dsdata.list_users(DirectoryId=directory_id, MaxResults=_MAX_RESULTS_MAX)
    assert sorted(u.get("SAMAccountName") for u in whole.get("Users") or []) == sorted(
            set(reference)), (
        f"expected MaxResults={_MAX_RESULTS_MAX} to return all {total} users in one page, got "
        f"{sorted(u.get('SAMAccountName') for u in whole.get('Users') or [])!r}"
    )
    assert not (whole.get("NextToken") or None), (
        f"expected no NextToken when the whole {total}-user inventory fits in one page of "
        f"{_MAX_RESULTS_MAX}, got {whole.get('NextToken')!r}"
    )

    refused = _refusal(
        lambda: dsdata.list_users(DirectoryId=directory_id, NextToken=_FABRICATED_TOKEN),
        f"ListUsers with the fabricated NextToken {_FABRICATED_TOKEN!r} against a directory this "
        f"caller CAN reach",
    )
    assert refused.get("Code") == "ValidationException", (
        f"expected a fabricated NextToken on a REACHABLE directory to reach the token-parsing layer "
        f"and be refused with ValidationException, got {refused!r}"
    )
    assert refused.get("Message") == "Invalid parameter: NextToken.", (
        f"unexpected ValidationException message: {refused.get('Message')!r}"
    )
    assert refused.get("Reason") == "INVALID_NEXT_TOKEN", (
        f"expected the refusal to name the TOKEN as its reason rather than a member constraint — the "
        f"ValidationException code alone is shared with every other ds-data validation refusal — got "
        f"Reason={refused.get('Reason')!r} in {refused!r}"
    )
    after = _names(_walk(dsdata.list_users, "Users", DirectoryId=directory_id), "Users")
    assert sorted(after) == sorted(reference), (
        f"expected a refused paginated read to leave the inventory untouched, expected "
        f"{sorted(reference)!r}, got {sorted(after)!r}"
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
