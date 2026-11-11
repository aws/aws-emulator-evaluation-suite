"""directory-settings-reject-unknown-names-and-values-outside-allowed-values."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "directory-settings-reject-unknown-names-and-values-outside-allowed-values"
GROUP = "directory-settings"
SERVICES = ["ds"]

_PASSWORD = "Sim2Real#Pass99"
_SHARED_TAG_KEY = "sim2real-ds-shared"
_SHARED_TAG_VALUE = "behavioral-shared-mad"
_CREATE_TERMINAL = {"Active", "Inoperable", "Impaired", "Failed", "Deleted"}
_DIRECTORY_DEADLINE_S = 3600.0
_REQUEST_SEEN_DEADLINE_S = 180.0
# DirectoryConfigurationStatus, verbatim from the model's enum.
_STATUS_ENUM = ("Requested", "Updating", "Updated", "Failed", "Default")
# Satisfies the modelled Name pattern ^[a-zA-Z0-9-/. _]*$ so the request reaches the service
# instead of failing client-side parameter validation.
_UNKNOWN_SETTING = "SIM2REAL_NOT_A_REAL_SETTING"
# Likewise a Value that satisfies ^[a-zA-Z0-9_]*$ but cannot be in any setting's AllowedValues.
_ILLEGAL_VALUE = "Sim2RealNotAnAllowedValue"


def _refusal(fn, what: str) -> dict:
    """The refusal fn() raised, flattened over exc.response; raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return {**exc.response, **(exc.response.get("Error") or {})}
    raise AssertionError(
        f"{what} SUCCEEDED where real AWS refuses it; the response was {result!r}"
    )


def _poll(fn, pred, *, timeout_s: float, interval_s: float, what: str):
    """Poll fn() until pred(result); raises on timeout, naming what it was waiting for."""
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


def _settings(ds, directory_id: str, **extra) -> list:
    """Every SettingEntry across every page of DescribeSettings.

    ds declares no paginator for DescribeSettings, so the NextToken loop is explicit.
    """
    entries: list = []
    token = None
    while True:
        page = ds.describe_settings(
            **({"DirectoryId": directory_id, **extra, "NextToken": token} if token
               else {"DirectoryId": directory_id, **extra}))
        entries.extend(page.get("SettingEntries") or [])
        token = page.get("NextToken")
        if not token:
            return entries


def _allowed(entry: dict) -> list:
    """AllowedValues parsed into its member values.
    The field is a JSON array of strings (e.g. '["Enable","Disable"]'), not comma-delimited."""
    raw = entry.get("AllowedValues") or ""
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = None
    assert isinstance(parsed, list), (
        f"expected AllowedValues to parse as a JSON array of strings, got {raw!r} for setting "
        f"{entry.get('Name')!r}"
    )
    return [str(value) for value in parsed]


def _default_vpc_subnets(ec2, *, ctx) -> tuple:
    """The account's shared VPC and two of its subnets in distinct AZs (a Managed AD needs two).
    Reusing one VPC avoids the five-VPC account quota."""
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
    """Adopt the tagged shared Managed Microsoft AD or create one -> (directory_id, fqdn).

    Only a directory this call created is torn down; an adopted one is shared with other checks.
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """UpdateSettings refuses an unknown Name and a Value outside AllowedValues with distinct codes
    and no effect; an allowed value moves only that entry's RequestStatus. DescribeSettings is a
    pure read, and its Status filter partitions the inventory.
    """
    ds = ctx.client("ds")
    ec2 = ctx.client("ec2")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "expected STS to report the caller account id, got an empty value"
    directory_id, _fqdn = _adopt_or_create_directory(ctx, ds, ec2)

    entries = _settings(ds, directory_id)
    assert entries, (
        f"expected DescribeSettings on the Active directory {directory_id!r} to report at least one "
        f"configurable setting, got an empty SettingEntries list"
    )
    by_name = {}
    for entry in entries:
        name = entry.get("Name")
        assert name, f"expected every SettingEntry to carry a Name, got {entry!r}"
        assert name not in by_name, (
            f"expected each setting Name to appear at most once in DescribeSettings, but {name!r} "
            f"appears twice: {by_name.get(name)!r} and {entry!r}"
        )
        assert entry.get("RequestStatus") in _STATUS_ENUM, (
            f"expected setting {name!r} to carry a RequestStatus from the modelled "
            f"DirectoryConfigurationStatus enum {_STATUS_ENUM!r}, got "
            f"{entry.get('RequestStatus')!r}"
        )
        for region, region_status in (entry.get("RequestDetailedStatus") or {}).items():
            assert region_status in _STATUS_ENUM, (
                f"expected the per-region RequestDetailedStatus of {name!r} to use the same "
                f"DirectoryConfigurationStatus enum, got {region_status!r} for region {region!r}"
            )
        by_name[name] = entry

    # The setting and value are derived from what the directory reports, not pinned.
    subject = None
    for name in sorted(by_name):
        entry = by_name[name]
        allowed = _allowed(entry)
        applied = entry.get("AppliedValue")
        if len(allowed) >= 2 and applied in allowed:
            subject = (name, entry, allowed, applied)
            break
    assert subject is not None, (
        f"expected at least one setting whose AllowedValues parses to >= 2 members AND contains its "
        f"own AppliedValue, so a legal alternative value can be derived rather than guessed; found "
        f"none across {len(by_name)} settings. If the AppliedValue is simply absent on an untouched "
        f"directory this selection needs widening; if AllowedValues does not split on ',' the parser "
        f"is wrong. Raw pairs: "
        f"{ {n: (by_name[n].get('AllowedValues'), by_name[n].get('AppliedValue')) for n in sorted(by_name)} !r}"
    )
    name, entry, allowed, applied = subject
    target_value = next(value for value in allowed if value != applied)
    other_names = sorted(n for n in by_name if n != name)
    assert other_names, (
        f"expected the directory to report more than one setting so the untouched-neighbour "
        f"assertions below have a subject, got only {name!r}"
    )
    frozen_neighbours = {n: dict(by_name[n]) for n in other_names}

    for attempt in range(3):
        again = {e.get("Name"): e for e in _settings(ds, directory_id)}
        assert set(again) == set(by_name), (
            f"read {attempt + 1} of 3: expected the DescribeSettings inventory to be unchanged by "
            f"reading it, expected {sorted(by_name)!r}, got {sorted(again)!r}"
        )
        assert again[name].get("RequestStatus") == entry.get("RequestStatus"), (
            f"read {attempt + 1} of 3: expected DescribeSettings to be a pure read, but the "
            f"RequestStatus of {name!r} moved from {entry.get('RequestStatus')!r} to "
            f"{again[name].get('RequestStatus')!r} with no UpdateSettings in between"
        )

    unknown = _refusal(
        lambda: ds.update_settings(
            DirectoryId=directory_id,
            Settings=[{"Name": _UNKNOWN_SETTING, "Value": applied}]),
        f"UpdateSettings for {_UNKNOWN_SETTING!r}, a name absent from the {len(by_name)} settings "
        f"this directory reports",
    )
    assert unknown.get("Code") == "UnsupportedSettingsException", (
        f"expected an unknown setting Name to be refused with UnsupportedSettingsException, got "
        f"{unknown!r}"
    )
    expected_unknown = (
        f"Setting name: {_UNKNOWN_SETTING} is not currently supported with Inner Exception: "
        f"UnsupportedSettingException: Setting name: {_UNKNOWN_SETTING} is not currently supported"
        f" : RequestId: {unknown['ResponseMetadata']['RequestId']}"
    )
    assert unknown.get("Message") == expected_unknown, (
        f"expected message {expected_unknown!r}, got {unknown.get('Message')!r}"
    )
    after_unknown = {e.get("Name"): e for e in _settings(ds, directory_id)}
    assert _UNKNOWN_SETTING not in after_unknown, (
        f"expected the refused UpdateSettings to create nothing, but {_UNKNOWN_SETTING!r} is in "
        f"the DescribeSettings inventory: {sorted(after_unknown)!r}"
    )

    assert _ILLEGAL_VALUE not in allowed, (
        f"the negative below requires {_ILLEGAL_VALUE!r} to be genuinely outside the AllowedValues "
        f"of {name!r}, but the directory lists it: {allowed!r}"
    )
    illegal = _refusal(
        lambda: ds.update_settings(
            DirectoryId=directory_id,
            Settings=[{"Name": name, "Value": _ILLEGAL_VALUE}]),
        f"UpdateSettings setting {name!r} to {_ILLEGAL_VALUE!r}, which is outside the AllowedValues "
        f"{allowed!r} the directory itself reported",
    )
    assert illegal.get("Code") == "InvalidParameterException", (
        f"expected a Value outside the entry's own AllowedValues to be refused with "
        f"InvalidParameterException, got {illegal!r}"
    )
    expected_illegal = (
        f"Invalid setting value found for Setting name: {name} and value: {_ILLEGAL_VALUE} with "
        f"Inner Exception: InvalidParameterException: Invalid setting value found for Setting "
        f"name: {name} and value: {_ILLEGAL_VALUE} : RequestId: "
        f"{illegal['ResponseMetadata']['RequestId']}"
    )
    assert illegal.get("Message") == expected_illegal, (
        f"expected message {expected_illegal!r}, got {illegal.get('Message')!r}"
    )
    assert illegal.get("Code") != unknown.get("Code"), (
        f"expected an unknown setting NAME and an out-of-range VALUE to draw DIFFERENT codes — a "
        f"target with one catch-all UpdateSettings error must not satisfy both negatives — got "
        f"{illegal.get('Code')!r} for both"
    )
    after_illegal = {e.get("Name"): e for e in _settings(ds, directory_id)}
    assert after_illegal[name].get("AppliedValue") == applied, (
        f"expected two refused UpdateSettings calls to leave the deployed value of {name!r} alone, "
        f"expected AppliedValue {applied!r}, got {after_illegal[name].get('AppliedValue')!r}"
    )
    assert after_illegal[name].get("RequestStatus") == entry.get("RequestStatus"), (
        f"expected a refused UpdateSettings not to enter the state machine at all, expected "
        f"RequestStatus {entry.get('RequestStatus')!r} for {name!r}, got "
        f"{after_illegal[name].get('RequestStatus')!r}"
    )

    # UpdateSettingsResult carries only DirectoryId, so acceptance is read via DescribeSettings.
    # Convergence to 'Updated' is not awaited; it takes far longer than this poll.
    accepted = ds.update_settings(
        DirectoryId=directory_id, Settings=[{"Name": name, "Value": target_value}])
    assert accepted.get("DirectoryId") == directory_id, (
        f"expected UpdateSettings to echo the directory it acted on, expected {directory_id!r}, got "
        f"{accepted!r}"
    )
    moved = _poll(
        lambda: {e.get("Name"): e for e in _settings(ds, directory_id)}[name],
        lambda e: e.get("RequestedValue") == target_value
        and e.get("RequestStatus") != entry.get("RequestStatus"),
        timeout_s=_REQUEST_SEEN_DEADLINE_S, interval_s=10.0,
        what=f"DescribeSettings to report {name!r} as requested to {target_value!r} and off its "
             f"resting RequestStatus {entry.get('RequestStatus')!r}",
    )
    assert moved.get("RequestedValue") == target_value, (
        f"positive control failed: expected the accepted UpdateSettings to be recorded as "
        f"RequestedValue {target_value!r} on {name!r}, got {moved.get('RequestedValue')!r}"
    )
    assert moved.get("RequestStatus") in ("Requested", "Updating", "Updated"), (
        f"positive control failed: expected an accepted UpdateSettings to put {name!r} into a "
        f"request state ('Requested', 'Updating' or 'Updated'), got "
        f"{moved.get('RequestStatus')!r} — 'Failed' and 'Default' both mean the request did not take"
    )
    assert moved.get("LastRequestedDateTime") is not None, (
        f"expected an accepted UpdateSettings to stamp LastRequestedDateTime on {name!r}, got "
        f"{moved!r}"
    )

    final = {e.get("Name"): e for e in _settings(ds, directory_id)}
    for neighbour in other_names:
        before = frozen_neighbours[neighbour]
        assert final[neighbour].get("AppliedValue") == before.get("AppliedValue"), (
            f"expected updating {name!r} to leave {neighbour!r} alone, expected AppliedValue "
            f"{before.get('AppliedValue')!r}, got {final[neighbour].get('AppliedValue')!r}"
        )
        assert final[neighbour].get("RequestStatus") == before.get("RequestStatus"), (
            f"expected updating {name!r} not to disturb the state machine of {neighbour!r}, "
            f"expected RequestStatus {before.get('RequestStatus')!r}, got "
            f"{final[neighbour].get('RequestStatus')!r}"
        )

    seen: dict = {}
    for status in _STATUS_ENUM:
        slice_entries = _settings(ds, directory_id, Status=status)
        for sliced in slice_entries:
            assert sliced.get("RequestStatus") == status, (
                f"expected DescribeSettings(Status={status!r}) to return only entries whose "
                f"RequestStatus is {status!r}, got {sliced.get('Name')!r} with "
                f"{sliced.get('RequestStatus')!r}"
            )
            assert sliced.get("Name") not in seen, (
                f"expected each setting to fall in exactly one Status slice, but "
                f"{sliced.get('Name')!r} is in both {seen.get(sliced.get('Name'))!r} and "
                f"{status!r}"
            )
            seen[sliced.get("Name")] = status
    assert set(seen) == set(final), (
        f"expected the five Status slices to partition the unfiltered inventory exactly, expected "
        f"{sorted(final)!r}, got {sorted(seen)!r}"
    )
    assert seen[name] == final[name].get("RequestStatus"), (
        f"expected the setting this check moved to be found in the slice matching its new "
        f"RequestStatus {final[name].get('RequestStatus')!r}, it was in {seen[name]!r}"
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
