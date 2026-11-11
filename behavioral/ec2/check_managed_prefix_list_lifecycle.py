"""managed-prefix-list-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-prefix-list-lifecycle"
GROUP = 'prefix-list'
SERVICES = ['ec2']


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A MaxEntries=2 prefix list fills to its cap with a version bump, one entry past it fails
    PrefixListMaxEntriesExceeded with its exact message and changes neither version nor entries, and
    after DeleteManagedPrefixList a modify fails InvalidPrefixListID.NotFound.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-pl-")
    resp = ec2.create_managed_prefix_list(
        PrefixListName=name,
        MaxEntries=2,
        AddressFamily="IPv4",
        Entries=[{"Cidr": "10.0.0.0/24", "Description": "first"}],
        TagSpecifications=_ec2_tag_specs("prefix-list", name),
    )
    pl = resp["PrefixList"]
    pl_id = pl["PrefixListId"]
    ctx.on_cleanup(lambda: _swallow(lambda: ec2.delete_managed_prefix_list(PrefixListId=pl_id)))
    assert pl["MaxEntries"] == 2, f"expected MaxEntries=2, got {pl['MaxEntries']}"
    assert pl["AddressFamily"] == "IPv4", f"expected AddressFamily=IPv4, got {pl['AddressFamily']}"

    def _describe():
        return ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0]

    _poll_until(_describe, lambda p: p["State"] == "create-complete", timeout_s=120, interval_s=3)
    version = _describe()["Version"]

    entries = ec2.get_managed_prefix_list_entries(PrefixListId=pl_id)["Entries"]
    assert [e["Cidr"] for e in entries] == ["10.0.0.0/24"], f"unexpected entries: {entries}"

    # Positive control: adding a second entry, exactly up to the declared MaxEntries
    # cap, must succeed. This is what makes the refusal below attributable to the
    # cap specifically, not to ModifyManagedPrefixList being broken outright.
    ec2.modify_managed_prefix_list(
        PrefixListId=pl_id,
        CurrentVersion=version,
        AddEntries=[{"Cidr": "10.1.0.0/24", "Description": "second"}],
    )
    at_cap = _poll_until(_describe, lambda p: p["State"] == "modify-complete", timeout_s=60, interval_s=3)
    assert at_cap["Version"] == version + 1, (
        f"expected version {version + 1} after the positive-control modify, got {at_cap['Version']}"
    )
    cidrs_at_cap = sorted(e["Cidr"] for e in ec2.get_managed_prefix_list_entries(PrefixListId=pl_id)["Entries"])
    assert cidrs_at_cap == ["10.0.0.0/24", "10.1.0.0/24"], (
        f"expected exactly the 2 entries at the MaxEntries cap, got {cidrs_at_cap}"
    )
    version = at_cap["Version"]

    # Break exactly one thing: one more entry pushes the list past its declared
    # MaxEntries=2 cap, and must be refused with the specific error.
    over, over_message = _error(
        lambda: ec2.modify_managed_prefix_list(
            PrefixListId=pl_id,
            CurrentVersion=version,
            AddEntries=[{"Cidr": "10.2.0.0/24"}],
        )
    )
    assert over == "PrefixListMaxEntriesExceeded", (
        f"expected PrefixListMaxEntriesExceeded, got {over}"
    )
    assert over_message == (
        "You've reached the maximum number of entries for the prefix list. "
        "This modification saves (3) entries and the maximum number of entries for this "
        "prefix list is (2)."
    ), f"unexpected PrefixListMaxEntriesExceeded message {over_message!r}"

    # Effect absent: the refused modify must not have bumped the version or
    # changed the entry set.
    unchanged = _describe()
    assert unchanged["Version"] == version, (
        f"a refused ModifyManagedPrefixList bumped the version from {version} to {unchanged['Version']}"
    )
    cidrs_after_refusal = sorted(
        e["Cidr"] for e in ec2.get_managed_prefix_list_entries(PrefixListId=pl_id)["Entries"]
    )
    assert cidrs_after_refusal == cidrs_at_cap, (
        f"a refused ModifyManagedPrefixList changed the entry set from {cidrs_at_cap} "
        f"to {cidrs_after_refusal}"
    )

    # Delete, then prove the id is gone and unusable at an independent read.
    ec2.delete_managed_prefix_list(PrefixListId=pl_id)

    def _lookup():
        try:
            lists = ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        if not lists:
            return "__empty__"
        return f"__present:{lists[0]['State']}__"

    gone = _poll_until(_lookup, lambda v: not str(v).startswith("__present"), timeout_s=120, interval_s=5)
    assert gone in ("InvalidPrefixListID.NotFound", "__empty__"), (
        f"expected the deleted prefix list to be gone, got {gone}"
    )

    dead_mutation, dead_message = _error(
        lambda: ec2.modify_managed_prefix_list(
            PrefixListId=pl_id, CurrentVersion=version, AddEntries=[{"Cidr": "10.3.0.0/24"}]
        )
    )
    assert dead_mutation == "InvalidPrefixListID.NotFound", (
        f"expected a mutation on the deleted prefix list id to fail NotFound, got {dead_mutation}"
    )
    assert dead_message == f"Prefix List {pl_id} not found.", f"unexpected not-found message {dead_message!r}"

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidPrefixListID.NotFound":
            raise

def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s. Last result: {last!r}")

# Marker tag on every resource this check creates, so leftovers can be found by tag.
_MANAGED_TAG_KEY = "sim2real-managed"
_MANAGED_TAG_VALUE = "true"


def _ec2_tag_specs(resource_type: str, name: str | None = None) -> list[dict]:
    """TagSpecifications carrying the managed-resource marker tag."""
    tags = [{"Key": _MANAGED_TAG_KEY, "Value": _MANAGED_TAG_VALUE}]
    if name:
        tags.append({"Key": "Name", "Value": name})
    return [{"ResourceType": resource_type, "Tags": tags}]

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
