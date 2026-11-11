"""op-contract-modify-managed-prefix-list."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-modify-managed-prefix-list"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyManagedPrefixList: adding an entry bumps Version/State, and a bogus
    PrefixListId is rejected with the specific not-found error."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-pl-")
    created = ec2.create_managed_prefix_list(
        PrefixListName=name,
        MaxEntries=5,
        AddressFamily="IPv4",
        Entries=[{"Cidr": "10.10.0.0/32", "Description": "seed"}],
        TagSpecifications=[{"ResourceType": "prefix-list", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["PrefixList"]
    pl_id = created["PrefixListId"]
    ctx.on_cleanup(lambda: _delete_prefix_list(ctx, pl_id))

    pl = _poll_until(
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0],
        lambda p: p["State"] in ("create-complete", "create-failed"),
        timeout_s=60,
    )
    assert pl["State"] == "create-complete", f"prefix list failed to create: {pl}"
    version_before = pl["Version"]

    # success path: add an entry. The Version bump is applied asynchronously (the
    # immediate response can still report the pre-modification version while the
    # modification is in progress), so we poll DescribeManagedPrefixLists rather than
    # asserting on the ModifyManagedPrefixList response body itself.
    modified = ec2.modify_managed_prefix_list(
        PrefixListId=pl_id,
        CurrentVersion=version_before,
        AddEntries=[{"Cidr": "10.10.1.0/32", "Description": "added"}],
    )["PrefixList"]
    assert modified["State"] in ("modify-in-progress", "modify-complete"), modified

    pl_after = _poll_until(
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0],
        lambda p: p["State"] in ("modify-complete", "modify-failed"),
        timeout_s=60,
    )
    assert pl_after["State"] == "modify-complete", f"modification failed: {pl_after}"
    assert pl_after["Version"] == version_before + 1, pl_after
    entries = ec2.get_managed_prefix_list_entries(PrefixListId=pl_id)["Entries"]
    assert any(e["Cidr"] == "10.10.1.0/32" for e in entries), entries

    # error boundary: a syntactically valid but nonexistent prefix list id is rejected
    err, err_message = _client_error(
        lambda: ec2.modify_managed_prefix_list(
            PrefixListId="pl-00000000000000000",
            CurrentVersion=1,
            AddEntries=[{"Cidr": "10.10.2.0/32"}],
        )
    )
    assert err == "InvalidPrefixListID.NotFound", err
    expected_message = "Prefix List pl-00000000000000000 not found."
    assert err_message == expected_message, f"expected message {expected_message!r}, got {err_message!r}"

    # the cleanup delete is a free negative: prove the id this check created is
    # gone via an independent read, and that a mutation against it now fails the
    # same way a mutation against a never-existing id does.
    ec2.delete_managed_prefix_list(PrefixListId=pl_id)

    def _lookup():
        try:
            lists = ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"]
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
        if not lists:
            return "__empty__"
        return f"__present:{lists[0]['State']}__"

    final = _poll_until(
        _lookup,
        lambda v: not str(v).startswith("__present"),
        timeout_s=120,
        interval_s=5,
    )
    gone = ("InvalidPrefixListID.NotFound", f"The prefix list ({pl_id}) does not exist.")
    assert final in (gone, "__empty__"), (
        f"expected deleted prefix list gone, got {final}"
    )

    dead_err, dead_err_message = _client_error(
        lambda: ec2.modify_managed_prefix_list(
            PrefixListId=pl_id,
            CurrentVersion=pl_after["Version"],
            AddEntries=[{"Cidr": "10.10.3.0/32"}],
        )
    )
    assert dead_err == "InvalidPrefixListID.NotFound", dead_err
    expected_message = f"Prefix List {pl_id} not found."
    assert dead_err_message == expected_message, f"expected message {expected_message!r}, got {dead_err_message!r}"


def _delete_prefix_list(ctx, pl_id: str) -> None:
    # Best-effort safety net for a run() that failed before reaching the
    # in-body delete: the success path already deletes pl_id itself, so
    # NotFound here just means there is nothing left to clean up.
    ec2 = ctx.client("ec2")
    try:
        _poll_until(
            lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0],
            lambda p: not p["State"].endswith("in-progress"),
            timeout_s=60,
        )
    except ClientError as err:
        if err.response["Error"]["Code"] != "InvalidPrefixListID.NotFound":
            raise
    try:
        ec2.delete_managed_prefix_list(PrefixListId=pl_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidPrefixListID.NotFound":
            raise


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
