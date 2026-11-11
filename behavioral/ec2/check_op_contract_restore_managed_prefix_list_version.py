"""op-contract-restore-managed-prefix-list-version."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-restore-managed-prefix-list-version"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RestoreManagedPrefixListVersion reverts the entry set of a managed prefix list to
    match an earlier version's content, and rejects an unknown prefix list id with
    InvalidPrefixListID.NotFound."""
    ec2 = ctx.client("ec2")

    pl = ec2.create_managed_prefix_list(
        PrefixListName=ctx.unique_name("sim2real-pl-"),
        MaxEntries=2,
        AddressFamily="IPv4",
        Entries=[{"Cidr": "10.20.0.0/24", "Description": "v1"}],
        TagSpecifications=[{"ResourceType": "prefix-list", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["PrefixList"]
    pl_id = pl["PrefixListId"]
    ctx.on_cleanup(lambda: ec2.delete_managed_prefix_list(PrefixListId=pl_id))

    assert _poll_until(
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0][
            "State"
        ],
        lambda state: state == "create-complete",
        timeout_s=60,
        interval_s=3,
    ), "prefix list never reached create-complete"

    ec2.modify_managed_prefix_list(
        PrefixListId=pl_id,
        CurrentVersion=1,
        AddEntries=[{"Cidr": "10.20.1.0/24", "Description": "v2-added"}],
    )
    assert _poll_until(
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0][
            "State"
        ],
        lambda state: state == "modify-complete",
        timeout_s=60,
        interval_s=3,
    ), "prefix list never reached modify-complete"

    entries_v2 = ec2.get_managed_prefix_list_entries(PrefixListId=pl_id)["Entries"]
    assert len(entries_v2) == 2, f"expected 2 entries after modify, got {entries_v2}"

    ec2.restore_managed_prefix_list_version(
        PrefixListId=pl_id, PreviousVersion=1, CurrentVersion=2
    )
    assert _poll_until(
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0][
            "State"
        ],
        lambda state: state == "restore-complete",
        timeout_s=60,
        interval_s=3,
    ), "prefix list never reached restore-complete"

    entries_restored = ec2.get_managed_prefix_list_entries(PrefixListId=pl_id)["Entries"]
    assert len(entries_restored) == 1 and entries_restored[0]["Cidr"] == "10.20.0.0/24", (
        f"restore did not revert entries to version 1's content: {entries_restored}"
    )

    # Use a well-formed hex id that isn't a degenerate/sequential pattern (neither all-zero
    # nor the classic ascending 0123456789abcdef ladder): AWS's format validator rejects
    # those patterns as malformed before the request ever reaches the existence check, which
    # would produce a different error code than the NotFound boundary this check targets.
    # Also use distinct Previous/CurrentVersion values -- passing equal values fails AWS's
    # parameter validation (they must differ) before the id is ever looked up, which would
    # likewise surface a different error code than the NotFound boundary this check targets.
    code, message = _client_error(
        lambda: ec2.restore_managed_prefix_list_version(
            PrefixListId="pl-a1b2c3d4e5f607182", PreviousVersion=1, CurrentVersion=2
        )
    )
    assert code == "InvalidPrefixListID.NotFound", f"unexpected error code: {code}"
    expected_message = "The prefix list (pl-a1b2c3d4e5f607182) does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        try:
            result = probe()
        except Exception:
            result = None
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result if predicate(result) else False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
