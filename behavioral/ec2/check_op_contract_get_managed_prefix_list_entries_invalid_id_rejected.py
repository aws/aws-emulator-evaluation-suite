"""op-contract-get-managed-prefix-list-entries-invalid-id-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-get-managed-prefix-list-entries-invalid-id-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetManagedPrefixListEntries returns exactly the entries a prefix list was
    created with, and rejects a nonexistent prefix list id.
    """
    ec2 = ctx.client("ec2")

    entries = [
        {"Cidr": "10.205.0.0/16", "Description": "sim2real-entry-a"},
        {"Cidr": "10.206.0.0/20", "Description": "sim2real-entry-b"},
    ]
    prefix_list = ec2.create_managed_prefix_list(
        PrefixListName=ctx.unique_name("sim2real-pl-"),
        AddressFamily="IPv4",
        MaxEntries=5,
        Entries=entries,
        TagSpecifications=[
            {"ResourceType": "prefix-list", "Tags": [{"Key": "sim2real", "Value": "1"}]}
        ],
    )["PrefixList"]
    pl_id = prefix_list["PrefixListId"]
    _wait_pl_state(ec2, pl_id, {"create-complete"})
    ctx.on_cleanup(lambda: ec2.delete_managed_prefix_list(PrefixListId=pl_id))

    # success-path contract: exactly the entries provisioned come back, unmodified.
    got = ec2.get_managed_prefix_list_entries(PrefixListId=pl_id)["Entries"]
    got_pairs = {(e["Cidr"], e["Description"]) for e in got}
    expected_pairs = {(e["Cidr"], e["Description"]) for e in entries}
    assert got_pairs == expected_pairs, f"expected {expected_pairs}, got {got_pairs}"

    # error boundary (overly-permissive probe): a well-formed but nonexistent prefix
    # list id must be rejected, not treated as an empty entry set.
    code = _error_code(
        lambda: ec2.get_managed_prefix_list_entries(PrefixListId="pl-00000000000000000")
    )
    _assert_invalid_id(code, "PrefixList")


def _wait_pl_state(ec2, pl_id, target_states, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        lists = ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"]
        if lists:
            state = lists[0]["State"]
            if state in target_states:
                return state
            if state == "create-failed":
                raise AssertionError(f"prefix list {pl_id} entered create-failed")
        time.sleep(interval_s)
    raise AssertionError(f"prefix list {pl_id} never reached {target_states}, last state {state}")


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an
    over-permissive target accepting a request real AWS rejects is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _assert_invalid_id(code, token):
    assert code.endswith(".NotFound") or code.endswith(".Malformed"), (
        f"expected a *.NotFound/*.Malformed error code, got {code!r}"
    )
    assert token.lower() in code.lower(), f"expected {token!r} referenced in code, got {code!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
