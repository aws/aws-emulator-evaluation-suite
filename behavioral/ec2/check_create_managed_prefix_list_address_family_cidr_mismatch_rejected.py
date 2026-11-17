"""create-managed-prefix-list-address-family-cidr-mismatch-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-managed-prefix-list-address-family-cidr-mismatch-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateManagedPrefixList rejects an IPv4 CIDR entry when AddressFamily is IPv6, and the
    matching IPv6 entry on the same request succeeds.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-plfam-")

    code, message = _client_error(
        lambda: ec2.create_managed_prefix_list(
            PrefixListName=name,
            AddressFamily="IPv6",
            MaxEntries=1,
            Entries=[{"Cidr": "10.50.0.0/24", "Description": "wrong-family"}],
            TagSpecifications=[{"ResourceType": "prefix-list", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
        )
    )
    assert code == "InvalidParameterCombination", f"expected InvalidParameterCombination, got {code!r}"
    expected_message = "An (IPv6) prefix list cannot contain an (10.50.0.0/24) CIDR."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the rejected request must not have minted a prefix list under this name
    all_names = {
        pl["PrefixListName"]
        for page in ec2.get_paginator("describe_managed_prefix_lists").paginate()
        for pl in page["PrefixLists"]
    }
    assert name not in all_names, f"rejected request must not appear in DescribeManagedPrefixLists: {name!r}"

    # positive control: the legal neighbour -- an IPv6 entry under AddressFamily=IPv6 -- succeeds
    resp = ec2.create_managed_prefix_list(
        PrefixListName=name,
        AddressFamily="IPv6",
        MaxEntries=1,
        Entries=[{"Cidr": "2001:db8::/32", "Description": "right-family"}],
        TagSpecifications=[{"ResourceType": "prefix-list", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    pl_id = resp["PrefixList"]["PrefixListId"]
    ctx.on_cleanup(lambda: ec2.delete_managed_prefix_list(PrefixListId=pl_id))
    assert resp["PrefixList"]["AddressFamily"] == "IPv6", (
        f"expected AddressFamily IPv6, got {resp['PrefixList']['AddressFamily']!r}"
    )

    final_state = _poll_until(
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0]["State"],
        lambda state: state in ("create-complete", "create-failed"),
        timeout_s=60,
        interval_s=3,
    )
    assert final_state == "create-complete", f"prefix list did not reach create-complete, got {final_state!r}"

    entries = ec2.get_managed_prefix_list_entries(PrefixListId=pl_id)["Entries"]
    cidrs = {e["Cidr"] for e in entries}
    assert cidrs == {"2001:db8::/32"}, f"unexpected entries: {entries!r}"


def _client_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
