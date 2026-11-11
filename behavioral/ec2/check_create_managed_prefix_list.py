"""create-managed-prefix-list."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-managed-prefix-list"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateManagedPrefixList returns an IPv4 list (MaxEntries 5, Version 1) that reaches create-complete with its
    two entries, while a name over 255 characters is refused with InvalidParameterValue and its exact message
    and no list carries it.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-pl-")

    resp = ec2.create_managed_prefix_list(
        PrefixListName=name,
        AddressFamily="IPv4",
        MaxEntries=5,
        Entries=[
            {"Cidr": "10.44.0.0/24", "Description": "a"},
            {"Cidr": "10.44.1.0/24", "Description": "b"},
        ],
        TagSpecifications=[
            {"ResourceType": "prefix-list", "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}]}
        ],
    )
    prefix_list = resp["PrefixList"]
    pl_id = prefix_list["PrefixListId"]
    ctx.on_cleanup(lambda: ec2.delete_managed_prefix_list(PrefixListId=pl_id))

    assert prefix_list["AddressFamily"] == "IPv4", f"expected AddressFamily IPv4, got {prefix_list['AddressFamily']!r}"
    assert prefix_list["MaxEntries"] == 5, f"expected MaxEntries 5, got {prefix_list['MaxEntries']!r}"
    assert prefix_list["Version"] == 1, f"expected initial Version 1, got {prefix_list['Version']!r}"
    assert prefix_list["PrefixListId"].startswith("pl-"), f"expected a pl- id, got {prefix_list['PrefixListId']!r}"

    final_state = _poll_until(
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0]["State"],
        lambda state: state in ("create-complete", "create-failed"),
        timeout_s=60,
        interval_s=3,
    )
    assert final_state == "create-complete", f"prefix list did not reach create-complete, got {final_state!r}"

    entries = ec2.get_managed_prefix_list_entries(PrefixListId=pl_id)["Entries"]
    cidrs = {e["Cidr"] for e in entries}
    assert cidrs == {"10.44.0.0/24", "10.44.1.0/24"}, f"unexpected entries: {entries!r}"

    too_long_name = "x" * 256
    code, message = _client_error(
        lambda: ec2.create_managed_prefix_list(
            PrefixListName=too_long_name,
            AddressFamily="IPv4",
            MaxEntries=1,
        )
    )
    assert code == "InvalidParameterValue", (
        f"expected an over-length prefix list name to be rejected with InvalidParameterValue, got {code!r}"
    )
    expected_message = (
        "The prefix list name is too long. A prefix list name can be up to (255) characters in length."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    all_names = {
        pl["PrefixListName"]
        for page in ec2.get_paginator("describe_managed_prefix_lists").paginate()
        for pl in page["PrefixLists"]
    }
    assert too_long_name not in all_names, (
        f"rejected over-length name {too_long_name!r} must not appear in DescribeManagedPrefixLists"
    )


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
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
