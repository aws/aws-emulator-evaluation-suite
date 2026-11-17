"""get-managed-prefix-list-associations-max-results-below-minimum-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-managed-prefix-list-associations-max-results-below-minimum-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetManagedPrefixListAssociations, sent without client-side validation, rejects a
    MaxResults one below its documented minimum of 5, and the minimum value itself is accepted.
    """
    ec2 = ctx.client("ec2")

    pl_name = ctx.unique_name("sim2real-pl-")
    pl_id = ec2.create_managed_prefix_list(
        PrefixListName=pl_name,
        AddressFamily="IPv4",
        MaxEntries=5,
        Entries=[{"Cidr": "10.60.0.0/24", "Description": "sim2real"}],
        TagSpecifications=[{"ResourceType": "prefix-list", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["PrefixList"]["PrefixListId"]
    ctx.on_cleanup(lambda: ec2.delete_managed_prefix_list(PrefixListId=pl_id))
    _poll_until(
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0]["State"],
        lambda state: state == "create-complete",
        timeout_s=60,
        interval_s=3,
    )

    # error boundary: one below the documented minimum of 5, sent past client-side validation
    raw_ec2 = ctx.client("ec2", config=Config(parameter_validation=False))
    code, message = _error(
        lambda: raw_ec2.get_managed_prefix_list_associations(PrefixListId=pl_id, MaxResults=4)
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected_message = "Value ( 4 ) for parameter maxResults is invalid. Expecting a value greater than or equal to 5."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: the legal neighbour -- the minimum value itself -- is accepted
    resp = ec2.get_managed_prefix_list_associations(PrefixListId=pl_id, MaxResults=5)
    assert resp["PrefixListAssociations"] == [], (
        f"expected no associations for a freshly created prefix list, got {resp['PrefixListAssociations']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator answering a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
