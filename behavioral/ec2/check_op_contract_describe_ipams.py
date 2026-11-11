"""op-contract-describe-ipams."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-describe-ipams"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DescribeIpams returns a new IPAM in create-complete with its Description, free tier and a default
    resource discovery; a well-formed unknown IPAM ID fails with InvalidIpamId.NotFound and its exact
    message."""
    ec2 = ctx.client("ec2")

    # The "ipamdc" prefix belongs to this check alone, so the stale-IPAM reclaim keyed on it never
    # deletes another check's live IPAM.
    description = ctx.unique_name("sim2real-behav-ipamdc-")

    # The per-Region IPAM quota can be 1, so an interrupted run's leftover IPAM makes CreateIpam fail
    # with ResourceLimitExceeded; reclaim leftovers with this check's own prefix first.
    _reclaim_stale_test_ipams(ec2)

    created = ec2.create_ipam(
        Description=description,
        Tier="free",
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": description}]}],
    )["Ipam"]
    ipam_id = created["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    final = _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda item: item["State"] == "create-complete",
        timeout_s=60.0,
    )
    assert final is not None and final["State"] == "create-complete", f"got {final}"
    assert final["Description"] == description, f"expected Description {description!r}, got {final['Description']!r}"
    assert final["Tier"] == "free", f"expected Tier 'free', got {final['Tier']!r}"
    assert final["IpamId"] == ipam_id, f"expected IpamId {ipam_id!r}, got {final['IpamId']!r}"
    assert final.get("DefaultResourceDiscoveryId"), "expected a default resource discovery id"

    # Describing by a well-formed but nonexistent id must fail with the specific NotFound
    # code for this resource type, not a generic 400.
    code, message = _client_error(lambda: ec2.describe_ipams(IpamIds=["ipam-0000000000000000"]))
    assert code == "InvalidIpamId.NotFound", f"expected InvalidIpamId.NotFound, got {code!r}"
    expected_message = "The IPAM (ipam-0000000000000000) does not exist."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _reclaim_stale_test_ipams(ec2, prefix="sim2real-behav-ipamdc", timeout_s=60.0):
    from botocore.exceptions import ClientError

    try:
        rows = ec2.describe_ipams().get("Ipams", [])
    except ClientError:
        return
    stale_ids = [
        row["IpamId"]
        for row in rows
        if row.get("Description", "").startswith(prefix) and row.get("State") != "delete-complete"
    ]
    if not stale_ids:
        return
    for ipam_id in stale_ids:
        try:
            ec2.delete_ipam(IpamId=ipam_id, Cascade=True)
        except ClientError:
            pass
    _poll_until(
        lambda: ec2.describe_ipams(IpamIds=stale_ids)["Ipams"],
        lambda leftover: all(row.get("State") == "delete-complete" for row in leftover),
        timeout_s=timeout_s,
    )


def _client_error(fn):
    """Call fn() and return the (code, message) it is refused with; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not observed within {timeout_s}s; last saw {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
