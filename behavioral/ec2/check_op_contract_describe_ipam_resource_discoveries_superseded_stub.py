"""op-contract-describe-ipam-resource-discoveries-superseded-stub."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-describe-ipam-resource-discoveries-superseded-stub"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DescribeIpamResourceDiscoveries returns a new IPAM's default resource discovery as default,
    create-complete and owned by the IPAM's owner, and DryRun answers DryRunOperation with its exact
    message."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-behav-ipamrd2-")
    ipam = ec2.create_ipam(
        Description=name,
        Tier="free",
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))
    default_rd_id = ipam["DefaultResourceDiscoveryId"]
    assert default_rd_id, f"expected a default resource discovery id on {ipam}"

    # Success path: the IPAM's own default resource discovery must show up in
    # the unfiltered Describe list, with real, matching field content.
    discovery = _poll_until(
        lambda: _find(ec2.describe_ipam_resource_discoveries()["IpamResourceDiscoveries"], default_rd_id),
        lambda item: item is not None and item["State"] == "create-complete",
        timeout_s=60.0,
    )
    assert discovery is not None, f"default resource discovery {default_rd_id} never appeared"
    assert discovery["IpamResourceDiscoveryId"] == default_rd_id, (
        f"expected id {default_rd_id!r}, got {discovery['IpamResourceDiscoveryId']!r}"
    )
    assert discovery["IsDefault"] is True, f"expected IsDefault True, got {discovery['IsDefault']!r}"
    assert discovery["OwnerId"] == ipam["OwnerId"], (
        f"expected OwnerId {ipam['OwnerId']!r}, got {discovery['OwnerId']!r}"
    )
    assert discovery["State"] == "create-complete", (
        f"expected create-complete, got {discovery['State']!r}: {discovery}"
    )

    code, message = _error(lambda: ec2.describe_ipam_resource_discoveries(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {message!r}"


def _find(rows, discovery_id):
    for row in rows:
        if row.get("IpamResourceDiscoveryId") == discovery_id:
            return row
    return None


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
