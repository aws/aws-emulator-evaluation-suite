"""op-contract-describe-ipam-resource-discoveries."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-describe-ipam-resource-discoveries"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIpamResourceDiscoveries reflects a freshly created discovery + DryRun boundary."""
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")

    owns_discovery = True
    name = ctx.unique_name("sim2real-behav-ipamrd-")
    try:
        created = ec2.create_ipam_resource_discovery(
            OperatingRegions=[{"RegionName": ctx.region}],
            Description=name,
            TagSpecifications=[
                {"ResourceType": "ipam-resource-discovery", "Tags": [{"Key": "Name", "Value": name}]}
            ],
        )["IpamResourceDiscovery"]
        rd_id = created["IpamResourceDiscoveryId"]
        ctx.on_cleanup(lambda: ec2.delete_ipam_resource_discovery(IpamResourceDiscoveryId=rd_id))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceLimitExceeded":
            raise
        # The account is already at its resource-discovery quota (accounts
        # typically start with a default discovery pre-provisioned). Fall
        # back to exercising the Describe contract against an existing
        # resource discovery instead of creating a new one.
        owns_discovery = False
        existing = ec2.describe_ipam_resource_discoveries()["IpamResourceDiscoveries"]
        assert existing, "hit ResourceLimitExceeded but no existing resource discoveries found"
        rd_id = existing[0]["IpamResourceDiscoveryId"]

    # Success path: the discovery must show up, described by id, and be in a terminal
    # "create-complete" state.
    final = _poll_until(
        lambda: ec2.describe_ipam_resource_discoveries(IpamResourceDiscoveryIds=[rd_id])[
            "IpamResourceDiscoveries"
        ][0],
        lambda item: item["State"] == "create-complete",
        timeout_s=60.0,
    )
    assert final["IpamResourceDiscoveryId"] == rd_id, f"expected {rd_id}, got {final['IpamResourceDiscoveryId']}"
    if owns_discovery:
        assert any(r["RegionName"] == ctx.region for r in final["OperatingRegions"]), (
            f"expected {ctx.region} among operating regions, got {final['OperatingRegions']}"
        )

    # Filtering by a well-formed but nonexistent id is a specific NotFound (unlike
    # e.g. VPC-style filters, IPAM resource discovery lookups by id error out rather
    # than narrowing to an empty result set).
    code, message = _error(
        lambda: ec2.describe_ipam_resource_discoveries(
            IpamResourceDiscoveryIds=["ipam-res-disco-0000000000000000"]
        )
    )
    assert code == "InvalidIpamResourceDiscoveryId.NotFound", f"expected NotFound, got {code!r}"
    assert message == (
        "The IPAM resource discovery (ipam-res-disco-0000000000000000) does not exist."
    ), f"unexpected InvalidIpamResourceDiscoveryId.NotFound message: {message!r}"

    # Error boundary: DryRun.
    code, message = _error(lambda: ec2.describe_ipam_resource_discoveries(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {message!r}"


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
    raise AssertionError(f"condition not met within {timeout_s}s; last={result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
