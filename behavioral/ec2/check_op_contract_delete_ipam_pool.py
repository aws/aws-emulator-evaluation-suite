"""op-contract-delete-ipam-pool."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-ipam-pool"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DeleteIpamPool with DryRun answers DryRunOperation and leaves the pool; the real call deletes an
    unused pool, and deleting it again fails with InvalidIpamPoolId.NotFound (exact messages)."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-ipam-")
    ipam = ec2.create_ipam(
        Description=name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    ipam = _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=60,
    )
    private_scope_id = ipam["PrivateDefaultScopeId"]

    pool_name = ctx.unique_name("sim2real-ipam-pool-")
    pool = ec2.create_ipam_pool(
        IpamScopeId=private_scope_id,
        AddressFamily="ipv4",
        Locale=ctx.region,
        TagSpecifications=[{"ResourceType": "ipam-pool", "Tags": [{"Key": "Name", "Value": pool_name}]}],
    )["IpamPool"]
    pool_id = pool["IpamPoolId"]

    pool = _poll_until(
        lambda: ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0],
        lambda p: p["State"] == "create-complete",
        timeout_s=60,
    )

    # error boundary: DryRun must short-circuit with DryRunOperation and leave the pool intact
    code, message = _error(lambda: ec2.delete_ipam_pool(IpamPoolId=pool_id, DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
    still_there = ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]
    assert still_there["State"] == "create-complete", "DryRun must not delete the pool"

    # success path: a pool with no provisioned CIDRs/allocations deletes cleanly
    resp = ec2.delete_ipam_pool(IpamPoolId=pool_id)
    assert resp["IpamPool"]["IpamPoolId"] == pool_id
    assert resp["IpamPool"]["State"] in ("delete-in-progress", "delete-complete")

    _poll_until(
        lambda: _describe_pools_tolerant(ec2, pool_id),
        lambda pools: (not pools) or pools[0]["State"] == "delete-complete",
        timeout_s=60,
    )

    # a mutation on the dead id must also fail, with the specific not-found code
    code, message = _error(lambda: ec2.delete_ipam_pool(IpamPoolId=pool_id))
    assert code == "InvalidIpamPoolId.NotFound", f"expected InvalidIpamPoolId.NotFound, got {code}"
    assert message == f"The ipam-pool ID '{pool_id}' does not exist", f"unexpected message {message!r}"


def _describe_pools_tolerant(ec2, pool_id):
    # once the pool is truly gone, DescribeIpamPools raises NotFound instead of
    # returning an empty list - treat that as "deleted" for polling purposes.
    try:
        return ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidIpamPoolId.NotFound":
            return []
        raise


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
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
