"""op-contract-deprovision-public-ipv4-pool-cidr-unprovisioned-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deprovision-public-ipv4-pool-cidr-unprovisioned-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeprovisionPublicIpv4PoolCidr on a real pool with a CIDR never provisioned into it succeeds and
    the pool still holds no address ranges; on a nonexistent pool ID it fails with
    InvalidPublicIpv4Pool.NotFound and its exact message."""
    ec2 = ctx.client("ec2")

    pool_id = ec2.create_public_ipv4_pool(
        TagSpecifications=[
            {
                "ResourceType": "ipv4pool-ec2",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-pubpool-")}],
            }
        ]
    )["PoolId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_public_ipv4_pool(PoolId=pool_id)))

    def _pool_exists():
        pools = ec2.describe_public_ipv4_pools(PoolIds=[pool_id])["PublicIpv4Pools"]
        return len(pools) == 1

    assert _poll_until(_pool_exists, lambda ok: ok, timeout_s=30, interval_s=2), "pool never appeared"

    # Error boundary #1: a real pool with a CIDR never provisioned into it. AWS answers a no-op success,
    # so assert that the CIDR never becomes part of the pool.
    never_provisioned_cidr = "203.0.113.0/24"
    resp = ec2.deprovision_public_ipv4_pool_cidr(PoolId=pool_id, Cidr=never_provisioned_cidr)
    assert resp.get("PoolId") == pool_id, f"unexpected response for no-op deprovision: {resp}"

    pool_after = ec2.describe_public_ipv4_pools(PoolIds=[pool_id])["PublicIpv4Pools"][0]
    ranges_after = pool_after.get("PoolAddressRanges", [])
    assert ranges_after == [], (
        f"a never-provisioned CIDR must never appear in the pool's address ranges, got {ranges_after}"
    )

    # error boundary #2: distinct failure mode - the pool itself doesn't exist
    bogus_pool_id = "ipv4pool-ec2-00000000000000000"
    error2 = _error(
        lambda: ec2.deprovision_public_ipv4_pool_cidr(PoolId=bogus_pool_id, Cidr="203.0.113.0/24")
    )
    assert error2["Code"] == "InvalidPublicIpv4Pool.NotFound", error2
    assert error2.get("Message") == f"The pool ID '{bogus_pool_id}' does not exist.", error2


def _error(fn):
    """Call fn() and return its botocore Error dict; a call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidPublicIpv4Pool.NotFound":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
