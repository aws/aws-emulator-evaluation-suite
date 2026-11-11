"""op-contract-delete-public-ipv4-pool-standalone-rejection."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-public-ipv4-pool-standalone-rejection"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePublicIpv4Pool on two pool IDs that were never provisioned fails with
    InvalidPublicIpv4Pool.NotFound and the exact message naming each ID, and neither ID appears in
    DescribePublicIpv4Pools."""
    ec2 = ctx.client("ec2")

    for bogus_pool_id in ("ipv4pool-ec2-00000000000000000", "ipv4pool-ec2-0123456789abcdef0"):
        code, message = _error(lambda pid=bogus_pool_id: ec2.delete_public_ipv4_pool(PoolId=pid))
        assert code == "InvalidPublicIpv4Pool.NotFound", f"unexpected code for {bogus_pool_id}: {code}"
        assert message == f"The pool ID '{bogus_pool_id}' does not exist.", message

        # Independent read at the destination: the rejected pool id must never
        # surface as an owned pool, confirming the rejection reflects real
        # account state rather than a response the delete call fabricates.
        pools = ec2.describe_public_ipv4_pools()["PublicIpv4Pools"]
        pool_ids = [p["PoolId"] for p in pools]
        assert bogus_pool_id not in pool_ids, (
            f"rejected pool id {bogus_pool_id} must not appear in describe_public_ipv4_pools, "
            f"got {pool_ids}"
        )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an over-permissive target accepting an input real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
