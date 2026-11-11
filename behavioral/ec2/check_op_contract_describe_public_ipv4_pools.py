"""op-contract-describe-public-ipv4-pools."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-public-ipv4-pools"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribePublicIpv4Pools lists a created pool, also under an unrecognized filter name, which is
    ignored; a malformed PoolIds value fails with InvalidPublicIpv4PoolID.Malformed and its exact
    message."""
    ec2 = ctx.client("ec2")

    created = ec2.create_public_ipv4_pool(
        TagSpecifications=[{"ResourceType": "ipv4pool-ec2", "Tags": [{"Key": "sim2real", "Value": "1"}]}]
    )
    pool_id = created["PoolId"]
    ctx.on_cleanup(lambda: ec2.delete_public_ipv4_pool(PoolId=pool_id))

    resp = ec2.describe_public_ipv4_pools()
    assert "PublicIpv4Pools" in resp, f"missing PublicIpv4Pools in {resp!r}"
    pools = resp["PublicIpv4Pools"]
    assert isinstance(pools, list), f"expected a list, got {type(pools)!r}"
    for pool in pools:
        assert pool["PoolId"].startswith("ipv4pool-ec2-"), f"unexpected pool id shape: {pool['PoolId']!r}"
    assert any(p["PoolId"] == pool_id for p in pools), (
        f"expected created pool {pool_id} in unfiltered describe, got {[p['PoolId'] for p in pools]}"
    )

    # An unrecognized filter name is ignored, not rejected: the call succeeds with the documented shape
    # and still lists the created pool.
    resp2 = ec2.describe_public_ipv4_pools(
        Filters=[{"Name": "totally-bogus-filter-key", "Values": ["x"]}]
    )
    assert "PublicIpv4Pools" in resp2, f"missing PublicIpv4Pools in {resp2!r}"
    pools2 = resp2["PublicIpv4Pools"]
    assert isinstance(pools2, list), f"expected a list, got {type(pools2)!r}"
    assert any(p["PoolId"] == pool_id for p in pools2), (
        f"expected an unrecognized filter to be ignored, not to exclude {pool_id}: "
        f"got {[p['PoolId'] for p in pools2]}"
    )

    # A malformed pool id (wrong prefix/shape) is rejected server-side.
    code, message = _error(
        lambda: ec2.describe_public_ipv4_pools(PoolIds=["totally-bogus-pool-id"])
    )
    assert code == "InvalidPublicIpv4PoolID.Malformed", (
        f"expected InvalidPublicIpv4PoolID.Malformed, got {code}"
    )
    assert message == "The pool ID 'totally-bogus-pool-id' is invalid.", message


def _error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, because an emulator
    accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
