"""op-contract-describe-ipv6-pools-superseded-stub."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-ipv6-pools-superseded-stub"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIpv6Pools answers 200 with one unpaginated list of pools with IDs and CIDR block lists,
    three reads return the same pool set, and DryRun answers DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_ipv6_pools()
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected 200, got {status!r}"
    assert "Ipv6Pools" in resp, f"missing key in response: {sorted(resp)}"
    pools = resp["Ipv6Pools"]
    assert isinstance(pools, list), f"Ipv6Pools is not a list: {pools!r}"
    for pool in pools:
        assert "PoolId" in pool, f"pool missing PoolId: {pool!r}"
        assert "PoolCidrBlocks" in pool, f"pool missing PoolCidrBlocks: {pool!r}"
        assert isinstance(pool["PoolCidrBlocks"], list), (
            f"PoolCidrBlocks is not a list: {pool['PoolCidrBlocks']!r}"
        )
    # With no MaxResults given, the service returns the full result set in one
    # page: NextToken must be absent/null, not a truncation cursor.
    assert resp.get("NextToken") is None, f"unexpected pagination cursor: {resp.get('NextToken')!r}"

    # Freeze detector: a plain read must not perturb state -- three consecutive
    # calls return the identical pool id set.
    ids_first = sorted(p["PoolId"] for p in pools)
    for _ in range(2):
        again = ec2.describe_ipv6_pools()["Ipv6Pools"]
        ids_again = sorted(p["PoolId"] for p in again)
        assert ids_again == ids_first, f"pool set changed across reads: {ids_first!r} -> {ids_again!r}"

    code, message = _client_error(lambda: ec2.describe_ipv6_pools(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"expected {_DRY_RUN_MESSAGE!r}, got {message!r}"


def _client_error(fn):
    """Call fn() and return the (code, message) it is refused with; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
