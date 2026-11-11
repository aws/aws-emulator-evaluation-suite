"""op-contract-describe-ipv6-pools."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-ipv6-pools"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeIpv6Pools: success-path shape (BYOIP pools, usually none) + DryRun boundary."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_ipv6_pools()
    assert "Ipv6Pools" in resp, f"missing key in response: {sorted(resp)}"
    pools = resp["Ipv6Pools"]
    assert isinstance(pools, list), f"Ipv6Pools was not a list: {pools!r}"
    for pool in pools:
        assert "PoolId" in pool, f"pool missing PoolId: {sorted(pool)}"
        assert "PoolCidrBlocks" in pool, f"pool missing PoolCidrBlocks: {sorted(pool)}"

    # PoolIds is an existence lookup, not a plain filter: a well-formed but
    # nonexistent pool id is rejected as NotFound rather than narrowing to empty.
    code_pool, message_pool = _client_error(
        lambda: ec2.describe_ipv6_pools(PoolIds=["ipv6pool-ec2-00000000000000000"])
    )
    assert code_pool == "InvalidIpv6PoolID.NotFound", f"expected NotFound, got {code_pool!r}"
    expected_message_pool = "Ipv6Pool 'ipv6pool-ec2-00000000000000000' does not exist."
    assert message_pool == expected_message_pool, f"expected {expected_message_pool!r}, got {message_pool!r}"

    # Error boundary: DryRun.
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
