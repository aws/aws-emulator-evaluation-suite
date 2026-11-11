"""op-contract-create-public-ipv4-pool."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-create-public-ipv4-pool"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePublicIpv4Pool: success creates an empty pool visible via an independent read;
    DryRun short-circuits before execution; deleting the pool removes it from that same
    independent read and a repeat delete is rejected rather than silently re-applied."""
    ec2 = ctx.client("ec2")

    resp = ec2.create_public_ipv4_pool()
    pool_id = resp["PoolId"]
    ctx.on_cleanup(lambda: _delete_if_present(ec2, pool_id))

    assert pool_id.startswith("ipv4pool-ec2-"), f"unexpected pool id shape: {pool_id!r}"

    described = ec2.describe_public_ipv4_pools(PoolIds=[pool_id])["PublicIpv4Pools"]
    assert len(described) == 1, f"expected exactly one pool for {pool_id!r}, got {len(described)}"
    assert described[0]["PoolId"] == pool_id, (
        f"expected PoolId {pool_id!r}, got {described[0]['PoolId']!r}"
    )
    # A freshly created pool owns no CIDRs yet.
    assert described[0].get("PoolAddressRanges", []) == [], (
        f"expected no address ranges on a freshly created pool, "
        f"got {described[0].get('PoolAddressRanges')!r}"
    )

    # Error boundary: DryRun must short-circuit with DryRunOperation rather than creating a pool.
    code, message = _client_error(lambda: ec2.create_public_ipv4_pool(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_dry_run = "Request would have succeeded, but DryRun flag is set."
    assert message == expected_dry_run, f"expected message {expected_dry_run!r}, got {message!r}"

    # Delete effect: the real delete under test must succeed, disappear from an
    # independent read, and a repeat delete must be rejected rather than re-applied.
    ec2.delete_public_ipv4_pool(PoolId=pool_id)

    expected_gone = f"The pool ID '{pool_id}' does not exist."
    code, message = _client_error(lambda: ec2.describe_public_ipv4_pools(PoolIds=[pool_id]))
    assert code == "InvalidPublicIpv4PoolID.NotFound", (
        f"expected InvalidPublicIpv4PoolID.NotFound describing the deleted pool {pool_id!r}, got {code!r}"
    )
    assert message == expected_gone, f"expected message {expected_gone!r}, got {message!r}"

    code, message = _client_error(lambda: ec2.delete_public_ipv4_pool(PoolId=pool_id))
    assert code == "InvalidPublicIpv4Pool.NotFound", (
        f"expected the repeat delete of {pool_id!r} to be rejected with InvalidPublicIpv4Pool.NotFound, "
        f"got {code!r}"
    )
    assert message == expected_gone, f"expected message {expected_gone!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


def _delete_if_present(ec2, pool_id):
    try:
        ec2.delete_public_ipv4_pool(PoolId=pool_id)
    except ClientError as e:
        if "NotFound" not in e.response["Error"]["Code"]:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
