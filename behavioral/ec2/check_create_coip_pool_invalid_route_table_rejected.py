"""create-coip-pool-invalid-route-table-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-coip-pool-invalid-route-table-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCoipPool rejects a well-formed unknown route table id with InvalidLocalGatewayRouteTableID.NotFound
    and a misshapen one with InvalidLocalGatewayRouteTableID.Malformed, each with its exact message, and
    creates no COIP pool; the success path needs an Outpost."""
    ec2 = ctx.client("ec2")

    # Positive control: CreateCoipPool succeeds only on an Outpost, so a read of the same
    # local-gateway surface must succeed instead.
    describe_resp = ec2.describe_local_gateway_route_tables()
    assert "LocalGatewayRouteTables" in describe_resp, (
        f"expected DescribeLocalGatewayRouteTables to succeed as a health check, got {describe_resp!r}"
    )
    baseline_pool_ids = {p["PoolId"] for p in ec2.describe_coip_pools()["CoipPools"]}

    # Correctly formatted local-gateway-route-table id that cannot exist in any account.
    bogus_route_table_id = "lgw-rtb-0123456789abcdef0"

    code, message = _error(lambda: ec2.create_coip_pool(LocalGatewayRouteTableId=bogus_route_table_id))
    assert code == "InvalidLocalGatewayRouteTableID.NotFound", (
        f"expected InvalidLocalGatewayRouteTableID.NotFound for a well-formed but nonexistent "
        f"local gateway route table id, got {code!r}"
    )
    expected = f"The LocalGateway Route Table ID '{bogus_route_table_id}' does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # A second, distinct malformed-id boundary: an id that isn't even shaped like
    # a local-gateway-route-table id at all must also be rejected (not silently coerced).
    code2, message2 = _error(lambda: ec2.create_coip_pool(LocalGatewayRouteTableId="totally-not-an-id"))
    assert code2 == "InvalidLocalGatewayRouteTableID.Malformed", (
        f"expected InvalidLocalGatewayRouteTableID.Malformed for an id that isn't shaped like a "
        f"local gateway route table id at all (distinct from the well-formed-but-absent case "
        f"above), got {code2!r}"
    )
    expected2 = "The local-gateway-route-table ID 'totally-not-an-id' is malformed"
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"

    # Independent read at the destination: neither rejected call created a pool.
    after_pool_ids = {p["PoolId"] for p in ec2.describe_coip_pools()["CoipPools"]}
    assert after_pool_ids == baseline_pool_ids, (
        f"expected no COIP pool to exist after two rejected CreateCoipPool calls, "
        f"new pool ids: {after_pool_ids - baseline_pool_ids}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected CreateCoipPool to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
