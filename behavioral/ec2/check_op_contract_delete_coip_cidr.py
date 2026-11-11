"""op-contract-deleteCoipCidr."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteCoipCidr"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."
_POOL_NOT_FOUND_MESSAGE = "The pool ID 'ipv4pool-coip-00000000000000000' does not exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCoipCidr on a nonexistent CoipPoolId fails with InvalidPoolID.NotFound and its exact message.
    Where a customer-owned IP pool exists or can be created (Outposts only), DryRun answers
    DryRunOperation and a real delete returns the CIDR and removes it from DescribeCoipPools."""
    ec2 = ctx.client("ec2")

    # Always testable, no prerequisite: a syntactically valid but nonexistent pool/cidr pair
    # must be rejected, not silently accepted.
    err = _client_error(
        lambda: ec2.delete_coip_cidr(
            CoipPoolId="ipv4pool-coip-00000000000000000", Cidr="203.0.113.0/24"
        )
    )
    assert err.get("Code") == "InvalidPoolID.NotFound", f"expected InvalidPoolID.NotFound, got {err!r}"
    assert err.get("Message") == _POOL_NOT_FOUND_MESSAGE, f"unexpected not-found message: {err!r}"

    pool_id = _adopt_or_create_pool(ctx, ec2)
    if pool_id is None:
        return

    test_cidr = "203.0.113.0/28"
    ec2.create_coip_cidr(CoipPoolId=pool_id, Cidr=test_cidr)

    def _cleanup() -> None:
        try:
            ec2.delete_coip_cidr(CoipPoolId=pool_id, Cidr=test_cidr)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidPoolID.NotFound":
                raise

    ctx.on_cleanup(_cleanup)

    # Error boundary: DryRun must short-circuit before the delete is applied.
    err = _client_error(
        lambda: ec2.delete_coip_cidr(CoipPoolId=pool_id, Cidr=test_cidr, DryRun=True)
    )
    assert err.get("Code") == "DryRunOperation", f"expected DryRunOperation, got {err!r}"
    assert err.get("Message") == _DRY_RUN_MESSAGE, f"unexpected DryRun message: {err!r}"

    resp = ec2.delete_coip_cidr(CoipPoolId=pool_id, Cidr=test_cidr)
    assert resp["CoipCidr"]["Cidr"] == test_cidr, (
        f"expected DeleteCoipCidr to echo {test_cidr!r}, got {resp['CoipCidr']!r}"
    )

    remaining = ec2.describe_coip_pools(PoolIds=[pool_id])["CoipPools"][0].get("PoolCidrs", [])
    assert test_cidr not in remaining, remaining

    # Error boundary: a nonexistent CoipPoolId is rejected with the specific not-found code.
    err2 = _client_error(
        lambda: ec2.delete_coip_cidr(CoipPoolId="ipv4pool-coip-00000000000000000", Cidr=test_cidr)
    )
    assert err2.get("Code") == "InvalidPoolID.NotFound", f"expected InvalidPoolID.NotFound, got {err2!r}"
    assert err2.get("Message") == _POOL_NOT_FOUND_MESSAGE, f"unexpected not-found message: {err2!r}"


def _adopt_or_create_pool(ctx, ec2):
    """Return a usable CoipPoolId: an existing pool, one created from a LocalGatewayRouteTableId
    (Outposts local gateway attached), or None when neither is available."""
    pools = ec2.describe_coip_pools().get("CoipPools", [])
    if pools:
        return pools[0]["PoolId"]

    route_tables = ec2.describe_local_gateway_route_tables().get("LocalGatewayRouteTables", [])
    if not route_tables:
        return None

    local_gateway_route_table_id = route_tables[0]["LocalGatewayRouteTableId"]
    pool = ec2.create_coip_pool(
        LocalGatewayRouteTableId=local_gateway_route_table_id,
        TagSpecifications=[
            {
                "ResourceType": "coip-pool",
                "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
            }
        ],
    )["CoipPool"]
    pool_id = pool["PoolId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_coip_pool(CoipPoolId=pool_id)))
    return pool_id


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "InvalidParameterValue"
            and "does not exist" in err.get("Message", "")
        ):
            raise


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
