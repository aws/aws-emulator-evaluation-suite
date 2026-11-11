"""op-contract-delete-coip-pool."""
from __future__ import annotations
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-coip-pool"
GROUP = "error-semantics"
SERVICES = ["ec2"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCoipPool with DryRun answers DryRunOperation and a well-formed unknown pool ID fails with
    InvalidIpv4PoolCoipId.Malformed (exact messages); where an Outposts local gateway route table
    exists, a created pool deletes and no longer describes."""
    ec2 = ctx.client("ec2")
    fake_id = "coip-pool-00000000000000000"

    # Success-path contract proxy: EC2 DryRun is documented as a pure permission check ("If you
    # have the required permissions, the error response is DryRunOperation"), independent of
    # whether the referenced resource exists. This proves the call would have been accepted.
    dry_run_code, dry_run_message = _error(lambda: ec2.delete_coip_pool(CoipPoolId=fake_id, DryRun=True))
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code!r}"
    assert dry_run_message == "Request would have succeeded, but DryRun flag is set.", dry_run_message

    # Error boundary: AWS rejects this well-formed but unknown pool ID as malformed, since its CoIP pool
    # ID validation is stricter than an existence check.
    code, message = _error(lambda: ec2.delete_coip_pool(CoipPoolId=fake_id))
    assert code == "InvalidIpv4PoolCoipId.Malformed", f"expected InvalidIpv4PoolCoipId.Malformed, got {code!r}"
    assert message == f"The coip-pool ID '{fake_id}' is malformed", message

    # Deeper success path, reached only where Outposts infrastructure exists.
    route_tables = ec2.describe_local_gateway_route_tables().get("LocalGatewayRouteTables", [])
    if route_tables:
        lgrt_id = route_tables[0]["LocalGatewayRouteTableId"]
        pool = ec2.create_coip_pool(
            LocalGatewayRouteTableId=lgrt_id,
            TagSpecifications=[
                {
                    "ResourceType": "coip-pool",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-coip-")}],
                }
            ],
        )["CoipPool"]
        pool_id = pool["PoolId"]
        ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_coip_pool(CoipPoolId=pool_id)))
        resp = ec2.delete_coip_pool(CoipPoolId=pool_id)
        assert resp["CoipPool"]["PoolId"] == pool_id, (
            f"expected DeleteCoipPool to echo {pool_id!r}, got {resp['CoipPool'].get('PoolId')!r}"
        )
        remaining = ec2.describe_coip_pools(PoolIds=[pool_id]).get("CoipPools", [])
        assert not remaining, f"pool {pool_id} still present after delete"


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "InvalidParameterValue"
            and "does not exist" in err.get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
