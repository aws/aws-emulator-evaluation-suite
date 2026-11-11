"""placement-group-and-public-ipv4-pool."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error_code(fn):
    """Call *fn*; return the AWS error (code, message). Raise if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")

CHECK = "placement-group-and-public-ipv4-pool"
GROUP = 'vpc-networking'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePlacementGroup duplicate detection (with independent reads and a restore leg)
    plus CreatePublicIpv4Pool's full create/read/delete/re-delete lifecycle."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("pg-")

    def _create_group():
        return ec2.create_placement_group(
            GroupName=name,
            Strategy="cluster",
            TagSpecifications=[{"ResourceType": "placement-group", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
        )

    resp = _create_group()
    ctx.on_cleanup(lambda: ec2.delete_placement_group(GroupName=name))
    pg = resp["PlacementGroup"]
    assert pg["Strategy"] == "cluster", f"expected cluster, got {pg['Strategy']}"
    assert pg["State"] in ("pending", "available"), f"unexpected state {pg['State']}"

    described = ec2.describe_placement_groups(GroupNames=[name])["PlacementGroups"]
    assert len(described) == 1, f"expected exactly one placement group named {name}, got {described}"
    assert described[0]["State"] in ("pending", "available"), (
        f"unexpected independently-read state {described[0]['State']}"
    )

    dup, dup_message = _error_code(lambda: ec2.create_placement_group(GroupName=name, Strategy="cluster"))
    assert dup == "InvalidPlacementGroup.Duplicate", (
        f"expected InvalidPlacementGroup.Duplicate, got {dup}"
    )
    assert dup_message == f"The placement group '{name}' already exists.", dup_message

    described = ec2.describe_placement_groups(GroupNames=[name])["PlacementGroups"]
    assert len(described) == 1, (
        f"the rejected duplicate create must not have created a second group, got {described}"
    )

    ec2.delete_placement_group(GroupName=name)
    gone, gone_message = _error_code(lambda: ec2.describe_placement_groups(GroupNames=[name]))
    assert gone == "InvalidPlacementGroup.Unknown", (
        f"expected InvalidPlacementGroup.Unknown after delete, got {gone}"
    )
    assert gone_message == f"The Placement Group '{name}' is unknown.", gone_message

    restored = _create_group()
    pg2 = restored["PlacementGroup"]
    assert pg2["Strategy"] == "cluster", f"expected cluster on restore, got {pg2['Strategy']}"
    assert pg2["State"] in ("pending", "available"), f"unexpected state on restore {pg2['State']}"

    pool = ec2.create_public_ipv4_pool(
        TagSpecifications=[{"ResourceType": "ipv4pool-ec2", "Tags": [{"Key": "sim2real", "Value": "1"}]}]
    )
    pool_id = pool["PoolId"]

    def _cleanup_pool():
        try:
            ec2.delete_public_ipv4_pool(PoolId=pool_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidPublicIpv4Pool.NotFound":
                raise

    ctx.on_cleanup(_cleanup_pool)
    assert pool_id.startswith("ipv4pool-ec2-"), f"unexpected pool id {pool_id}"

    described_pool = ec2.describe_public_ipv4_pools(PoolIds=[pool_id])["PublicIpv4Pools"]
    assert len(described_pool) == 1 and described_pool[0]["PoolId"] == pool_id, (
        f"expected pool {pool_id} to be independently visible, got {described_pool}"
    )

    ec2.delete_public_ipv4_pool(PoolId=pool_id)
    pool_gone_code, _ = _error_code(lambda: ec2.describe_public_ipv4_pools(PoolIds=[pool_id]))
    assert pool_gone_code is not None, "expected describe_public_ipv4_pools on a deleted pool to fail"

    dead_delete_code, _ = _error_code(lambda: ec2.delete_public_ipv4_pool(PoolId=pool_id))
    assert dead_delete_code is not None, "expected delete on an already-deleted pool to fail"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
