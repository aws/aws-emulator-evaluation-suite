"""vpc-peering-authorization-lifecycle."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-peering-authorization-lifecycle"
GROUP = "state"
SERVICES = ["gamelift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcPeeringAuthorization issues an authorization valid for about 24 hours that
    DescribeVpcPeeringAuthorizations lists once; after the delete it is gone and the same pair can be
    authorized again.
    """
    gl = ctx.client("gamelift")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    peer_vpc_id = "vpc-" + uuid.uuid4().hex[:17]

    def _cleanup():
        try:
            gl.delete_vpc_peering_authorization(
                GameLiftAwsAccountId=account_id, PeerVpcId=peer_vpc_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    created = gl.create_vpc_peering_authorization(
        GameLiftAwsAccountId=account_id, PeerVpcId=peer_vpc_id
    )["VpcPeeringAuthorization"]
    assert created["PeerVpcId"] == peer_vpc_id, (
        f"expected PeerVpcId {peer_vpc_id!r}, got {created.get('PeerVpcId')!r}"
    )
    lifetime_s = (created["ExpirationTime"] - created["CreationTime"]).total_seconds()
    assert 23 * 3600 <= lifetime_s <= 25 * 3600, (
        f"expected an authorization lifetime of ~24h (documented), got {lifetime_s}s "
        f"(created={created['CreationTime']!r}, expires={created['ExpirationTime']!r})"
    )

    matches = [
        a
        for a in gl.describe_vpc_peering_authorizations()["VpcPeeringAuthorizations"]
        if a["PeerVpcId"] == peer_vpc_id
    ]
    assert len(matches) == 1, (
        f"expected exactly 1 authorization for {peer_vpc_id!r}, found {len(matches)}: {matches!r}"
    )

    gl.delete_vpc_peering_authorization(
        GameLiftAwsAccountId=account_id, PeerVpcId=peer_vpc_id
    )

    matches_after = [
        a
        for a in gl.describe_vpc_peering_authorizations()["VpcPeeringAuthorizations"]
        if a["PeerVpcId"] == peer_vpc_id
    ]
    assert matches_after == [], (
        f"expected no authorization for {peer_vpc_id!r} after delete, found {matches_after!r}"
    )

    recreated = gl.create_vpc_peering_authorization(
        GameLiftAwsAccountId=account_id, PeerVpcId=peer_vpc_id
    )["VpcPeeringAuthorization"]
    assert recreated["PeerVpcId"] == peer_vpc_id, (
        f"expected the deleted (account, peer VPC) pair to be reusable, but recreating "
        f"it returned PeerVpcId {recreated.get('PeerVpcId')!r}"
    )

    matches_recreated = [
        a
        for a in gl.describe_vpc_peering_authorizations()["VpcPeeringAuthorizations"]
        if a["PeerVpcId"] == peer_vpc_id
    ]
    assert len(matches_recreated) == 1, (
        f"expected the recreated authorization for {peer_vpc_id!r} to be visible, "
        f"found {len(matches_recreated)}: {matches_recreated!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
