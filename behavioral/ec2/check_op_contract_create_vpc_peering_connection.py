"""op-contract-createVpcPeeringConnection."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-createVpcPeeringConnection"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcPeeringConnection: success starts a same-account peering in pending-acceptance;
    a nonexistent peer VPC is rejected with InvalidVpcID.NotFound."""
    ec2 = ctx.client("ec2")

    # Peering does not require either side to be freshly created, so reuse the provided network
    # VPC as the requester (no quota cost, nothing to clean up) and create only the accepter VPC.
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        requester_id = default_vpcs[0]["VpcId"]
    else:
        requester_id = _create_vpc(ctx, ec2, "10.220.0.0/16")
        ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=requester_id))
    accepter_id = _create_vpc(ctx, ec2, "10.221.0.0/16")
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=accepter_id))

    resp = ec2.create_vpc_peering_connection(
        VpcId=requester_id,
        PeerVpcId=accepter_id,
        TagSpecifications=[_tag_spec(ctx, "vpc-peering-connection", "pcx")],
    )
    pcx = resp["VpcPeeringConnection"]
    pcx_id = pcx["VpcPeeringConnectionId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx_id))

    assert pcx["RequesterVpcInfo"]["VpcId"] == requester_id, (
        f"expected requester {requester_id}, got {pcx['RequesterVpcInfo']['VpcId']!r}"
    )
    assert pcx["AccepterVpcInfo"]["VpcId"] == accepter_id, (
        f"expected accepter {accepter_id}, got {pcx['AccepterVpcInfo']['VpcId']!r}"
    )

    # CreateVpcPeeringConnection's own response can come back with a transient
    # "initiating-request" status before AWS settles it to "pending-acceptance" -- poll
    # DescribeVpcPeeringConnections briefly rather than asserting against a possibly-transient
    # create response.
    def _status_code():
        pcxs = ec2.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx_id])[
            "VpcPeeringConnections"
        ]
        return pcxs[0]["Status"]["Code"] if pcxs else "unknown"

    # _poll_until raises if "pending-acceptance" is never observed, so reaching here already
    # proves the settled status; no further assertion is needed.
    _poll_until(_status_code, lambda s: s == "pending-acceptance", timeout_s=30, interval_s=2)

    # Error boundary: a nonexistent peer VPC is rejected.
    code, message = _error_of(
        lambda: ec2.create_vpc_peering_connection(
            VpcId=requester_id, PeerVpcId="vpc-00000000000000000"
        )
    )
    assert code == "InvalidVpcID.NotFound", f"expected InvalidVpcID.NotFound, got {code!r}"
    assert message == "The vpc ID 'vpc-00000000000000000' does not exist", message


def _error_of(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _create_vpc(ctx, ec2, cidr_block):
    """Create a VPC, failing loudly if the account has no quota left.

    A quota exhaustion is an environment precondition, not something a check may fix by deleting
    resources it does not own.
    """
    return ec2.create_vpc(
        CidrBlock=cidr_block, TagSpecifications=[_tag_spec(ctx, "vpc", "pcx-vpc")]
    )["Vpc"]["VpcId"]

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
