"""op-contract-describe-vpc-peering-connections."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-vpc-peering-connections"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVpcPeeringConnections shows an accepted connection active with its requester and accepter
    VPC IDs; an unknown connection ID fails with InvalidVpcPeeringConnectionID.NotFound and a message
    ending in that ID and "does not exist"."""
    ec2 = ctx.client("ec2")

    vpc1_id = _create_vpc_with_retry(
        ec2, "10.202.0.0/16", _tag_spec(ctx, "vpc", ctx.unique_name("sim2real-pcx-vpc1-"))
    )
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc1_id))

    # Peer with the shared network VPC: a second fresh VPC doubles pressure on the tight
    # per-region VPC quota (VpcLimitExceeded).
    vpc2_id = _get_default_vpc_id(ec2, ctx=ctx)
    if vpc2_id is None:
        vpc2_id = _create_vpc_with_retry(
            ec2, "10.203.0.0/16", _tag_spec(ctx, "vpc", ctx.unique_name("sim2real-pcx-vpc2-"))
        )
        ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc2_id))

    # A new VPC id takes a moment to propagate to other EC2 API code paths.
    for vid in (vpc1_id, vpc2_id):
        _poll_until(
            lambda vid=vid: ec2.describe_vpcs(VpcIds=[vid])["Vpcs"][0]["State"],
            lambda s: s == "available",
            timeout_s=30.0,
        )

    pcx = _create_peering_with_retry(
        ec2,
        vpc1_id,
        vpc2_id,
        _tag_spec(ctx, "vpc-peering-connection", ctx.unique_name("sim2real-pcx-")),
    )
    pcx_id = pcx["VpcPeeringConnectionId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx_id))

    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)

    described = _poll_until(
        lambda: ec2.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx_id])[
            "VpcPeeringConnections"
        ][0],
        lambda c: c["Status"]["Code"] == "active",
        timeout_s=60.0,
    )
    assert described["RequesterVpcInfo"]["VpcId"] == vpc1_id, (
        f"expected requester {vpc1_id!r}, got {described['RequesterVpcInfo']['VpcId']!r}"
    )
    assert described["AccepterVpcInfo"]["VpcId"] == vpc2_id, (
        f"expected accepter {vpc2_id!r}, got {described['AccepterVpcInfo']['VpcId']!r}"
    )

    code, message = _client_error(
        lambda: ec2.describe_vpc_peering_connections(
            VpcPeeringConnectionIds=["pcx-00000000000000000"]
        )
    )
    assert code == "InvalidVpcPeeringConnectionID.NotFound", (
        f"expected InvalidVpcPeeringConnectionID.NotFound, got {code!r}"
    )
    # Only the stable ends of the not-found message are pinned.
    assert message.startswith("The ") and message.endswith(" ID 'pcx-00000000000000000' does not exist"), (
        f"expected the not-found message for pcx-00000000000000000, got {message!r}"
    )


def _create_vpc_with_retry(ec2, cidr_block, tag_specs, attempts=4):
    """Create a VPC, retrying with a short backoff while the account is at its VPC limit.

    Never reaps other VPCs: a same-tag VPC that looks leaked may still be in use."""
    last_exc = None
    for _ in range(attempts):
        try:
            return ec2.create_vpc(CidrBlock=cidr_block, TagSpecifications=tag_specs)["Vpc"]["VpcId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded":
                raise
            last_exc = exc
            time.sleep(5.0)
    raise last_exc


def _get_default_vpc_id(ec2, *, ctx):
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    except ClientError:
        return None
    return vpcs[0]["VpcId"] if vpcs else None


def _tag_spec(ctx, resource_type: str, name: str):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [
                {"Key": "Name", "Value": name},
                {"Key": "sim2real", "Value": "true"},
                {"Key": "sim2real-created", "Value": str(int(time.time()))},
            ],
        }
    ]


def _create_peering_with_retry(ec2, vpc_id, peer_vpc_id, tag_specs, attempts=5, interval_s=3.0):
    """Create the peering, retrying InvalidVpcID.NotFound while a new VPC id propagates."""
    last_exc = None
    for _ in range(attempts):
        try:
            return ec2.create_vpc_peering_connection(
                VpcId=vpc_id, PeerVpcId=peer_vpc_id, TagSpecifications=tag_specs
            )["VpcPeeringConnection"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
