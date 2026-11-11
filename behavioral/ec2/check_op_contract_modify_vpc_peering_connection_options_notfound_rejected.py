"""op-contract-modify-vpc-peering-connection-options-notfound-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-vpc-peering-connection-options-notfound-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpcPeeringConnectionOptions enables AllowDnsResolutionFromRemoteVpc on an active
    same-account peering connection; a nonexistent VpcPeeringConnectionId is rejected with
    InvalidVpcPeeringConnectionID.NotFound."""
    ec2 = ctx.client("ec2")

    vpc_a = _get_default_vpc(ec2, ctx=ctx)
    if vpc_a is None:
        vpc_a = _create_vpc_with_retry(ctx, ec2, "10.220.0.0/16", "pcx-a")
        ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_a))
    vpc_b = _create_vpc_with_retry(ctx, ec2, "10.221.0.0/16", "pcx-b")
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_b))

    pcx_id = ec2.create_vpc_peering_connection(
        VpcId=vpc_a, PeerVpcId=vpc_b, TagSpecifications=_tag_spec(ctx, "vpc-peering-connection", "pcx")
    )["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx_id))

    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)
    active = _poll_until(
        lambda: _describe_pcx(ec2, pcx_id),
        lambda p: p is not None and p["Status"]["Code"] == "active",
        timeout_s=90,
        interval_s=5,
    )
    assert active["RequesterVpcInfo"]["VpcId"] == vpc_a, active
    assert active["AccepterVpcInfo"]["VpcId"] == vpc_b, active

    err, err_message = _client_error(
        lambda: ec2.modify_vpc_peering_connection_options(
            VpcPeeringConnectionId="pcx-00000000000000000",
            RequesterPeeringConnectionOptions={"AllowDnsResolutionFromRemoteVpc": True},
        )
    )
    assert err == "InvalidVpcPeeringConnectionID.NotFound", err
    expected_message = "The peering ID 'pcx-00000000000000000' does not exist"
    assert err_message == expected_message, f"expected message {expected_message!r}, got {err_message!r}"

    resp = ec2.modify_vpc_peering_connection_options(
        VpcPeeringConnectionId=pcx_id,
        RequesterPeeringConnectionOptions={"AllowDnsResolutionFromRemoteVpc": True},
    )
    assert resp["RequesterPeeringConnectionOptions"]["AllowDnsResolutionFromRemoteVpc"] is True, resp

    updated = _describe_pcx(ec2, pcx_id)
    assert updated["RequesterVpcInfo"]["PeeringOptions"]["AllowDnsResolutionFromRemoteVpc"] is True, updated


def _tag_spec(ctx, resource_type, prefix):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}]}]


def _create_vpc_with_retry(ctx, ec2, cidr_block, prefix, timeout_s=180.0, interval_s=10.0):
    # The per-region VPC quota is small and shared; a transient VpcLimitExceeded
    # clears as other VPCs are deleted, so retry for a bounded window.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(CidrBlock=cidr_block, TagSpecifications=_tag_spec(ctx, "vpc", prefix))["Vpc"]["VpcId"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last saw {last!r}")


def _describe_pcx(ec2, pcx_id):
    resp = ec2.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx_id])
    items = resp.get("VpcPeeringConnections", [])
    return items[0] if items else None


def _get_default_vpc(ec2, *, ctx):
    # Reusing the shared network for one side of the peering avoids consuming
    # another slot of the small per-region VPC quota.
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    return vpcs[0]["VpcId"] if vpcs else None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
