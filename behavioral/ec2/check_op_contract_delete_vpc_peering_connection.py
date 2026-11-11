"""op-contract-deleteVpcPeeringConnection."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVpcPeeringConnection"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVpcPeeringConnection tears down an active peering connection; a bogus id is rejected NotFound."""
    ec2 = ctx.client("ec2")

    vpc_a = ec2.create_vpc(
        CidrBlock="10.220.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "pcx-a")]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_a)))

    # reuse the run's shared network as the peer side when one exists, to avoid tripping the
    # per-region VPC limit by creating two brand-new VPCs just for this check
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_b = default_vpcs[0]["VpcId"]
    else:
        vpc_b = ec2.create_vpc(
            CidrBlock="10.221.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "pcx-b")]
        )["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_b)))

    created = ec2.create_vpc_peering_connection(
        VpcId=vpc_a,
        PeerVpcId=vpc_b,
        TagSpecifications=[_tag_spec(ctx, "vpc-peering-connection", "pcx")],
    )
    pcx_id = created["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    state = {"deleted": False}

    def _cleanup():
        if not state["deleted"]:
            _safe(lambda: ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx_id))

    ctx.on_cleanup(_cleanup)

    _poll_until(
        lambda: ec2.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx_id])[
            "VpcPeeringConnections"
        ][0]["Status"]["Code"],
        lambda c: c == "pending-acceptance",
        timeout_s=30.0,
    )

    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)
    active = _poll_until(
        lambda: ec2.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx_id])[
            "VpcPeeringConnections"
        ][0],
        lambda c: c["Status"]["Code"] == "active",
        timeout_s=30.0,
    )
    assert active["RequesterVpcInfo"]["VpcId"] == vpc_a, (
        f"expected requester {vpc_a}, got {active['RequesterVpcInfo']['VpcId']}"
    )
    assert active["AccepterVpcInfo"]["VpcId"] == vpc_b, (
        f"expected accepter {vpc_b}, got {active['AccepterVpcInfo']['VpcId']}"
    )

    # success path: delete an active peering connection
    ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)
    state["deleted"] = True
    _poll_until(
        lambda: ec2.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx_id])[
            "VpcPeeringConnections"
        ][0]["Status"]["Code"],
        lambda c: c == "deleted",
        timeout_s=30.0,
    )

    # distinct error boundary: a syntactically valid but nonexistent peering connection id is rejected
    bogus_id = _mutate_id(pcx_id)
    code, message = _error_of(lambda: ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=bogus_id))
    assert code == "InvalidVpcPeeringConnectionID.NotFound", (
        f"expected InvalidVpcPeeringConnectionID.NotFound, got {code!r}"
    )
    assert message == f"The vpcPeeringConnection ID '{bogus_id}' does not exist", message


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _error_of(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        f"expected InvalidVpcPeeringConnectionID.NotFound, but the call SUCCEEDED: {result!r}"
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("InvalidVpcID.NotFound", "InvalidVpcPeeringConnectionID.NotFound")
            and not (err["Code"] == "InvalidStateTransition" and "from rejected to deleting" in err.get("Message", ""))
        ):
            raise


def _mutate_id(real_id: str) -> str:
    return real_id[:-1] + ("0" if real_id[-1] != "0" else "1")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
