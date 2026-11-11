"""vpc-peering-connection-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _client_error(fn):
    """Call *fn*; return (code, message) of the ClientError it raises.

    Raises AssertionError when the call succeeds.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _wait_pcx_status(ec2, pcx_id, want, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    status_code = None
    while time.monotonic() < deadline:
        status_code = ec2.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx_id])[
            "VpcPeeringConnections"
        ][0]["Status"]["Code"]
        if status_code == want:
            return status_code
        time.sleep(3)
    raise AssertionError(
        f"{pcx_id} did not reach {want!r} within {timeout_s}s, last status={status_code!r}"
    )


def _pcx(ec2, pcx_id):
    return ec2.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx_id])[
        "VpcPeeringConnections"
    ][0]


def _vpc_info(info):
    """The identity fields of a Requester/AccepterVpcInfo block."""
    keys = ("VpcId", "OwnerId", "Region", "CidrBlock", "CidrBlockSet")
    return {k: info.get(k) for k in keys}


def _wait_vpc_available(ec2, vpc_id, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]
        if state == "available":
            return
        time.sleep(2)
    raise AssertionError(f"{vpc_id} did not reach 'available' within {timeout_s}s, last state={state!r}")

CHECK = "vpc-peering-connection-lifecycle"
GROUP = 'vpc-networking'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A same-account peering moves initiating-request -> pending-acceptance -> active -> deleted with
    exact status messages, and both VpcInfo blocks carry each side's VPC id, owner, region and CIDR.
    """
    ec2 = ctx.client("ec2")
    vpc_a = ec2.create_vpc(CidrBlock="10.106.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_a))
    _wait_vpc_available(ec2, vpc_a)

    vpc_b = ec2.create_vpc(CidrBlock="10.107.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_b))
    _wait_vpc_available(ec2, vpc_b)

    resp = ec2.create_vpc_peering_connection(VpcId=vpc_a, PeerVpcId=vpc_b, TagSpecifications=[{"ResourceType": "vpc-peering-connection", "Tags": [{"Key": "sim2real", "Value": "1"}]}])
    pcx = resp["VpcPeeringConnection"]
    pcx_id = pcx["VpcPeeringConnectionId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx_id))
    want_initiating = {"Code": "initiating-request", "Message": f"Initiating Request to {ctx.account}"}
    assert pcx["Status"] == want_initiating, (
        f"CreateVpcPeeringConnection answered status {pcx['Status']}, expected {want_initiating}"
    )

    _wait_pcx_status(ec2, pcx_id, "pending-acceptance")
    pending = _pcx(ec2, pcx_id)["Status"]
    want_pending = {"Code": "pending-acceptance", "Message": f"Pending Acceptance by {ctx.account}"}
    assert pending == want_pending, f"the pending connection reads {pending}, expected {want_pending}"

    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)
    _wait_pcx_status(ec2, pcx_id, "active")
    active = _pcx(ec2, pcx_id)
    assert active["Status"] == {"Code": "active", "Message": "Active"}, (
        f"the accepted connection reads {active['Status']}"
    )
    for side, vpc_id, cidr in (
        ("RequesterVpcInfo", vpc_a, "10.106.0.0/16"),
        ("AccepterVpcInfo", vpc_b, "10.107.0.0/16"),
    ):
        want = {
            "VpcId": vpc_id, "OwnerId": ctx.account, "Region": ctx.region, "CidrBlock": cidr,
            "CidrBlockSet": [{"CidrBlock": cidr}],
        }
        assert _vpc_info(active[side]) == want, (
            f"{side} of the active connection reads {_vpc_info(active[side])}, expected {want}"
        )

    # Re-accepting an already-active peering connection is idempotent on real AWS: the call
    # succeeds rather than raising InvalidStateTransition.
    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)

    # Independent read: the redundant Accept must not have perturbed the connection's state.
    settled = ec2.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx_id])[
        "VpcPeeringConnections"
    ][0]["Status"]["Code"]
    assert settled == "active", f"expected still active after redundant accept, got {settled!r}"

    ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)
    _wait_pcx_status(ec2, pcx_id, "deleted")
    deleted = _pcx(ec2, pcx_id)["Status"]
    want_deleted = {"Code": "deleted", "Message": f"Deleted by {ctx.account}"}
    assert deleted == want_deleted, f"the deleted connection reads {deleted}, expected {want_deleted}"

    # A mutation on the now-deleted connection must fail, not silently succeed.
    code, message = _client_error(
        lambda: ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)
    )
    expected = (
        "InvalidStateTransition",
        f"Invalid state transition for {pcx_id}, attempted to transition from deleted to provisioning",
    )
    assert (code, message) == expected, (
        f"accepting a deleted peering connection: got {code!r} {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
