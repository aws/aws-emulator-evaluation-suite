"""op-contract-reject-vpc-peering-connection."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-reject-vpc-peering-connection"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DryRun on a pending-acceptance same-account peering connection returns DryRunOperation;
    RejectVpcPeeringConnection then returns true and the connection settles to rejected."""
    ec2 = ctx.client("ec2")

    # The VPC quota is low per region: reclaim VPCs left behind by an interrupted earlier run
    # of this check (found by tag) so they cannot cause VpcLimitExceeded below.
    _release_stale_vpcs(ec2)

    # Reuse the shared network as one side of the peering; create a VPC only when it is absent.
    vpc_a = _default_vpc(ec2, ctx=ctx)
    if vpc_a is None:
        vpc_a = _create_vpc_with_retry(
            ec2,
            cidr_block="10.190.0.0/24",
            tag_specifications=[
                {
                    "ResourceType": "vpc",
                    "Tags": [{"Key": "sim2real-check", "Value": CHECK}, {"Key": "Name", "Value": ctx.unique_name("sim2real-pcx-vpc-a-")}],
                }
            ],
            timeout_s=650,
            interval_s=20,
        )
        ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_a))
        ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_a], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    vpc_a_cidr = ec2.describe_vpcs(VpcIds=[vpc_a])["Vpcs"][0]["CidrBlock"]

    # The VPC quota (default 5/region) can stay saturated, so retrying CreateVpc may never
    # converge. Any available VPC with a non-overlapping CIDR can serve as the peer, and peering
    # has no side effect on its resources; create one only when none exists.
    reused_vpc_b = _reusable_peer_vpc(ec2, vpc_a_cidr, exclude_vpc_id=vpc_a)
    if reused_vpc_b is not None:
        vpc_b = reused_vpc_b
    else:
        # VpcLimitExceeded contention can outlast a 240 s retry window; the later waits are short.
        vpc_b = _create_vpc_with_retry(
            ec2,
            cidr_block="10.191.0.0/24",
            tag_specifications=[
                {
                    "ResourceType": "vpc",
                    "Tags": [{"Key": "sim2real-check", "Value": CHECK}, {"Key": "Name", "Value": ctx.unique_name("sim2real-pcx-vpc-b-")}],
                }
            ],
            timeout_s=650,
            interval_s=20,
        )
        ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_b))
        ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_b], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    pcx_id = ec2.create_vpc_peering_connection(VpcId=vpc_a, PeerVpcId=vpc_b)[
        "VpcPeeringConnection"
    ]["VpcPeeringConnectionId"]
    ctx.on_cleanup(lambda: _delete_pcx(ec2, pcx_id))

    _poll_until(
        lambda: ec2.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx_id])[
            "VpcPeeringConnections"
        ][0]["Status"]["Code"],
        lambda s: s == "pending-acceptance",
        timeout_s=60,
        interval_s=3,
    )

    code, message = _error(
        lambda: ec2.reject_vpc_peering_connection(DryRun=True, VpcPeeringConnectionId=pcx_id)
    )
    assert (code, message) == ("DryRunOperation", _DRY_RUN_MESSAGE), (
        f"expected DryRunOperation {_DRY_RUN_MESSAGE!r}, got {code!r} {message!r}"
    )

    resp = ec2.reject_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)
    assert resp["Return"] is True, f"expected Return=True, got {resp['Return']!r}"

    final_state = _poll_until(
        lambda: ec2.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx_id])[
            "VpcPeeringConnections"
        ][0]["Status"]["Code"],
        lambda s: s == "rejected",
        timeout_s=60,
        interval_s=3,
    )
    assert final_state == "rejected", f"expected rejected, got {final_state!r}"


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _create_vpc_with_retry(ec2, *, cidr_block, tag_specifications, timeout_s=650.0, interval_s=20.0):
    """Create a VPC, retrying VpcLimitExceeded until the deadline.

    The VPC quota is small and shared, so the limit is often transient contention."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(CidrBlock=cidr_block, TagSpecifications=tag_specifications)["Vpc"]["VpcId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "VpcLimitExceeded" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _reusable_peer_vpc(ec2, vpc_a_cidr, *, exclude_vpc_id):
    """Return an available VPC other than exclude_vpc_id whose CIDR does not overlap vpc_a_cidr
    and that is not already peered with it, or None."""
    import ipaddress

    net_a = ipaddress.ip_network(vpc_a_cidr)
    paginator = ec2.get_paginator("describe_vpcs")
    for page in paginator.paginate(Filters=[{"Name": "state", "Values": ["available"]}]):
        for vpc in page["Vpcs"]:
            vpc_id = vpc["VpcId"]
            if vpc_id == exclude_vpc_id:
                continue
            cidr = vpc.get("CidrBlock")
            if not cidr:
                continue
            try:
                net_b = ipaddress.ip_network(cidr)
            except ValueError:
                continue
            if net_a.overlaps(net_b):
                continue
            if _already_peered(ec2, vpc_id, exclude_vpc_id):
                continue
            return vpc_id
    return None


def _already_peered(ec2, vpc_id_a, vpc_id_b):
    active = {"initiating-request", "pending-acceptance", "provisioning", "active"}
    for req, acc in ((vpc_id_a, vpc_id_b), (vpc_id_b, vpc_id_a)):
        pcxs = ec2.describe_vpc_peering_connections(
            Filters=[
                {"Name": "requester-vpc-info.vpc-id", "Values": [req]},
                {"Name": "accepter-vpc-info.vpc-id", "Values": [acc]},
            ]
        )["VpcPeeringConnections"]
        if any(p["Status"]["Code"] in active for p in pcxs):
            return True
    return False


def _delete_pcx(ec2, pcx_id):
    try:
        ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "InvalidVpcPeeringConnectionID.NotFound"
            and not (err["Code"] == "InvalidStateTransition" and "from rejected to deleting" in err.get("Message", ""))
        ):
            raise


def _delete_vpc(ec2, vpc_id):
    try:
        ec2.delete_vpc(VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


def _release_stale_vpcs(ec2):
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:sim2real-check", "Values": [CHECK]}])["Vpcs"]
        for v in vpcs:
            vpc_id = v["VpcId"]
            try:
                pcxs = ec2.describe_vpc_peering_connections(
                    Filters=[{"Name": "requester-vpc-info.vpc-id", "Values": [vpc_id]}]
                )["VpcPeeringConnections"]
                pcxs += ec2.describe_vpc_peering_connections(
                    Filters=[{"Name": "accepter-vpc-info.vpc-id", "Values": [vpc_id]}]
                )["VpcPeeringConnections"]
                for pcx in pcxs:
                    try:
                        ec2.delete_vpc_peering_connection(
                            VpcPeeringConnectionId=pcx["VpcPeeringConnectionId"]
                        )
                    except Exception:
                        pass
                ec2.delete_vpc(VpcId=vpc_id)
            except Exception:
                pass
    except Exception:
        pass


def _default_vpc(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    return vpcs[0]["VpcId"] if vpcs else None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
