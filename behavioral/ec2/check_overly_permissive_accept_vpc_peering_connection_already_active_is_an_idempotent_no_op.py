"""overly-permissive-accept-vpc-peering-connection-already-active-is-an-idempotent-no-op."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "overly-permissive-accept-vpc-peering-connection-already-active-is-an-idempotent-no-op"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second AcceptVpcPeeringConnection on an already-active connection succeeds rather than
    raising IncorrectState: it echoes the same connection, still active, and a later read agrees."""
    ec2 = ctx.client("ec2")

    # Reuse the default VPC as one end when there is one: the per-account VPC quota is scarce.
    vpc1 = _get_default_vpc_id(ec2, ctx=ctx)
    vpc_create_deadline = time.monotonic() + 700.0
    _vpc_tags = [{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}]
    if vpc1 is None:
        vpc1 = _create_vpc_with_retry(
            ec2, deadline=vpc_create_deadline, CidrBlock="10.231.0.0/16", TagSpecifications=_vpc_tags
        )["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _delete_vpc_and_wait(ec2, vpc1))
    vpc2 = _create_vpc_with_retry(
        ec2, deadline=vpc_create_deadline, CidrBlock="10.232.0.0/16", TagSpecifications=_vpc_tags
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc_and_wait(ec2, vpc2))

    pcx_id = ec2.create_vpc_peering_connection(
        VpcId=vpc1,
        PeerVpcId=vpc2,
        TagSpecifications=[
            {"ResourceType": "vpc-peering-connection", "Tags": [{"Key": "sim2real", "Value": "1"}]}
        ],
    )["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    ctx.on_cleanup(lambda: _delete_pcx(ec2, pcx_id))

    status = _poll_until(
        lambda: _pcx_status(ec2, pcx_id),
        lambda s: s in ("pending-acceptance", "failed"),
        timeout_s=60,
    )
    assert status == "pending-acceptance", f"expected pending-acceptance, got {status!r}"

    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)
    status2 = _poll_until(
        lambda: _pcx_status(ec2, pcx_id), lambda s: s in ("active", "failed"), timeout_s=60
    )
    assert status2 == "active", f"expected active after first accept, got {status2!r}"

    again_pcx = ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)[
        "VpcPeeringConnection"
    ]
    assert again_pcx["VpcPeeringConnectionId"] == pcx_id, (
        f"expected the redundant accept to echo {pcx_id!r}, "
        f"got {again_pcx.get('VpcPeeringConnectionId')!r}"
    )
    assert again_pcx["Status"]["Code"] == "active", (
        f"expected the redundant accept's own response to report active, "
        f"got {again_pcx['Status']!r}"
    )

    final_status = _pcx_status(ec2, pcx_id)
    assert final_status == "active", f"expected still active, got {final_status!r}"


# ===== helpers =====
def _get_default_vpc_id(ec2, *, ctx):
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    return vpcs[0]["VpcId"] if vpcs else None


def _create_vpc_with_retry(ec2, *, deadline: float, interval_s: float = 15.0, **kwargs):
    while True:
        try:
            return ec2.create_vpc(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "VpcLimitExceeded":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"VPC quota exhausted for the whole retry window: {exc}"
                ) from exc
            time.sleep(interval_s)


def _pcx_status(ec2, pcx_id: str) -> str:
    resp = ec2.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx_id])
    return resp["VpcPeeringConnections"][0]["Status"]["Code"]


def _delete_pcx(ec2, pcx_id: str) -> None:
    try:
        ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "InvalidVpcPeeringConnectionID.NotFound"
            and not (err["Code"] == "InvalidStateTransition" and "from rejected to deleting" in err.get("Message", ""))
        ):
            raise


def _delete_vpc_and_wait(ec2, vpc_id: str, *, timeout_s: float = 90.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidVpcID.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while True:
        try:
            ec2.describe_vpcs(VpcIds=[vpc_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVpcID.NotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"VPC {vpc_id} still listed {timeout_s}s after DeleteVpc")
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
