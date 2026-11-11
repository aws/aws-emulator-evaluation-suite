"""op-contract-acceptVpcPeeringConnection."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-acceptVpcPeeringConnection"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AcceptVpcPeeringConnection: drives a real pending-acceptance ->
    active transition on a same-account peering connection, then asserts a
    distinct not-found error boundary for a nonexistent connection ID."""
    ec2 = ctx.client("ec2")

    # One side of the peering is the run's network VPC; the check creates
    # only the second VPC, and creates both only when there is none.
    vpc1 = _get_default_vpc_id(ec2, ctx=ctx)
    # A single shared deadline across both potential CreateVpc calls below.
    vpc_create_deadline = time.monotonic() + 700.0
    vpc_tag_spec = lambda name: [
        {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name(name)}]}
    ]
    if vpc1 is None:
        vpc1 = _create_vpc_with_retry(
            ec2, deadline=vpc_create_deadline, CidrBlock="10.221.0.0/16",
            TagSpecifications=vpc_tag_spec("sim2real-pcx-vpc1-"),
        )["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _delete_vpc_and_wait(ec2, vpc1))
    vpc2 = _create_vpc_with_retry(
        ec2, deadline=vpc_create_deadline, CidrBlock="10.222.0.0/16",
        TagSpecifications=vpc_tag_spec("sim2real-pcx-vpc2-"),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc_and_wait(ec2, vpc2))

    pcx_id = ec2.create_vpc_peering_connection(
        VpcId=vpc1,
        PeerVpcId=vpc2,
        TagSpecifications=[
            {
                "ResourceType": "vpc-peering-connection",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-pcx-")}],
            }
        ],
    )["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    ctx.on_cleanup(lambda: _delete_pcx(ec2, pcx_id))

    status = _poll_until(
        lambda: _pcx_status(ec2, pcx_id),
        lambda s: s in ("pending-acceptance", "failed"),
        timeout_s=60,
    )
    assert status == "pending-acceptance", f"expected pending-acceptance, got {status!r}"

    accepted = ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)
    accepted_id = accepted["VpcPeeringConnection"]["VpcPeeringConnectionId"]
    assert accepted_id == pcx_id, f"expected accept response to echo {pcx_id!r}, got {accepted_id!r}"

    status2 = _poll_until(
        lambda: _pcx_status(ec2, pcx_id), lambda s: s in ("active", "failed"), timeout_s=60
    )
    assert status2 == "active", f"expected active after accept, got {status2!r}"

    described = ec2.describe_vpc_peering_connections(VpcPeeringConnectionIds=[pcx_id])[
        "VpcPeeringConnections"
    ][0]
    requester_vpc = described["RequesterVpcInfo"]["VpcId"]
    assert requester_vpc == vpc1, f"expected requester VPC {vpc1!r}, got {requester_vpc!r}"
    accepter_vpc = described["AccepterVpcInfo"]["VpcId"]
    assert accepter_vpc == vpc2, f"expected accepter VPC {vpc2!r}, got {accepter_vpc!r}"

    # distinct error boundary: accepting a nonexistent (but well-formed)
    # peering connection ID must be rejected with a NotFound error.
    missing_pcx_id = "pcx-00000000000000000"
    info = _error_info(
        lambda: ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=missing_pcx_id)
    )
    assert info["code"] == "InvalidVpcPeeringConnectionID.NotFound", f"unexpected code {info['code']!r}"
    expected_message = f"The vpcPeeringConnection ID '{missing_pcx_id}' does not exist"
    assert info["message"] == expected_message, (
        f"expected message {expected_message!r}, got {info['message']!r}"
    )


# ===== helpers =====
def _get_default_vpc_id(ec2, *, ctx):
    """Look up the run's shared network, if any. The shared network is a
    permanent, account-level resource that no check (this one or any
    other concurrently-running one) ever creates or tears down, so it is
    safe scaffolding to reuse without racing anyone else's cleanup."""
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    return vpcs[0]["VpcId"] if vpcs else None


def _create_vpc_with_retry(ec2, *, deadline: float, interval_s: float = 15.0, **kwargs):
    """CreateVpc, retrying VpcLimitExceeded until the shared deadline; raises AssertionError when
    it passes."""
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


def _error_info(fn):
    """Call fn(); return its botocore error. An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses is not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {"code": err["Code"], "message": err.get("Message")}
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


def _delete_vpc_and_wait(ec2, vpc_id: str, *, timeout_s: float = 90.0, interval_s: float = 2.0) -> None:
    """Delete the VPC, retrying only DependencyViolation while a just-deleted dependent's ENIs and
    route tables are released, and wait until DescribeVpcs stops returning it; raise anything else."""
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
            raise AssertionError(f"vpc {vpc_id} still describes {timeout_s}s after DeleteVpc")
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
