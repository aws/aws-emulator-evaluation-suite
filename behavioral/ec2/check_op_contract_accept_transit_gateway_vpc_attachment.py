"""op-contract-acceptTransitGatewayVpcAttachment."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-acceptTransitGatewayVpcAttachment"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcceptTransitGatewayVpcAttachment on a same-account attachment, which AWS auto-accepts to
    'available', is rejected with a distinct state-conflict error rather than silently succeeding."""
    ec2 = ctx.client("ec2")

    tgw_name = ctx.unique_name("sim2real-behav-tgw-")
    tgw_id = _create_transit_gateway_with_retry(
        ec2,
        Description=tgw_name,
        Options={"AutoAcceptSharedAttachments": "disable"},
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": tgw_name}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw(ec2, tgw_id))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0][
            "State"
        ],
        lambda state: state == "available",
        timeout_s=150,
    )

    # A dedicated VPC, created and torn down by this check, scaffolds the attachment's subnet.
    vpc_name = ctx.unique_name("sim2real-behav-tgw-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.211.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc_and_wait(ec2, vpc_id))
    subnet_cidr = "10.211.1.0/24"
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=subnet_cidr, AvailabilityZone=az)[
        "Subnet"
    ]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_subnet_with_retry(ec2, subnet_id))

    attachment_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id, VpcId=vpc_id, SubnetIds=[subnet_id]
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]

    def _delete_attachment() -> None:
        try:
            ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attachment_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
                raise
        _poll_until(
            lambda: _attachment_state(ec2, attachment_id),
            lambda state: state in ("deleted", "not-found"),
            timeout_s=300,
        )

    ctx.on_cleanup(_delete_attachment)

    # success-path contract: same-account attachments require no acceptance
    # step at all -- they transition straight to "available".
    state = _poll_until(
        lambda: _attachment_state(ec2, attachment_id),
        lambda state: state in ("available", "failed"),
        timeout_s=180,
    )
    assert state == "available", f"expected attachment to auto-become available, got {state!r}"

    # distinct error boundary: accepting an attachment that is not in
    # pendingAcceptance state must be rejected, not silently accepted.
    code, message = _error(
        lambda: ec2.accept_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attachment_id)
    )
    assert code == "IncorrectState", f"expected IncorrectState, got {code!r}"
    assert message == f"{attachment_id} is in invalid state", f"unexpected IncorrectState message: {message!r}"

    # effect-absent: the rejected Accept call must not have moved the
    # attachment off "available" -- confirmed via an independent read
    # (DescribeTransitGatewayVpcAttachments), a different operation than
    # the one that was rejected.
    post_state = _attachment_state(ec2, attachment_id)
    assert post_state == "available", (
        f"expected attachment to remain 'available' after the rejected accept, got {post_state!r}"
    )


# ===== helpers =====
def _create_transit_gateway_with_retry(ec2, *, timeout_s: float = 520.0, interval_s: float = 15.0, **kwargs):
    """CreateTransitGateway, retrying TransitGatewayLimitExceeded within a bounded window; raises
    AssertionError when the window runs out."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_transit_gateway(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "TransitGatewayLimitExceeded":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"TransitGateway quota exhausted for the whole {timeout_s}s retry "
                    f"window: {exc}"
                ) from exc
            time.sleep(interval_s)


def _error(fn):
    """Call fn(); return (code, message) of its botocore error. An unexpected SUCCESS
    raises, because accepting a call real AWS rejects is its own failure, not a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded and returned {result!r}")


def _attachment_state(ec2, attachment_id: str) -> str:
    resp = ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attachment_id])
    items = resp.get("TransitGatewayVpcAttachments", [])
    if not items:
        return "not-found"
    return items[0]["State"]


def _delete_tgw(ec2, tgw_id: str) -> None:
    """Delete the transit gateway and wait until it is gone, retrying only IncorrectState while the
    just-deleted attachment's resources are released; raise anything else."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidTransitGatewayID.NotFound":
                return
            if code != "IncorrectState" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    _poll_until(
        lambda: _tgw_state(ec2, tgw_id),
        lambda state: state in ("deleted", "not-found"),
        timeout_s=150,
        interval_s=2,
    )


def _tgw_state(ec2, tgw_id: str) -> str:
    try:
        resp = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidTransitGatewayID.NotFound":
            return "not-found"
        raise
    items = resp.get("TransitGateways", [])
    if not items:
        return "not-found"
    return items[0]["State"]


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


def _delete_subnet_with_retry(
    ec2, subnet_id: str, *, timeout_s: float = 60.0, interval_s: float = 3.0
) -> None:
    """DeleteSubnet can fail with DependencyViolation for a brief window
    right after the transit gateway attachment (whose underlying ENI lives
    in this subnet) reports itself deleted -- the ENI's own removal can lag
    the attachment's "deleted" state by a few seconds. Retry the delete
    itself within a bounded window instead of a single fire-and-forget
    call so that lag doesn't leak the subnet (and, transitively, the VPC
    it's the last dependent of, permanently consuming its quota slot)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_subnet(SubnetId=subnet_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidSubnetID.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 5.0):
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
