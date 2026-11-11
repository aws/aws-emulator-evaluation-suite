"""op-contract-reject-transit-gateway-vpc-attachment-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-reject-transit-gateway-vpc-attachment-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RejectTransitGatewayVpcAttachment: DryRun short-circuits, an unknown id is NotFound, and a
    same-account attachment (auto-accepted to available) is refused with IncorrectState and keeps
    its state, since only a pendingAcceptance attachment can be rejected."""
    ec2 = ctx.client("ec2")
    fake_attachment_id = "tgw-attach-00000000000000001"

    # --- boundary A: DryRun short-circuits regardless of resource existence ---
    code, message = _error(
        lambda: ec2.reject_transit_gateway_vpc_attachment(
            DryRun=True, TransitGatewayAttachmentId=fake_attachment_id
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {message!r}"

    # --- boundary B: unknown attachment id is a distinct NotFound error ---
    code, message = _error(
        lambda: ec2.reject_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=fake_attachment_id)
    )
    assert code == "InvalidTransitGatewayAttachmentID.NotFound", f"unexpected code: {code!r}"
    expected_not_found = f"Transit Gateway Attachment {fake_attachment_id} was deleted or does not exist."
    assert message == expected_not_found, f"expected message {expected_not_found!r}, got {message!r}"
    assert code != "DryRunOperation", "NotFound boundary must be distinct from the DryRun boundary"

    # --- boundary C: a REAL, healthy, same-account attachment is rejected out of the wrong state ---
    tgw_id = _create_tgw_with_retry(
        ec2, Description=ctx.unique_name("sim2real-behav-tgw-reject-")
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw(ec2, tgw_id))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda state: state == "available",
        timeout_s=150,
    )

    # The check owns its VPC scaffolding; it never borrows the account's default VPC.
    vpc_id = ec2.create_vpc(
        CidrBlock="10.212.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-tgw-reject-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc_and_wait(ec2, vpc_id))
    subnet_cidr = "10.212.1.0/24"
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
    ctx.on_cleanup(lambda: _delete_attachment(ec2, attachment_id))

    # Positive proof the account/credentials/plumbing are healthy for this
    # exact resource family: a same-account attachment auto-accepts to
    # "available" with no Accept call at all.
    state = _poll_until(
        lambda: _attachment_state(ec2, attachment_id),
        lambda state: state in ("available", "failed"),
        timeout_s=240,
    )
    assert state == "available", f"expected the same-account attachment to auto-become available, got {state!r}"

    code, message = _error(
        lambda: ec2.reject_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attachment_id)
    )
    assert code == "IncorrectState", f"expected IncorrectState, got {code!r}"
    expected_state = f"{attachment_id} is in invalid state"
    assert message == expected_state, f"expected message {expected_state!r}, got {message!r}"
    assert code not in ("DryRunOperation", "InvalidTransitGatewayAttachmentID.NotFound"), (
        "the wrong-state boundary must be distinct from the DryRun and NotFound boundaries"
    )

    # Effect absent: the refused Reject call did not move the attachment's state.
    still_available = _attachment_state(ec2, attachment_id)
    assert still_available == "available", (
        f"the rejected RejectTransitGatewayVpcAttachment call still changed the state to "
        f"{still_available!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the
    strongest signal available and must not be turned into a code
    mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_tgw_with_retry(ec2, *, timeout_s: float = 90.0, interval_s: float = 10.0, **kwargs):
    """CreateTransitGateway can transiently report TransitGatewayLimitExceeded
    while other concurrently-running checks in the same account hold transit
    gateways against the account-wide quota; poll within a bounded window
    instead of treating that as a hard failure."""
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
                    f"TransitGateway quota exhausted for the whole {timeout_s}s retry window: {exc}"
                ) from exc
            time.sleep(interval_s)


def _attachment_state(ec2, attachment_id: str) -> str:
    resp = ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attachment_id])
    items = resp.get("TransitGatewayVpcAttachments", [])
    if not items:
        return "not-found"
    return items[0]["State"]


def _delete_attachment(ec2, attachment_id: str) -> None:
    try:
        ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attachment_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
            raise
    _poll_until(
        lambda: _attachment_state(ec2, attachment_id),
        lambda state: state in ("deleted", "not-found"),
        timeout_s=300,
        interval_s=2,
    )


def _delete_tgw(ec2, tgw_id: str) -> None:
    """Retry IncorrectState (attachments still deleting) to a deadline, then wait for deleted."""
    deadline = time.monotonic() + 120.0
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
        timeout_s=300,
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


def _delete_vpc_and_wait(ec2, vpc_id: str, *, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
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


def _delete_subnet_with_retry(ec2, subnet_id: str, *, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
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
