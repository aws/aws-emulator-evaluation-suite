"""op-contract-modify-transit-gateway-metering-policy."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-transit-gateway-metering-policy"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyTransitGatewayMeteringPolicy adds/removes a middlebox attachment; bad policy id -> NotFound."""
    ec2 = ctx.client("ec2")
    for op in (
        "create_transit_gateway_metering_policy",
        "modify_transit_gateway_metering_policy",
        "delete_transit_gateway_metering_policy",
    ):
        if not hasattr(ec2, op):
            raise AssertionError(f"unreachable: ec2 client lacks {op} (older botocore)")

    name = ctx.unique_name("sim2real-tgwmp-")

    tgw_id = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _retry_in_use(ec2, lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id)))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0],
        lambda t: t["State"] == "available",
        timeout_s=240,
    )

    # A real attachment is needed as a middlebox attachment target for the
    # modify call below (see comment there).
    vpc_id = ec2.create_vpc(
        CidrBlock="10.90.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_in_use(ec2, lambda: ec2.delete_vpc(VpcId=vpc_id)))
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.90.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_in_use(ec2, lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    attach_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id,
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        TagSpecifications=[
            {"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_attachment_and_wait(ec2, attach_id))
    _poll_until(
        lambda: ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attach_id])[
            "TransitGatewayVpcAttachments"
        ][0],
        lambda a: a["State"] == "available",
        timeout_s=180,
    )

    policy = ec2.create_transit_gateway_metering_policy(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-metering-policy", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["TransitGatewayMeteringPolicy"]
    policy_id = policy["TransitGatewayMeteringPolicyId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_metering_policy(TransitGatewayMeteringPolicyId=policy_id))

    def _read_policy():
        return ec2.describe_transit_gateway_metering_policies(TransitGatewayMeteringPolicyIds=[policy_id])[
            "TransitGatewayMeteringPolicies"
        ][0]

    # AWS requires ModifyTransitGatewayMeteringPolicy to specify either
    # AddMiddleboxAttachmentIds or RemoveMiddleboxAttachmentIds; a bare no-op
    # modify (neither parameter) is rejected with MissingParameter.
    resp = ec2.modify_transit_gateway_metering_policy(
        TransitGatewayMeteringPolicyId=policy_id, AddMiddleboxAttachmentIds=[attach_id]
    )
    modified = resp["TransitGatewayMeteringPolicy"]
    assert modified["TransitGatewayMeteringPolicyId"] == policy_id, (
        f"expected policy id {policy_id}, got {modified.get('TransitGatewayMeteringPolicyId')}"
    )
    assert modified["TransitGatewayId"] == tgw_id, (
        f"expected transit gateway id {tgw_id}, got {modified.get('TransitGatewayId')}"
    )

    # The modify call's own response is not enough: confirm the attachment is
    # actually reflected via an independent read (State transitions through
    # "modifying" before the policy settles back to "available").
    after_add = _poll_until(
        _read_policy,
        lambda p: p["State"] == "available" and attach_id in p.get("MiddleboxAttachmentIds", []),
        timeout_s=120,
    )
    assert attach_id in after_add["MiddleboxAttachmentIds"], (
        f"added middlebox attachment not reflected on independent read: {after_add}"
    )

    resp2 = ec2.modify_transit_gateway_metering_policy(
        TransitGatewayMeteringPolicyId=policy_id, RemoveMiddleboxAttachmentIds=[attach_id]
    )
    modified2 = resp2["TransitGatewayMeteringPolicy"]
    assert attach_id not in modified2.get("MiddleboxAttachmentIds", []), (
        f"removed middlebox attachment still present in modify response: {modified2}"
    )

    after_remove = _poll_until(
        _read_policy,
        lambda p: p["State"] == "available" and attach_id not in p.get("MiddleboxAttachmentIds", []),
        timeout_s=120,
    )
    assert attach_id not in after_remove["MiddleboxAttachmentIds"], (
        f"removed middlebox attachment still present on independent read: {after_remove}"
    )

    code, message = _client_error(
        lambda: ec2.modify_transit_gateway_metering_policy(
            TransitGatewayMeteringPolicyId="tgw-mp-00000000000000000",
            AddMiddleboxAttachmentIds=[attach_id],
        )
    )
    assert code == "InvalidTransitGatewayMeteringPolicyId.NotFound", f"unexpected error code: {code}"
    expected_message = "Transit Gateway Metering Policy Id tgw-mp-00000000000000000 was deleted or does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _delete_attachment_and_wait(ec2, attach_id):
    """Delete the VPC attachment and wait for it to clear before returning, so the
    dependent subnet/VPC deletes registered ahead of this one in the LIFO cleanup
    chain don't race the attachment's ENI teardown and fail with DependencyViolation."""
    from botocore.exceptions import ClientError

    try:
        _retry_in_use(ec2, lambda: ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attach_id))
    except ClientError as exc:
        if not exc.response["Error"]["Code"].endswith("NotFound"):
            raise

    def _state():
        try:
            atts = ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attach_id])[
                "TransitGatewayVpcAttachments"
            ]
            return atts[0]["State"] if atts else "deleted"
        except ClientError as exc:
            if exc.response["Error"]["Code"].endswith("NotFound"):
                return "deleted"
            raise

    # Real AWS holds a VPC attachment in 'deleting' for minutes: wait to the cleanup deadline.
    _poll_until(_state, lambda s: s == "deleted", timeout_s=max(_teardown_left(ec2), 1.0), interval_s=2.0)


# budget.cleanup_timeout for behavioral/ec2: one deadline shared by the check's teardowns.
_TEARDOWN_RETRY_S = 900.0
_TEARDOWN_DEADLINES: dict = {}
_IN_USE_CODES = ("IncorrectState", "DependencyViolation", "RequestLimitExceeded")


def _teardown_left(ec2) -> float:
    held = _TEARDOWN_DEADLINES.get(id(ec2))
    if held is None or held[0] is not ec2:
        held = _TEARDOWN_DEADLINES[id(ec2)] = (ec2, time.monotonic() + _TEARDOWN_RETRY_S)
    return held[1] - time.monotonic()


def _retry_in_use(ec2, fn):
    """Retry fn while a dependent is still deleting (IncorrectState / DependencyViolation) or
    throttled, every 2 s to the shared cleanup deadline; raise everything else."""
    from botocore.exceptions import ClientError

    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _IN_USE_CODES or _teardown_left(ec2) <= 0:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
