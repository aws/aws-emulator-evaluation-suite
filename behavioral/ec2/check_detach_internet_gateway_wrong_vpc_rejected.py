"""detach-internet-gateway-wrong-vpc-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "detach-internet-gateway-wrong-vpc-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DetachInternetGateway naming a VPC the gateway is not attached to fails Gateway.NotAttached and
    leaves it attached; a correct detach naming its own VPC succeeds first as the control."""
    ec2 = ctx.client("ec2")

    vpc_a = _create_vpc_with_retry(
        ec2, "10.207.0.0/16", _tag_spec(ctx, "vpc", ctx.unique_name("sim2real-igw-a-"))
    )
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_a))

    # The "wrong VPC" is a second VPC of the check's own that the gateway is never attached to.
    vpc_b = _create_vpc_with_retry(
        ec2, "10.208.0.0/16", _tag_spec(ctx, "vpc", ctx.unique_name("sim2real-igw-b-"))
    )
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_b))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=_tag_spec(ctx, "internet-gateway", ctx.unique_name("sim2real-igw-x-"))
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    ctx.on_cleanup(lambda: _detach(ec2, igw_id, vpc_a))

    _attach_internet_gateway_with_retry(ec2, igw_id, vpc_a)
    _poll_until(
        lambda: ec2.describe_internet_gateways(InternetGatewayIds=[igw_id])["InternetGateways"][
            0
        ]["Attachments"],
        lambda atts: bool(atts) and atts[0]["State"] == "available",
        timeout_s=30.0,
    )

    # Positive control: a detach naming the VPC the gateway IS attached to must actually
    # succeed. Without this, the mismatched-VPC rejection below would be indistinguishable
    # from a target that rejects every DetachInternetGateway call.
    ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_a)
    attachments = _poll_until(
        lambda: ec2.describe_internet_gateways(InternetGatewayIds=[igw_id])["InternetGateways"][
            0
        ]["Attachments"],
        lambda atts: atts == [],
        timeout_s=30.0,
    )
    assert attachments == [], f"expected no attachments after correct detach, got {attachments!r}"

    # Re-attach so the mismatched-VPC negative below has something to test against.
    _attach_internet_gateway_with_retry(ec2, igw_id, vpc_a)
    _poll_until(
        lambda: ec2.describe_internet_gateways(InternetGatewayIds=[igw_id])["InternetGateways"][
            0
        ]["Attachments"],
        lambda atts: bool(atts) and atts[0]["State"] == "available",
        timeout_s=30.0,
    )

    code, message = _error(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_b)
    )
    assert code == "Gateway.NotAttached", code
    assert message == f"resource {igw_id} is not attached to network {vpc_b}", (
        f"unexpected Gateway.NotAttached message: {message!r}"
    )

    # gateway must still be attached to vpc_a since the mismatched detach was rejected
    attachments = ec2.describe_internet_gateways(InternetGatewayIds=[igw_id])[
        "InternetGateways"
    ][0]["Attachments"]
    assert attachments and attachments[0]["VpcId"] == vpc_a, (
        f"expected gateway still attached to {vpc_a} after rejected mismatched detach, "
        f"got {attachments!r}"
    )


# ===== helpers =====
def _detach(ec2, igw_id, vpc_id):
    """Teardown: detach the gateway from `vpc_id`; a gateway a failed run left detached
    (Gateway.NotAttached) is fine, anything else raises."""
    try:
        ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "Gateway.NotAttached":
            raise


def _attach_internet_gateway_with_retry(ec2, igw_id, vpc_id, attempts=5, interval_s=3.0):
    """attach_internet_gateway, tolerating the brief window where a just-created VPC id
    has not yet propagated to every EC2 API code path (InvalidVpcID.NotFound)."""
    last_exc = None
    for _ in range(attempts):
        try:
            ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _create_vpc_with_retry(ec2, cidr_block, tag_specs, attempts=4):
    """create_vpc, retrying with a short backoff while the account is at its VPC limit."""
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


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must not read as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
