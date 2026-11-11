"""op-contract-detach-internet-gateway."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-detach-internet-gateway"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DetachInternetGateway: success detaches an attached IGW from its VPC, clearing the
    Attachments list; a subsequent detach of the now-unattached gateway is rejected with the
    specific Gateway.NotAttached error."""
    ec2 = ctx.client("ec2")

    # A VPC of the check's own: a VPC takes one internet gateway, so the shared network cannot host it.
    vpc_id = ec2.create_vpc(
        CidrBlock="10.206.0.0/16", TagSpecifications=_tag_spec(ctx, "vpc", ctx.unique_name("sim2real-igw-vpc-"))
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=_tag_spec(ctx, "internet-gateway", ctx.unique_name("sim2real-igw-"))
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))

    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    _poll_until(
        lambda: ec2.describe_internet_gateways(InternetGatewayIds=[igw_id])["InternetGateways"][
            0
        ]["Attachments"],
        lambda atts: bool(atts) and atts[0]["State"] == "available",
        timeout_s=30.0,
    )

    ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    attachments = _poll_until(
        lambda: ec2.describe_internet_gateways(InternetGatewayIds=[igw_id])["InternetGateways"][
            0
        ]["Attachments"],
        lambda atts: atts == [],
        timeout_s=30.0,
    )
    assert attachments == [], f"expected no attachments after detach, got {attachments}"

    code, message = _client_error(
        lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    )
    assert code == "Gateway.NotAttached", (
        f"expected Gateway.NotAttached detaching an already-detached IGW, got {code}"
    )
    expected_message = f"resource {igw_id} is not attached to network {vpc_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====
def _tag_spec(ctx, resource_type: str, name: str):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
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


def _client_error(fn):
    """Call fn() and return its error (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected detach to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
