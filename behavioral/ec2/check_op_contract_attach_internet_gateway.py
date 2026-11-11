"""op-contract-attachInternetGateway."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-attachInternetGateway"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An internet gateway attaches to one VPC and a VPC takes one internet gateway: both second
    attaches are refused with exact messages and change nothing; a deleted gateway reads not-found.
    """
    ec2 = ctx.client("ec2")

    igw_tags = [{"ResourceType": "internet-gateway", "Tags": [{"Key": "sim2real", "Value": "1"}]}]
    vpc_tags = [{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}]

    created = ec2.create_internet_gateway(TagSpecifications=igw_tags)["InternetGateway"]
    igw = created["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw))
    assert created["Tags"] == [{"Key": "sim2real", "Value": "1"}], (
        f"CreateInternetGateway must echo its TagSpecifications tags, got {created.get('Tags')}"
    )
    assert created["Attachments"] == [], f"a new internet gateway has no attachment, got {created}"

    # vpc1 and vpc2 must both be fresh VPCs with no IGW already attached, since the success path
    # below attaches a brand-new IGW to vpc1 first and later, in the restore leg, to vpc2 -- a VPC
    # that already has one attached would reject the attach with InvalidParameterValue for a
    # reason unrelated to what this check is testing.
    vpc1 = _create_vpc_retrying(ec2, "10.201.0.0/16", tags=vpc_tags)
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc1))
    vpc2 = _create_vpc_retrying(ec2, "10.202.0.0/16", tags=vpc_tags)
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc2))

    def _detach(vpc_id):
        try:
            ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "Gateway.NotAttached",
                "InvalidInternetGatewayID.NotFound",
            ):
                raise

    ctx.on_cleanup(lambda: _detach(vpc1))
    ctx.on_cleanup(lambda: _detach(vpc2))

    def _attachments(gateway_id):
        return ec2.describe_internet_gateways(InternetGatewayIds=[gateway_id])["InternetGateways"][0][
            "Attachments"
        ]

    # success path (positive control): attach to vpc1
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc1)

    attachments = _poll_until(
        lambda: _attachments(igw),
        lambda a: bool(a) and a[0]["State"] == "available",
        timeout_s=30,
        interval_s=2,
    )
    assert attachments[0]["VpcId"] == vpc1, f"expected attachment to {vpc1}, got {attachments}"
    assert attachments[0]["State"] == "available", f"expected available, got {attachments}"
    assert attachments == [{"State": "available", "VpcId": vpc1}], (
        f"the gateway must list exactly one available attachment to {vpc1}, got {attachments}"
    )

    # break: a VPC takes only one internet gateway
    second = ec2.create_internet_gateway(TagSpecifications=igw_tags)["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _delete_igw(ec2, second))
    got = _error(lambda: ec2.attach_internet_gateway(InternetGatewayId=second, VpcId=vpc1))
    want = ("InvalidParameterValue", f"Network {vpc1} already has an internet gateway attached")
    assert got == want, f"attaching a second gateway to {vpc1} answered {got}, expected {want}"
    assert _attachments(second) == [], (
        f"the refused gateway {second} must stay unattached, got {_attachments(second)}"
    )

    # break: an IGW can only be attached to one VPC at a time
    code, message = _error(lambda: ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc2))
    assert code == "Resource.AlreadyAssociated", f"expected Resource.AlreadyAssociated, got {code}"
    expected_message = f"resource {igw} is already attached to network {vpc1}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect-absent: the rejected re-attach must not have changed the attachment set
    post_reject = _attachments(igw)
    assert post_reject == [{"State": "available", "VpcId": vpc1}], (
        f"expected attachment unchanged at {vpc1} after the rejected re-attach, got {post_reject}"
    )

    # restore: detach from vpc1, then the identical call (attach to vpc2) must now succeed
    ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc1)
    _poll_until(
        lambda: _attachments(igw),
        lambda a: not a,
        timeout_s=30,
        interval_s=2,
    )
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc2)
    attachments2 = _poll_until(
        lambda: _attachments(igw),
        lambda a: bool(a) and a[0]["State"] == "available",
        timeout_s=30,
        interval_s=2,
    )
    assert attachments2[0]["VpcId"] == vpc2, f"expected attachment moved to {vpc2}, got {attachments2}"
    assert attachments2 == [{"State": "available", "VpcId": vpc2}], (
        f"the gateway must list exactly one available attachment to {vpc2}, got {attachments2}"
    )

    # a deleted gateway is gone by id
    ec2.delete_internet_gateway(InternetGatewayId=second)
    got = _error(lambda: ec2.describe_internet_gateways(InternetGatewayIds=[second]))
    want = ("InvalidInternetGatewayID.NotFound", f"The internetGateway ID '{second}' does not exist")
    assert got == want, f"describing the deleted gateway answered {got}, expected {want}"


def _create_vpc_retrying(
    ec2, cidr: str, *, tags: list | None = None, timeout_s: float = 300.0, interval_s: float = 10.0
) -> str:
    """create_vpc can transiently fail with VpcLimitExceeded when sibling checks running
    concurrently in the same account/region are holding their own scratch VPCs; retry with
    backoff so this check succeeds once they finish and their own cleanup releases quota,
    instead of treating a shared-account capacity blip as a hard failure."""
    deadline = time.monotonic() + timeout_s
    kwargs = {"CidrBlock": cidr}
    if tags:
        kwargs["TagSpecifications"] = tags
    while True:
        try:
            return ec2.create_vpc(**kwargs)["Vpc"]["VpcId"]
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its (code, message). An unexpected success raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _delete_igw(ec2, gateway_id: str) -> None:
    """Delete the gateway; only its own not-found code means it is already gone."""
    try:
        ec2.delete_internet_gateway(InternetGatewayId=gateway_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInternetGatewayID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
