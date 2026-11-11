"""create-vpc-link-invalid-target-badrequest."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "create-vpc-link-invalid-target-badrequest"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpcLink with a malformed target ARN is rejected with BadRequestException and creates
    nothing, while a well-formed but nonexistent NLB ARN is accepted and settles FAILED: the
    rejection is a format check on the ARN, not an existence check on the target."""
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")

    bad_name = ctx.unique_name("sim2real-bhv-vpclink-bad-")
    code, message = _error(lambda: apigw.create_vpc_link(name=bad_name, targetArns=["not-a-valid-nlb-arn"]))
    assert code == "BadRequestException", f"expected BadRequestException for invalid target ARN, got {code!r}"
    assert message == "Invalid ARN. ARN is not well formed not-a-valid-nlb-arn", (
        f"unexpected BadRequestException message {message!r}"
    )

    # effect-absent: an independent read shows no VpcLink was created under that name.
    links = _list_vpc_links(apigw)
    assert not any(v["name"] == bad_name for v in links), "a VpcLink was created despite the malformed target ARN"

    # positive control: the identical call shape with a well-formed (if nonexistent) NLB ARN is
    # accepted synchronously -- CreateVpcLink validates ARN shape up front, and target existence
    # only asynchronously, where the link settles FAILED.
    account_id = sts.get_caller_identity()["Account"]
    well_formed_arn = (
        f"arn:aws:elasticloadbalancing:{ctx.region}:{account_id}:"
        "loadbalancer/net/sim2real-nonexistent-nlb/0123456789abcdef"
    )
    good_name = ctx.unique_name("sim2real-bhv-vpclink-ok-")
    created = apigw.create_vpc_link(
        name=good_name, targetArns=[well_formed_arn], tags={"sim2real": CHECK}
    )
    vpc_link_id = created["id"]
    ctx.on_cleanup(lambda: _delete_vpc_link_with_retry(apigw, vpc_link_id))
    assert created["status"] == "PENDING", (
        f"expected well-formed-but-nonexistent target to be accepted as PENDING, got {created['status']!r}"
    )

    fetched = _poll_vpc_link_terminal(apigw, vpc_link_id)
    assert fetched["name"] == good_name, f"expected VpcLink name {good_name!r}, got {fetched['name']!r}"
    assert fetched["status"] == "FAILED", (
        f"expected the link to a nonexistent NLB to settle FAILED, got {fetched['status']!r}"
    )
    assert fetched.get("statusMessage") == "NLB ARN not found", (
        f"unexpected statusMessage {fetched.get('statusMessage')!r}"
    )


# ===== helpers =====
def _error(fn: Any) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS accepted the call instead of rejecting it: {result!r}")


def _poll_vpc_link_terminal(apigw, vpc_link_id: str, timeout_s: float = 600.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        link = apigw.get_vpc_link(vpcLinkId=vpc_link_id)
        if link["status"] in ("AVAILABLE", "FAILED"):
            return link
        if time.monotonic() >= deadline:
            raise AssertionError(f"VpcLink {vpc_link_id} not terminal after {timeout_s}s: {link['status']}")
        time.sleep(5)


def _list_vpc_links(apigw) -> list[dict]:
    items: list[dict] = []
    kwargs: dict[str, Any] = {}
    while True:
        resp = apigw.get_vpc_links(**kwargs)
        items.extend(resp.get("items", []))
        position = resp.get("position")
        if not position:
            break
        kwargs["position"] = position
    return items


def _delete_vpc_link_with_retry(apigw, vpc_link_id: str, timeout_s: float = 120.0) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            apigw.delete_vpc_link(vpcLinkId=vpc_link_id)
            return
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            # A link still settling (PENDING/DELETING) or a throttled call is retried; the rest raise.
            busy = ("BadRequestException", "ConflictException", "TooManyRequestsException")
            if code not in busy or time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
