"""vpc-link-invalid-target-arn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "vpc-link-invalid-target-arn-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpcLink rejects a malformed targetArns entry with BadRequestException, while a
    well-formed but non-existent NLB ARN is accepted as PENDING, reads back PENDING or FAILED, and
    settles FAILED with statusMessage "NLB ARN not found"."""
    apigw = ctx.client("apigateway")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bad_arn = "not-an-arn-at-all"
    code, message = _expect_rejected(
        lambda: apigw.create_vpc_link(name=ctx.unique_name("sim2real-vpclink-bad-"), targetArns=[bad_arn])
    )
    assert code == "BadRequestException", f"expected BadRequestException for malformed targetArns, got {code}"
    assert message == f"Invalid ARN. ARN is not well formed {bad_arn}", (
        f"unexpected BadRequestException message {message!r}"
    )

    # The malformed request must not have created anything.
    listed_names = {v["name"] for v in apigw.get_vpc_links()["items"]}
    assert not any("sim2real-vpclink-bad-" in n for n in listed_names), "malformed VpcLink create was not fully rejected"

    # Positive control: a well-formed NLB ARN (pointing at a non-existent load balancer) is
    # accepted synchronously -- CreateVpcLink only validates ARN shape up front, not existence.
    # This leaves a real (if inert) VpcLink resource behind for a while on real AWS; it is created
    # there anyway, and the retrying cleanup below reclaims it once the link settles.
    well_formed_arn = (
        f"arn:aws:elasticloadbalancing:{ctx.region}:{account_id}:loadbalancer/net/"
        "sim2real-nonexistent-nlb/0123456789abcdef"
    )
    good = apigw.create_vpc_link(
        name=ctx.unique_name("sim2real-vpclink-good-"),
        targetArns=[well_formed_arn],
        tags={"sim2real": CHECK},
    )
    good_id = good["id"]
    ctx.on_cleanup(lambda: _delete_vpc_link_with_retry(apigw, good_id))
    assert good["status"] == "PENDING", f"expected well-formed-but-nonexistent target to be accepted as PENDING, got {good['status']}"

    # Independent read at the destination -- the create call's own response is not enough on its
    # own: get_vpc_link finds the link straight after the create, PENDING or already FAILED (AWS
    # documents no PENDING duration), then the terminal state is graded.
    pending = apigw.get_vpc_link(vpcLinkId=good_id)
    assert pending["id"] == good_id, f"get_vpc_link returned {pending['id']!r} for {good_id}"
    assert pending["status"] in ("PENDING", "FAILED"), (
        f"expected get_vpc_link to report PENDING or FAILED for {good_id}, got {pending['status']}"
    )
    fetched = _poll_vpc_link_terminal(apigw, good_id)
    assert fetched["status"] == "FAILED", (
        f"expected the link to a nonexistent NLB to settle FAILED for {good_id}, got {fetched['status']}"
    )
    assert fetched.get("statusMessage") == "NLB ARN not found", (
        f"unexpected statusMessage {fetched.get('statusMessage')!r}"
    )


def _expect_rejected(fn):
    """Call fn(); return its (error code, message), or raise if it unexpectedly succeeded."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is not None:
            err = response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_vpc_link_terminal(apigw, vpc_link_id: str, timeout_s: float = 600.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        link = apigw.get_vpc_link(vpcLinkId=vpc_link_id)
        if link["status"] in ("AVAILABLE", "FAILED"):
            return link
        if time.monotonic() >= deadline:
            raise AssertionError(f"VpcLink {vpc_link_id} not terminal after {timeout_s}s: {link['status']}")
        time.sleep(5)


def _delete_vpc_link_with_retry(apigw, vpc_link_id: str, timeout_s: float = 120.0) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            apigw.delete_vpc_link(vpcLinkId=vpc_link_id)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NotFoundException":
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
