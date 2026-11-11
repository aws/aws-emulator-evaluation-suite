"""create-vpc-link-empty-target-list-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-vpc-link-empty-target-list-rejected"
GROUP = "negative-classes"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcLink with an empty targetArns list fails as missing the required target and creates no
    VpcLink, while the same call with one well-formed target ARN creates a PENDING link that settles in
    FAILED."""
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bad_name = ctx.unique_name("sim2real-behav-vpclink-bad-")
    code, message = _error(
        lambda: apigw.create_vpc_link(
            name=bad_name,
            targetArns=[],
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Need at least one target arn to create a vpc link", (
        f"unexpected BadRequestException message {message!r}"
    )

    # effect-absent: no VpcLink with that name was created.
    links = apigw.get_vpc_links(limit=500).get("items", [])
    assert not any(v.get("name") == bad_name for v in links), "a VpcLink was created with an empty target list"

    # positive control: the identical call shape with one (syntactically well-formed, same-account)
    # target ARN present succeeds (the NLB need not exist -- CreateVpcLink returns 202 and
    # validates the target asynchronously, settling the link in FAILED).
    good_name = ctx.unique_name("sim2real-behav-vpclink-ok-")
    target_arn = (
        f"arn:aws:elasticloadbalancing:{ctx.region}:{account_id}:"
        "loadbalancer/net/sim2real-dummy-nlb/50dc6c495c0c9188"
    )
    created = apigw.create_vpc_link(
        name=good_name,
        targetArns=[target_arn],
        tags={"sim2real": CHECK},
    )
    vpc_link_id = created["id"]

    def _cleanup_vpc_link():
        try:
            apigw.delete_vpc_link(vpcLinkId=vpc_link_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_vpc_link)

    assert created["name"] == good_name
    assert created["targetArns"] == [target_arn]
    assert created["status"] == "PENDING", f"expected a fresh VpcLink to start PENDING, got {created['status']}"

    fetched = _poll_vpc_link_terminal(apigw, vpc_link_id)
    assert fetched["name"] == good_name
    assert fetched["targetArns"] == [target_arn]
    assert fetched["status"] == "FAILED", f"expected the link to a nonexistent NLB to settle FAILED, got {fetched}"
    assert fetched.get("statusMessage") == "NLB ARN not found", (
        f"unexpected statusMessage {fetched.get('statusMessage')!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_vpc_link_terminal(apigw, vpc_link_id, timeout_s=600.0):
    deadline = time.monotonic() + timeout_s
    while True:
        link = apigw.get_vpc_link(vpcLinkId=vpc_link_id)
        if link["status"] in ("AVAILABLE", "FAILED"):
            return link
        if time.monotonic() >= deadline:
            raise AssertionError(f"VpcLink {vpc_link_id} not terminal after {timeout_s}s: {link['status']}")
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
