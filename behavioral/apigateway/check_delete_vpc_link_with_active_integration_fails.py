"""delete-vpc-link-with-active-integration-fails."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-vpc-link-with-active-integration-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a VPC Link still referenced by a PRIVATE (VPC_LINK) integration must
    fail BadRequestException, not orphan the integration's connectionId."""
    apigw = ctx.client("apigateway")

    target_arn = _fake_nlb_arn(ctx)
    vpclink_name = ctx.unique_name("sim2real-vpclink-")
    vpc_link_id = apigw.create_vpc_link(
        name=vpclink_name, targetArns=[target_arn], tags={"Name": vpclink_name}
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_vpc_link(vpcLinkId=vpc_link_id)))

    # Let the (fake-NLB-targeted) link leave PENDING first -- DeleteVpcLink refuses
    # outright while PENDING regardless of references, so a later rejection can only be
    # attributed to the live Integration reference below, not that unrelated state gate.
    _wait_terminal(apigw, vpc_link_id)

    api_name = ctx.unique_name("sim2real-vpclink-api-")
    api_id = apigw.create_rest_api(name=api_name, tags={"Name": api_name})["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="HTTP_PROXY",
        integrationHttpMethod="GET",
        uri="http://internal.example.com/",
        connectionType="VPC_LINK",
        connectionId=vpc_link_id,
    )

    err = _error(lambda: apigw.delete_vpc_link(vpcLinkId=vpc_link_id))
    expected = (
        "BadRequestException",
        f"Cannot delete vpc link. Vpc link '{vpc_link_id}', is referenced in "
        f"[{api_id}:GET:{root_id}] in format of [RESTApiId:Method:Resource].",
    )
    assert err == expected, (
        f"expected {expected!r} deleting a VPC link referenced by an active integration, got {err!r}"
    )

    # the link must still exist and be usable since the delete was rejected
    still = apigw.get_vpc_link(vpcLinkId=vpc_link_id)
    assert still["id"] == vpc_link_id, (
        f"expected the VPC link to remain intact after the rejected delete, got {still!r}"
    )

    # Positive control: once the referencing integration is removed, the identical
    # delete call succeeds -- proving the rejection above is specific to the active
    # reference, not a blanket refusal to delete any VpcLink.
    apigw.delete_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    apigw.delete_vpc_link(vpcLinkId=vpc_link_id)
    _poll_until(
        lambda: _vpc_link_present(apigw, vpc_link_id),
        lambda present: not present,
        timeout_s=180,
        interval_s=5,
    )
    err = _error(lambda: apigw.get_vpc_link(vpcLinkId=vpc_link_id))
    gone = ("NotFoundException", "Invalid Vpc Link identifier specified")
    assert err == gone, f"expected {gone!r} reading the deleted VPC link, got {err!r}"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _fake_nlb_arn(ctx) -> str:
    """A syntactically-valid NLB ARN that references no real NLB (CreateVpcLink only
    format-checks the ARN synchronously, so the VpcLink provisions -- and fails fast,
    since the target never becomes reachable -- without needing a real NLB at all)."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    suffix = uuid.uuid4().hex[:16]
    return (
        f"arn:aws:elasticloadbalancing:{ctx.region}:{account_id}:"
        f"loadbalancer/net/sim2real-vpclink-nlb/{suffix}"
    )


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _vpc_link_present(apigw, vpc_link_id) -> bool:
    """True while GetVpcLink still returns the link; False once it is NotFoundException."""
    try:
        apigw.get_vpc_link(vpcLinkId=vpc_link_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
        return False
    return True


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_terminal(apigw, vpc_link_id, timeout_s: float = 60.0):
    """Poll until the VpcLink leaves PENDING (AVAILABLE or FAILED); raises if it doesn't
    within the window. A fake target ARN normally reaches FAILED within seconds."""
    return _poll_until(
        lambda: apigw.get_vpc_link(vpcLinkId=vpc_link_id)["status"],
        lambda status: status != "PENDING",
        timeout_s=timeout_s,
        interval_s=3,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
