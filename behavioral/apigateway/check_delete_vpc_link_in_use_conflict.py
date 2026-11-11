"""delete-vpc-link-in-use-conflict."""
from __future__ import annotations

import time
import uuid
from typing import Any, Callable

from botocore.exceptions import ClientError

CHECK = "delete-vpc-link-in-use-conflict"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVpcLink on a VpcLink still referenced by a live private integration is
    rejected with BadRequestException regardless of the link's own provisioning outcome;
    once the reference is removed, deletion succeeds."""
    apigw = ctx.client("apigateway")

    # CreateVpcLink only format-checks the target ARN synchronously -- the rejection under test
    # (delete blocked by a live Integration reference) does not depend on the link ever reaching
    # AVAILABLE, so a syntactically-valid ARN pointing at no real NLB reaches a terminal state
    # fast, instead of the multi-minute real-NLB convergence a genuine load balancer needs
    # (a real NLB plus VpcLink can take several minutes to converge, longer than this check's 300 s budget).
    target_arn = _fake_nlb_arn(ctx)
    vpclink_name = ctx.unique_name("sim2real-behav-vpclink-")
    vpc_link_id = apigw.create_vpc_link(
        name=vpclink_name, targetArns=[target_arn], tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_vpc_link(vpcLinkId=vpc_link_id)))

    link_state = _poll_until(
        lambda: apigw.get_vpc_link(vpcLinkId=vpc_link_id),
        lambda r: r["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=240.0,
        interval_s=5.0,
    )
    if link_state["status"] not in ("AVAILABLE", "FAILED"):
        raise AssertionError(
            f"vpc link did not leave PENDING within timeout "
            f"(last status={link_state['status']}, message={link_state.get('statusMessage')!r})",
        )

    api_name = ctx.unique_name("sim2real-behav-api-")
    rest_api_id = apigw.create_rest_api(name=api_name, tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_rest_api(restApiId=rest_api_id)))
    root_id = [r for r in apigw.get_resources(restApiId=rest_api_id)["items"] if r["path"] == "/"][0]["id"]

    apigw.put_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=rest_api_id, resourceId=root_id, httpMethod="GET",
        type="HTTP_PROXY", integrationHttpMethod="GET", uri="http://sim2real-behav-backend.example.com/",
        connectionType="VPC_LINK", connectionId=vpc_link_id,
    )

    # Negative: VPC link is now referenced by an active integration -> delete is rejected.
    # AWS returns BadRequestException here, not ConflictException.
    code, message = _client_error(lambda: apigw.delete_vpc_link(vpcLinkId=vpc_link_id))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == (
        f"Cannot delete vpc link. Vpc link '{vpc_link_id}', is referenced in "
        f"[{rest_api_id}:GET:{root_id}] in format of [RESTApiId:Method:Resource]."
    ), message

    # The forbidden effect did not happen: the vpc link still exists and is not gone.
    still_there = apigw.get_vpc_link(vpcLinkId=vpc_link_id)
    assert still_there["id"] == vpc_link_id, f"expected vpc link {vpc_link_id!r} to survive the rejected delete, got {still_there!r}"

    # Positive control: once the referencing integration/API is removed, deletion succeeds.
    apigw.delete_rest_api(restApiId=rest_api_id)
    apigw.delete_vpc_link(vpcLinkId=vpc_link_id)
    final_code, final_message = _poll_until_gone(apigw, vpc_link_id, timeout_s=90.0, interval_s=5.0)
    assert final_code == "NotFoundException", (
        f"expected the deleted vpc link to be gone, GetVpcLink returned {final_code!r}"
    )
    assert final_message == "Invalid Vpc Link identifier specified", final_message

    # A mutation on the now-dead id fails the same specific way, not just a read.
    patch_code, patch_message = _client_error(
        lambda: apigw.update_vpc_link(
            vpcLinkId=vpc_link_id,
            patchOperations=[{"op": "replace", "path": "/name", "value": "x"}],
        )
    )
    assert patch_code == "NotFoundException", (
        f"expected a mutation on the deleted vpc link id to fail, got {patch_code!r}"
    )
    assert patch_message == "Invalid Vpc Link identifier specified", patch_message


def _fake_nlb_arn(ctx) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    suffix = uuid.uuid4().hex[:16]
    return (
        f"arn:aws:elasticloadbalancing:{ctx.region}:{account_id}:"
        f"loadbalancer/net/sim2real-behav-nlb/{suffix}"
    )


def _client_error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_not_found(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _poll_until_gone(apigw: Any, vpc_link_id: str, *, timeout_s: float, interval_s: float) -> tuple[str, str | None]:
    """Poll GetVpcLink until it fails; return that (code, message), or raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            apigw.get_vpc_link(vpcLinkId=vpc_link_id)
        except ClientError as e:
            error = e.response["Error"]
            return error["Code"], error.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"vpc link {vpc_link_id} still readable {timeout_s}s after its delete")
        time.sleep(interval_s)


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
