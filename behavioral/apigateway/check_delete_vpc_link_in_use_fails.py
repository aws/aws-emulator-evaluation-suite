"""delete-vpc-link-in-use-fails."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "delete-vpc-link-in-use-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteVpcLink on an AVAILABLE link an integration references fails with BadRequestException
    and leaves the link intact; once the integration is removed the same delete succeeds.

    Reference: https://docs.aws.amazon.com/apigateway/latest/api/API_DeleteVpcLink.html"""
    apigw = ctx.client("apigateway")
    elbv2 = ctx.client("elbv2")

    subnet_ids = _subnets_for_nlb(ctx)

    nlb_name = (ctx.unique_name("sim2real-nlb-").rstrip("-"))[:32]
    nlb_arn = elbv2.create_load_balancer(
        Name=nlb_name,
        Subnets=subnet_ids,
        Scheme="internal",
        Type="network",
        Tags=[{"Key": "Name", "Value": nlb_name}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=nlb_arn))
    _wait_for_nlb_active(ctx, nlb_arn)

    # A VpcLink's target NLB is marked FAILED (never reaches AVAILABLE) unless the NLB has
    # at least one listener -- targets need not be healthy, but the listener must exist.
    target_group_arn = elbv2.create_target_group(
        Name=(nlb_name[:29].rstrip("-") + "-tg"),
        Protocol="TCP",
        Port=80,
        VpcId=elbv2.describe_load_balancers(LoadBalancerArns=[nlb_arn])["LoadBalancers"][0]["VpcId"],
        TargetType="ip",
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=target_group_arn))
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=nlb_arn,
        Protocol="TCP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": target_group_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))

    vpc_link_id = apigw.create_vpc_link(
        name=ctx.unique_name("sim2real-vpclink-"), targetArns=[nlb_arn]
    )["id"]
    ctx.on_cleanup(lambda: _safe_delete_vpc_link(apigw, vpc_link_id))

    # A still-PENDING link is refused with the same code even when unreferenced, so wait for
    # AVAILABLE before the negative to attribute the refusal to the integration reference.
    status = _wait_terminal_vpc_link(ctx, apigw, vpc_link_id, timeout_s=420.0, interval_s=15.0)
    if status != "AVAILABLE":
        raise AssertionError(
            f"VPC link never reached AVAILABLE (status={status!r})"
        )

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-api-"))["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="HTTP",
        integrationHttpMethod="GET",
        uri="http://example.com/",
        connectionType="VPC_LINK",
        connectionId=vpc_link_id,
    )

    code, message = _client_error(lambda: apigw.delete_vpc_link(vpcLinkId=vpc_link_id))
    assert code == "BadRequestException", (
        f"expected BadRequestException deleting an AVAILABLE VPC link in active use, "
        f"got {code!r}"
    )
    assert message == (
        f"Cannot delete vpc link. Vpc link '{vpc_link_id}', is referenced in "
        f"[{api_id}:GET:{root_id}] in format of [RESTApiId:Method:Resource]."
    ), message

    # the link must still be intact (not partially torn down) after the failed delete
    link = apigw.get_vpc_link(vpcLinkId=vpc_link_id)
    assert link["id"] == vpc_link_id

    # Restore: remove the referencing integration, then the identical delete call must now
    # succeed -- proving the rejection above was specifically about the reference, not the
    # link's provisioning state -- and the link must actually disappear.
    apigw.delete_integration(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    apigw.delete_vpc_link(vpcLinkId=vpc_link_id)
    get_code, get_message = _poll_until_gone(apigw, vpc_link_id)
    assert get_code == "NotFoundException", (
        f"expected the deleted vpc link to be gone, GetVpcLink returned {get_code!r}"
    )
    assert get_message == "Invalid Vpc Link identifier specified", get_message

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


def _client_error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_vpc_link(apigw, vpc_link_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        apigw.delete_vpc_link(vpcLinkId=vpc_link_id)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _poll_until_gone(
    apigw, vpc_link_id: str, timeout_s: float = 90.0, interval_s: float = 10.0
) -> tuple[str, str | None]:
    """Poll GetVpcLink until it fails; return that (code, message), or raise on timeout."""
    from botocore.exceptions import ClientError

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


def _wait_terminal_vpc_link(ctx, apigw, vpc_link_id: str, timeout_s: float, interval_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        status = apigw.get_vpc_link(vpcLinkId=vpc_link_id)["status"]
        if status in ("AVAILABLE", "FAILED") or time.monotonic() >= deadline:
            return status
        time.sleep(interval_s)


def _subnets_for_nlb(ctx) -> list[str]:
    """The run's shared network: one subnet per zone, at most three, for the internal NLB."""
    return list(ctx.network().subnet_ids)[:3]


def _wait_for_nlb_active(ctx, lb_arn: str, timeout_s: float = 240.0, interval_s: float = 15.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        state = lb["State"]["Code"]
        if state == "active":
            return
        if state == "failed":
            raise AssertionError(f"NLB provisioning failed: {lb['State']}")
        time.sleep(interval_s)
    raise AssertionError("NLB never reached 'active' state within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
