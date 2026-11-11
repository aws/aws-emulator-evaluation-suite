"""vpc-link-integration-availability-flow."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "vpc-link-integration-availability-flow"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A VPC_LINK integration can be wired before the VPC Link reaches AVAILABLE (only actually
    routing traffic through it requires that); once the link is AVAILABLE, a deployed method
    invocation really attempts the backend connection through the Network Load Balancer."""
    elbv2 = ctx.client("elbv2")
    apigw = ctx.client("apigateway")
    check_name = ctx.unique_name("sim2real-vpclink-flow-")

    # The internal NLB sits in two zones of the run's shared network.
    subnet_ids = ctx.network().subnet_ids[:2]

    nlb_name = _elb_safe_name(check_name)
    nlb = elbv2.create_load_balancer(
        Name=nlb_name, Subnets=subnet_ids, Scheme="internal", Type="network",
        Tags=[{"Key": "Name", "Value": nlb_name}],
    )["LoadBalancers"][0]
    nlb_arn = nlb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=nlb_arn))
    elbv2.get_waiter("load_balancer_available").wait(LoadBalancerArns=[nlb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    vpc_link_created = apigw.create_vpc_link(
        name=ctx.unique_name("sim2real-vpclink-"), targetArns=[nlb_arn], tags={"sim2real": CHECK}
    )
    vpc_link_id = vpc_link_created["id"]
    ctx.on_cleanup(lambda: _delete_vpc_link_and_wait(apigw, vpc_link_id))
    assert vpc_link_created["status"] != "AVAILABLE", (
        f"VPC link was already AVAILABLE at creation ({vpc_link_created['status']!r}); "
        "the pre-AVAILABLE integration-wiring claim below would go untested by this run"
    )

    rest_api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-vpclink-api-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=rest_api_id))
    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]
    resource_id = apigw.create_resource(
        restApiId=rest_api_id, parentId=root_id, pathPart="private"
    )["id"]
    apigw.put_method(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )

    # Wiring the VPC_LINK integration itself does not require the link to be AVAILABLE yet --
    # only actually routing traffic through it does.
    apigw.put_integration(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="HTTP_PROXY",
        integrationHttpMethod="GET",
        uri="http://internal.example.com/",
        connectionType="VPC_LINK",
        connectionId=vpc_link_id,
    )
    integration = apigw.get_integration(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET"
    )
    assert integration["connectionType"] == "VPC_LINK"
    assert integration["connectionId"] == vpc_link_id

    status = _poll_until(
        lambda: apigw.get_vpc_link(vpcLinkId=vpc_link_id)["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=600,
        interval_s=15,
    )
    assert status == "AVAILABLE", f"VPC link failed to provision: {status}"

    apigw.create_deployment(restApiId=rest_api_id, stageName="prod")
    resp = apigw.test_invoke_method(
        restApiId=rest_api_id, resourceId=resource_id, httpMethod="GET"
    )
    # The NLB has no listener registered, so any attempt to actually route through it must fail
    # at the gateway with a server-side status -- this is the only outcome AWS guarantees here.
    assert resp["status"] >= 500, f"expected a backend-connectivity failure, got {resp['status']}"


def _elb_safe_name(name: str) -> str:
    safe = "".join(c if (c.isalnum() or c == "-") else "-" for c in name)
    safe = safe.strip("-")[:32].strip("-")
    return safe or "sim2real-nlb"


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _delete_vpc_link_and_wait(apigw, vpc_link_id, timeout_s=900.0, interval_s=15.0):
    """Delete a REST API VPC link and wait until it is gone, so its load balancer becomes deletable.

    A link still provisioning refuses the delete; that is retried until the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            apigw.delete_vpc_link(vpcLinkId=vpc_link_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code not in ("BadRequestException", "ConflictException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    # The wait for the accepted delete gets its own window.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            apigw.get_vpc_link(vpcLinkId=vpc_link_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"VPC link {vpc_link_id} still exists {timeout_s:.0f}s after DeleteVpcLink")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
