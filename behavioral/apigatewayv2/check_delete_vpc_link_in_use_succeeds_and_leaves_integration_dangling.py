"""delete-vpc-link-in-use-succeeds-and-leaves-integration-dangling."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-vpc-link-in-use-succeeds-and-leaves-integration-dangling"
GROUP = "server-side"
SERVICES = ["apigatewayv2"]
TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVpcLink on a link an integration still references is accepted and completes, leaving
    the integration with a dangling ConnectionId (no rejection, no cascade); an unused link
    deletes the same way.
    """
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    apigw = ctx.client("apigatewayv2")

    subnets = _default_subnets(ec2, ctx=ctx)
    if not subnets:
        raise AssertionError(
            "no default-VPC subnets available in this account/region to create "
            "an apigatewayv2 VPC link; would need explicit VPC/subnet provisioning "
            "to close this gap"
        )
    subnet_ids = [s["SubnetId"] for s in subnets]
    vpc_id = subnets[0]["VpcId"]

    # A real NLB + listener is required: CreateIntegration with ConnectionType
    # VPC_LINK resolves the IntegrationUri to an actual listener at creation
    # time, it does not accept an arbitrary/synthetic listener ARN.
    tg_arn = elbv2.create_target_group(
        Name=ctx.unique_name("sim2real-behav-tg-")[:32],
        Protocol="TCP",
        Port=80,
        VpcId=vpc_id,
        TargetType="instance",
        Tags=TAGS_KV,
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))

    lb_arn = elbv2.create_load_balancer(
        Name=ctx.unique_name("sim2real-behav-nlb-")[:32],
        Subnets=subnet_ids,
        Scheme="internal",
        Type="network",
        Tags=TAGS_KV,
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(elbv2, lb_arn))

    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol="TCP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=TAGS_KV,
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: _delete_listener_if_present(elbv2, listener_arn))

    api_id = apigw.create_api(
        Name=ctx.unique_name("sim2real-behav-api-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    used_link_id = apigw.create_vpc_link(
        Name=ctx.unique_name("sim2real-behav-vpclink-"), SubnetIds=subnet_ids, Tags=TAGS
    )["VpcLinkId"]
    # Best-effort: the check normally deletes the link itself.
    ctx.on_cleanup(lambda: _delete_vpc_link_if_present(apigw, used_link_id))

    _poll_until(
        lambda: apigw.get_vpc_link(VpcLinkId=used_link_id)["VpcLinkStatus"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=300,
        interval_s=10,
    )

    integration_id = apigw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationMethod="ANY",
        ConnectionType="VPC_LINK",
        ConnectionId=used_link_id,
        IntegrationUri=listener_arn,
        PayloadFormatVersion="1.0",
    )["IntegrationId"]

    # Accepted asynchronously (202); a synchronous rejection raises and fails the check.
    apigw.delete_vpc_link(VpcLinkId=used_link_id)

    # AWS enforces no referential integrity here, so the in-use link really disappears.
    final_status = _poll_until(
        lambda: _get_vpc_link_status_or_gone(apigw, used_link_id),
        lambda s: s == "GONE",
        timeout_s=180,
        interval_s=10,
    )
    assert final_status == "GONE", (
        f"expected DeleteVpcLink to eventually make the in-use link disappear, got {final_status!r}"
    )

    # The integration is not cascade-deleted and keeps pointing at the missing link.
    dangling = apigw.get_integration(ApiId=api_id, IntegrationId=integration_id)
    assert dangling["ConnectionId"] == used_link_id, (
        f"expected the integration to keep its stale ConnectionId, got {dangling!r}"
    )

    # Positive control: an unused VPC link deletes the same way.
    unused_link_id = apigw.create_vpc_link(
        Name=ctx.unique_name("sim2real-behav-vpclink-"), SubnetIds=subnet_ids, Tags=TAGS
    )["VpcLinkId"]
    ctx.on_cleanup(lambda: _delete_vpc_link_if_present(apigw, unused_link_id))
    _poll_until(
        lambda: apigw.get_vpc_link(VpcLinkId=unused_link_id)["VpcLinkStatus"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=300,
        interval_s=10,
    )
    apigw.delete_vpc_link(VpcLinkId=unused_link_id)  # must not raise
    _poll_until(
        lambda: _get_vpc_link_status_or_gone(apigw, unused_link_id),
        lambda s: s == "GONE",
        timeout_s=120,
        interval_s=5,
    )

def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _get_vpc_link_status_or_gone(apigw, vpc_link_id):
    from botocore.exceptions import ClientError

    try:
        return apigw.get_vpc_link(VpcLinkId=vpc_link_id)["VpcLinkStatus"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return "GONE"
        raise


def _delete_vpc_link_if_present(apigw, vpc_link_id):
    from botocore.exceptions import ClientError

    try:
        apigw.delete_vpc_link(VpcLinkId=vpc_link_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _delete_listener_if_present(elbv2, listener_arn):
    from botocore.exceptions import ClientError

    try:
        elbv2.delete_listener(ListenerArn=listener_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ListenerNotFound":
            raise


def _delete_lb_and_wait(elbv2, lb_arn):
    from botocore.exceptions import ClientError

    try:
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise
        return
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError as e:
            if e.response["Error"]["Code"] == "LoadBalancerNotFound":
                return
            raise
        time.sleep(10)


def _default_subnets(ec2, *, ctx) -> list[dict]:
    resp = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )
    return resp.get("Subnets", [])[:3]



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
