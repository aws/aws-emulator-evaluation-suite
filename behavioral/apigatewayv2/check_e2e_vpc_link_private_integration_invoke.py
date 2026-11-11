"""e2e-vpc-link-private-integration-invoke."""
from __future__ import annotations

import io
import json
import time
import zipfile

import requests
from behavioral_harness import tags

CHECK = "e2e-vpc-link-private-integration-invoke"
GROUP = "e2e"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A VpcLink-backed private integration actually proxies HTTP API traffic through to a
    VPC-internal ALB target, and the backend response is observed through the public API endpoint."""
    apigw = ctx.client("apigatewayv2")

    vpc_id, subnet_ids = _shared_vpc_subnets(ctx)
    sg_id = _create_alb_security_group(ctx, vpc_id)

    fn_arn, fn_name = _create_backend_function(ctx, tag="vpc-link-target")

    alb_arn = _create_internal_alb(ctx, subnet_ids, sg_id)
    tg_arn = _create_lambda_target_group(ctx, fn_name, fn_arn)
    listener_arn = _create_listener(ctx, alb_arn, tg_arn)
    _wait_alb_active(ctx, alb_arn)

    vpc_link_id = _create_vpc_link(ctx, subnet_ids, sg_id)
    _wait_vpc_link_available(ctx, vpc_link_id)

    api_id = apigw.create_api(Name=ctx.unique_name("sim2real-behav-api-"), ProtocolType="HTTP")["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    integration_id = apigw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationMethod="ANY",
        ConnectionType="VPC_LINK",
        ConnectionId=vpc_link_id,
        IntegrationUri=listener_arn,
        PayloadFormatVersion="1.0",
    )["IntegrationId"]
    ctx.on_cleanup(lambda: apigw.delete_integration(ApiId=api_id, IntegrationId=integration_id))
    route_id = apigw.create_route(ApiId=api_id, RouteKey="ANY /proxy", Target=f"integrations/{integration_id}")["RouteId"]
    ctx.on_cleanup(lambda: apigw.delete_route(ApiId=api_id, RouteId=route_id))
    apigw.create_stage(ApiId=api_id, StageName="$default", AutoDeploy=True)

    api_endpoint = apigw.get_api(ApiId=api_id)["ApiEndpoint"]
    proxy_url, route = ctx.endpoint_route(f"{api_endpoint}/proxy")
    body = _poll_http_get(
        requests, proxy_url, "vpc-link-target", timeout_s=180.0, headers=route, verify=ctx.http_verify
    )
    assert "vpc-link-target" in body, (
        f"expected the public API endpoint to proxy through the VpcLink to the ALB/Lambda "
        f"backend and echo 'vpc-link-target'; got body={body!r}"
    )


# ===== helpers =====

def _shared_vpc_subnets(ctx) -> tuple[str, list[str]]:
    """The run's shared network: its VPC and subnets in two availability zones."""
    net = ctx.network()
    if len(net.subnet_ids) < 2:
        raise AssertionError(
            f"the shared network has fewer than 2 AZ-distinct subnets, required to create an "
            f"internal ALB and VPC Link: {net.subnet_ids}"
        )
    return net.vpc_id, net.subnet_ids[:2]


def _create_alb_security_group(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-sg-")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral test security group",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "behavioral"}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    vpc_cidr = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["CidrBlock"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": vpc_cidr}]}],
    )
    return sg_id


def _lambda_zip_bytes() -> bytes:
    buf = io.BytesIO()
    src = (
        "import os\n\n"
        "def handler(event, context):\n"
        "    return {'statusCode': 200, 'body': os.environ.get('RESPONSE_TAG', 'default')}\n"
    )
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


def _wait_lambda_active(ctx, fn_name: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = lam.get_function_configuration(FunctionName=fn_name).get("State")
        if state == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"lambda function never became Active (last state={state})")


def _delete_function_if_present(lam, fn_name: str) -> None:
    try:
        lam.delete_function(FunctionName=fn_name)
    except lam.exceptions.ResourceNotFoundException:
        pass


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    from botocore.exceptions import ClientError

    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_backend_function(ctx, tag: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    role_arn = _create_lambda_role(ctx)
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    zip_bytes = _lambda_zip_bytes()
    last_exc: Exception | None = None
    resp = None
    for _ in range(15):
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Environment={"Variables": {"RESPONSE_TAG": tag}},
                Timeout=10,
                Tags={"sim2real": "behavioral"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(2.0)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (last_exc={last_exc})")
    ctx.on_cleanup(lambda: _delete_function_if_present(lam, fn_name))
    ctx.on_cleanup(lambda: _delete_lambda_log_group(ctx, fn_name))
    _wait_lambda_active(ctx, fn_name)
    return resp["FunctionArn"], fn_name


def _create_internal_alb(ctx, subnet_ids: list[str], sg_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-alb-")[:32]
    alb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internal",
        Type="application",
        IpAddressType="ipv4",
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["LoadBalancers"][0]
    alb_arn = alb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))
    return alb_arn


def _create_lambda_target_group(ctx, fn_name: str, fn_arn: str) -> str:
    elbv2 = ctx.client("elbv2")
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-tg-")[:32]
    tg_arn = elbv2.create_target_group(
        Name=name, TargetType="lambda", Tags=[{"Key": "sim2real", "Value": "behavioral"}]
    )["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="sim2real-elbv2-invoke",
        Action="lambda:InvokeFunction",
        Principal="elasticloadbalancing.amazonaws.com",
        SourceArn=tg_arn,
    )
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}])
    return tg_arn


def _create_listener(ctx, alb_arn: str, tg_arn: str) -> str:
    elbv2 = ctx.client("elbv2")
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=alb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _wait_alb_active(ctx, alb_arn: str, timeout_s: float = 240.0, interval_s: float = 10.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        # A just-created load balancer can briefly read back as LoadBalancerNotFound.
        try:
            state = elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["State"]["Code"]
        except elbv2.exceptions.LoadBalancerNotFoundException:
            state = "not-yet-visible"
        if state == "active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"ALB never became active (last state={state})")


def _create_vpc_link(ctx, subnet_ids: list[str], sg_id: str) -> str:
    apigw = ctx.client("apigatewayv2")
    vpc_link_id = apigw.create_vpc_link(
        Name=ctx.unique_name("sim2real-behav-vpclink-"),
        SubnetIds=subnet_ids,
        SecurityGroupIds=[sg_id],
        Tags={"sim2real": "behavioral"},
    )["VpcLinkId"]
    ctx.on_cleanup(lambda: _delete_vpc_link_and_wait(apigw, vpc_link_id))
    return vpc_link_id


def _wait_vpc_link_available(ctx, vpc_link_id: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> None:
    apigw = ctx.client("apigatewayv2")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = apigw.get_vpc_link(VpcLinkId=vpc_link_id)["VpcLinkStatus"]
        if status == "AVAILABLE":
            return
        if status == "FAILED":
            raise AssertionError("vpc link entered FAILED status while waiting for AVAILABLE")
        time.sleep(interval_s)
    raise AssertionError(f"vpc link never became AVAILABLE (last status={status})")


def _poll_http_get(
    requests_mod,
    url: str,
    expected_substring: str,
    timeout_s: float = 60.0,
    headers=None,
    interval_s: float = 5.0,
    verify: bool | str = True,
) -> str:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    last_text = None
    while time.monotonic() < deadline:
        try:
            resp = requests_mod.get(url, headers=headers, timeout=10, verify=verify)
            last_text = resp.text
            if resp.status_code == 200 and expected_substring in resp.text:
                return resp.text
        except requests_mod.exceptions.RequestException as exc:
            last_exc = exc
        time.sleep(interval_s)
    raise AssertionError(f"{url} never returned expected content (last_text={last_text!r}, last_exc={last_exc})")


# The teardown waits below fit a 900 s cleanup budget: 420 s for the VPC link, 240 s for the
# security group and 180 s for the target group, so even all three at their bound fit in it.
def _delete_security_group_when_free(ec2, sg_id, timeout_s=240.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_target_group_when_free(elbv2, arn, timeout_s=180.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
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


def _delete_vpc_link_and_wait(apigw, vpc_link_id, timeout_s=420.0, interval_s=15.0):
    """Delete an HTTP API VPC link and wait until it is gone, so its ENIs leave the subnets.

    A link still PENDING refuses the delete (BadRequestException); that is retried until the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            apigw.delete_vpc_link(VpcLinkId=vpc_link_id)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "BadRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            apigw.get_vpc_link(VpcLinkId=vpc_link_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"VPC link {vpc_link_id} still exists {timeout_s:.0f}s after DeleteVpcLink")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
