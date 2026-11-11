"""e2e-vpc-link-private-integration-flow."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-vpc-link-private-integration-flow"
GROUP = "e2e"
SERVICES = ["apigatewayv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An HTTP_PROXY integration over a VpcLink routes live traffic to a private ALB
    backend; deleting the VpcLink means it can no longer be attached to an integration."""
    apigw = ctx.client("apigatewayv2")
    vpc_id, subnet_ids = _default_vpc_subnets(ctx, count=2)
    sg_id = _default_security_group(ctx, vpc_id)

    listener_arn = _create_alb_lambda_backend(ctx, subnet_ids, sg_id, "vpc-link-ok")

    vpc_link = apigw.create_vpc_link(
        Name=ctx.unique_name("sim2real-behav-vpclink-"),
        SubnetIds=subnet_ids,
        SecurityGroupIds=[sg_id],
        Tags={"sim2real": CHECK},
    )
    vpc_link_id = vpc_link["VpcLinkId"]

    def _cleanup_vpc_link():
        try:
            apigw.delete_vpc_link(VpcLinkId=vpc_link_id)
        except apigw.exceptions.NotFoundException:
            pass

    ctx.on_cleanup(_cleanup_vpc_link)

    _poll_until(
        lambda: apigw.get_vpc_link(VpcLinkId=vpc_link_id)["VpcLinkStatus"],
        lambda s: s == "AVAILABLE",
        timeout_s=600,
        interval_s=15,
    )

    api = apigw.create_api(
        Name=ctx.unique_name("sim2real-behav-"), ProtocolType="HTTP", Tags={"sim2real": CHECK}
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))

    integ = apigw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationUri=listener_arn,
        IntegrationMethod="ANY",
        ConnectionType="VPC_LINK",
        ConnectionId=vpc_link_id,
        PayloadFormatVersion="1.0",
    )
    apigw.create_route(ApiId=api_id, RouteKey="ANY /{proxy+}", Target=f"integrations/{integ['IntegrationId']}")
    apigw.create_stage(ApiId=api_id, StageName="prod", AutoDeploy=True)

    endpoint = api["ApiEndpoint"]
    body = _poll_until(
        lambda: _fetch_body(ctx, f"{endpoint}/prod/hello"),
        lambda b: "vpc-link-ok" in (b or ""),
        timeout_s=240,
        interval_s=10,
    )
    assert "vpc-link-ok" in body, (
        f"expected the HTTP_PROXY integration over the VpcLink to reach the private ALB/Lambda "
        f"backend and return 'vpc-link-ok', got {body!r}"
    )

    apigw.delete_vpc_link(VpcLinkId=vpc_link_id)
    _poll_until(
        lambda: _vpc_link_status_or_error(apigw, vpc_link_id),
        lambda r: r[0] == "NotFoundException",
        timeout_s=300,
        interval_s=15,
    )

    code, message = _error(
        lambda: apigw.create_integration(
            ApiId=api_id,
            IntegrationType="HTTP_PROXY",
            IntegrationUri=listener_arn,
            IntegrationMethod="ANY",
            ConnectionType="VPC_LINK",
            ConnectionId=vpc_link_id,
            PayloadFormatVersion="1.0",
        )
    )
    assert code == "BadRequestException", (
        f"expected create_integration against the now-deleted VpcLink {vpc_link_id!r} to fail with "
        f"BadRequestException, got {code!r}: {message!r}"
    )
    assert message == f"Vpc link {vpc_link_id} was not found in account {ctx.account}", (
        f"expected the exact deleted-VpcLink refusal message, got {message!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn; return the ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _vpc_link_status_or_error(apigw, vpc_link_id):
    """("OK", status) while GetVpcLink succeeds, else the ClientError (code, message)."""
    from botocore.exceptions import ClientError

    try:
        return "OK", apigw.get_vpc_link(VpcLinkId=vpc_link_id)["VpcLinkStatus"]
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={last!r}")


def _default_vpc_subnets(ctx, count=2):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to source subnets for a VPC link")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if len(subnets) < count:
        raise AssertionError(f"shared network has fewer than {count} subnets available for a VPC link")
    return vpc_id, [s["SubnetId"] for s in subnets[:count]]


def _lambda_zip(response_body: str) -> bytes:
    src = (
        "def handler(event, context):\n"
        "    return {\n"
        '        "statusCode": 200,\n'
        '        "statusDescription": "200 OK",\n'
        '        "isBase64Encoded": False,\n'
        '        "headers": {"Content-Type": "text/plain"},\n'
        f'        "body": "{response_body}",\n'
        "    }\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_lambda_function(ctx, role_arn: str, response_body: str) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    zip_bytes = _lambda_zip(response_body)
    resp = None
    last_err = None
    left = ctx.time_left()
    # A new role propagates to Lambda within seconds: retry its InvalidParameterValue to 60 s.
    deadline = time.monotonic() + (60 if left is None else min(60, left))
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=10,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(2)
    if resp is None:
        raise last_err or AssertionError(f"no time left to create Lambda function {fn_name}")
    fn_arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=fn_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=3,
    )
    return fn_arn


def _default_security_group(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group available")
    return sgs[0]["GroupId"]


def _create_alb_lambda_backend(ctx, subnet_ids, sg_id: str, response_body: str) -> str:
    # Application Load Balancer, not Network Load Balancer: NLB target groups do not
    # support TargetType="lambda", only ALB does. VPC links V2 support private
    # integrations with either an ALB or an NLB listener ARN.
    elbv2 = ctx.client("elbv2")
    lam = ctx.client("lambda")

    role_arn = _create_lambda_role(ctx)
    fn_arn = _create_lambda_function(ctx, role_arn, response_body)

    tg_name = ctx.unique_name("sim2real-tg-")[:32].rstrip("-")
    tg = elbv2.create_target_group(
        Name=tg_name, TargetType="lambda", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    tg_arn = tg["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda: elbv2.delete_target_group(TargetGroupArn=tg_arn))

    lam.add_permission(
        FunctionName=fn_arn,
        StatementId="elb-invoke",
        Action="lambda:InvokeFunction",
        Principal="elasticloadbalancing.amazonaws.com",
        SourceArn=tg_arn,
    )
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": fn_arn}])

    alb_name = ctx.unique_name("sim2real-alb-")[:32].rstrip("-")
    alb = elbv2.create_load_balancer(
        Name=alb_name,
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internal",
        Type="application",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    alb_arn = alb["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))

    _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])["LoadBalancers"][0]["State"]["Code"],
        lambda s: s == "active",
        timeout_s=300,
        interval_s=10,
    )

    listener = elbv2.create_listener(
        LoadBalancerArn=alb_arn,
        Protocol="HTTP",
        Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    listener_arn = listener["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_listener(ListenerArn=listener_arn))
    return listener_arn


def _fetch_body(ctx, url: str, timeout: float = 15.0) -> str | None:
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method="GET", headers=_route)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", errors="replace") if e.fp else None
    except urllib.error.URLError:
        return None


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
