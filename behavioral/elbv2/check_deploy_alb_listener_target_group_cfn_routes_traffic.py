"""deploy-alb-listener-target-group-cfn-routes-traffic."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-alb-listener-target-group-cfn-routes-traffic"
GROUP = "deploy"
SERVICES = ["elbv2"]

_BODY_MARKER = "sim2real-albcfn-routes-traffic-ok"


def _tags_kv() -> list[dict]:
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed ALB routes to an out-of-band registered Lambda target: the target turns healthy,
    the listener forwards to the CFN target group, and a request via the ALB DNS name reaches it."""
    subnet_ids, vpc_id = _get_subnets(ctx)
    sg_id = _create_ingress_sg(ctx, vpc_id)
    role_arn = _create_lambda_role(ctx)
    lambda_arn = _create_lambda_function(ctx, role_arn)

    tg_name = _short_name(ctx, "sim2realtg")
    alb_name = _short_name(ctx, "sim2realalb")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"}, "SgId": {"Type": "AWS::EC2::SecurityGroup::Id"}},
        "Resources": {
            "Alb": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Name": alb_name,
                    "Type": "application",
                    "Scheme": "internet-facing",
                    "Subnets": {"Ref": "SubnetIds"},
                    "SecurityGroups": [{"Ref": "SgId"}],
                    "Tags": _tags_kv(),
                },
            },
            "Tg": {
                "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                "Properties": {
                    "Name": tg_name,
                    "TargetType": "lambda",
                    "HealthCheckEnabled": True,
                    "HealthCheckIntervalSeconds": 35,
                    "HealthCheckTimeoutSeconds": 30,
                    "HealthyThresholdCount": 2,
                    "UnhealthyThresholdCount": 2,
                    "Tags": _tags_kv(),
                },
            },
            "Listener": {
                "Type": "AWS::ElasticLoadBalancingV2::Listener",
                "Properties": {
                    "LoadBalancerArn": {"Ref": "Alb"},
                    "Port": 80,
                    "Protocol": "HTTP",
                    "DefaultActions": [{"Type": "forward", "TargetGroupArn": {"Ref": "Tg"}}],
                },
            },
        },
        "Outputs": {
            "AlbArn": {"Value": {"Ref": "Alb"}},
            "ListenerArn": {"Value": {"Ref": "Listener"}},
            "TgArn": {"Value": {"Ref": "Tg"}},
            "DnsName": {"Value": {"Fn::GetAtt": ["Alb", "DNSName"]}},
        },
    }
    outputs = _deploy_cfn(
        ctx,
        template,
        parameters=[
            {"ParameterKey": "SubnetIds", "ParameterValue": ",".join(subnet_ids)},
            {"ParameterKey": "SgId", "ParameterValue": sg_id},
        ],
    )
    tg_arn = outputs["TgArn"]
    listener_arn = outputs["ListenerArn"]
    dns_name = outputs["DnsName"]

    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=lambda_arn,
        StatementId="AllowELBInvoke",
        Action="lambda:InvokeFunction",
        Principal="elasticloadbalancing.amazonaws.com",
        SourceArn=tg_arn,
    )

    elbv2 = ctx.client("elbv2")
    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": lambda_arn}])
    ctx.on_cleanup(lambda: elbv2.deregister_targets(TargetGroupArn=tg_arn, Targets=[{"Id": lambda_arn}]))

    state = _poll_target_health(ctx, tg_arn, lambda_arn, want_state="healthy", timeout_s=220.0)
    assert state == "healthy", f"target never reached healthy, last={state!r}"

    listeners = elbv2.describe_listeners(ListenerArns=[listener_arn])["Listeners"]
    assert len(listeners) == 1, f"expected exactly 1 listener for {listener_arn!r}, got {len(listeners)}"
    default_actions = listeners[0]["DefaultActions"]
    assert default_actions[0]["Type"] == "forward", f"expected DefaultActions[0].Type == 'forward', got {default_actions[0]['Type']!r}"
    assert default_actions[0]["TargetGroupArn"] == tg_arn, (
        f"listener's default action forwards to {default_actions[0]['TargetGroupArn']!r}, expected {tg_arn!r}"
    )

    body = _wait_http_ok(ctx, f"http://{dns_name}/", timeout_s=45.0, interval_s=5.0)
    assert body == _BODY_MARKER, f"ALB did not route the client request to our lambda target, got body={body!r}"




def _short_name(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix)[:32].rstrip("-")


def _get_subnets(ctx) -> tuple[list[str], str]:
    """Two subnets in distinct AZs of the run's shared network, as an ALB requires."""
    net = ctx.network()
    subnet_ids = net.subnet_ids[:2]
    if len(subnet_ids) < 2:
        raise AssertionError(f"shared network has fewer than 2 AZ subnets for the ALB: {net.subnets!r}")
    return subnet_ids, net.vpc_id


def _create_ingress_sg(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    sg_name = ctx.unique_name("sim2real-albcfn-sg-")
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real behavioral check: allow inbound HTTP to the ALB",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv() + [{"Key": "Name", "Value": sg_name}]}],
    )["GroupId"]

    def _cleanup_sg() -> None:
        deadline = time.monotonic() + 120.0
        while True:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except Exception:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(5)

    ctx.on_cleanup(_cleanup_sg)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}],
    )
    return sg_id


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = _short_name(ctx, "sim2real-lambda-role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_tags_kv()
    )["Role"]
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )

    def _cleanup():
        iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        )
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_lambda_function(ctx, role_arn: str) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    code = (
        "def handler(event, context):\n"
        "    return {'statusCode': 200, 'statusDescription': '200 OK', "
        f"'headers': {{'Content-Type': 'text/plain'}}, 'body': {_BODY_MARKER!r}}}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    resp = None
    last_exc = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": buf.getvalue()},
                Timeout=10,
                Tags={"sim2real:managed": "true", "sim2real:check": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"lambda function creation failed after retries: {last_exc}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _deploy_cfn(ctx, template_body: dict, parameters: list[dict] | None = None) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-albstack-")
    kwargs = {"StackName": stack_name, "TemplateBody": json.dumps(template_body), "Tags": _tags_kv()}
    if parameters:
        kwargs["Parameters"] = parameters
    cfn.create_stack(**kwargs)

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    ctx.on_cleanup(_cleanup)
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
    except Exception as exc:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        reasons = [e.get("ResourceStatusReason", "") for e in events if "FAILED" in e.get("ResourceStatus", "")]
        raise AssertionError(f"stack {stack_name} failed to create: {reasons}") from exc
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _poll_target_health(
    ctx, tg_arn: str, target_id: str, want_state: str = "healthy", timeout_s: float = 150.0, interval_s: float = 5.0
) -> str | None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = elbv2.describe_target_health(TargetGroupArn=tg_arn, Targets=[{"Id": target_id}])
        descs = resp["TargetHealthDescriptions"]
        if descs:
            last = descs[0]["TargetHealth"]["State"]
            if last == want_state:
                return last
        time.sleep(interval_s)
    return last


def _wait_http_ok(ctx, url: str, timeout_s: float = 45.0, interval_s: float = 5.0) -> str | None:
    deadline = time.monotonic() + timeout_s
    last_body: str | None = None
    while time.monotonic() < deadline:
        try:
            _url, _route = ctx.endpoint_route(url)
            with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=10) as resp:  # noqa: S310
                if resp.status == 200:
                    last_body = resp.read().decode()
                    if last_body == _BODY_MARKER:
                        return last_body
        except (urllib.error.URLError, OSError) as exc:
            last_body = f"<error: {exc}>"
        time.sleep(interval_s)
    return last_body


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
