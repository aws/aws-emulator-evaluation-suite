"""deploy-alb-listener-target-group-cfn-behaves."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-alb-listener-target-group-cfn-behaves"
GROUP = "deploy"
SERVICES = ["elbv2"]


def _tags_kv() -> list[dict]:
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]


_LAMBDA_SRC = (
    "def handler(event, context):\n"
    "    return {\n"
    "        'statusCode': 200,\n"
    "        'statusDescription': '200 OK',\n"
    "        'isBase64Encoded': False,\n"
    "        'headers': {'Content-Type': 'text/plain'},\n"
    "        'body': 'sim2real-alb-lambda-target-ok',\n"
    "    }\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CFN-deployed ALB+Listener+TargetGroup actually routes to a target registered via the API."""
    ctx.client("ec2")
    vpc_id, subnet_ids, sg_id = _default_vpc_subnets_and_sg(ctx)

    role_arn = _create_lambda_role(ctx)
    lambda_arn = _create_lambda_function(ctx, role_arn)

    stack_name = ctx.unique_name("sim2real-albcfn-")
    lb_name = ctx.unique_name("sim2real-lb-")[:32].rstrip("-")
    tg_name = ctx.unique_name("sim2real-tg-")[:32].rstrip("-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LB": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Name": lb_name,
                    "Type": "application",
                    "Scheme": "internet-facing",
                    "Subnets": subnet_ids,
                    "SecurityGroups": [sg_id],
                },
            },
            "TG": {
                "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                "Properties": {
                    "Name": tg_name,
                    "TargetType": "lambda",
                    "HealthCheckEnabled": True,
                },
            },
            "Listener": {
                "Type": "AWS::ElasticLoadBalancingV2::Listener",
                "Properties": {
                    "LoadBalancerArn": {"Ref": "LB"},
                    "Port": 80,
                    "Protocol": "HTTP",
                    "DefaultActions": [
                        {"Type": "forward", "TargetGroupArn": {"Ref": "TG"}}
                    ],
                },
            },
        },
        "Outputs": {
            "LoadBalancerArn": {"Value": {"Ref": "LB"}},
            "TargetGroupArn": {"Value": {"Ref": "TG"}},
            "ListenerArn": {"Value": {"Ref": "Listener"}},
            "DNSName": {"Value": {"Fn::GetAtt": ["LB", "DNSName"]}},
        },
    }
    outputs = _deploy_stack(ctx, stack_name, json.dumps(template), tags=_tags_kv())

    tg_arn = outputs["TargetGroupArn"]
    dns_name = outputs["DNSName"]

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

    _wait_target_healthy(ctx, tg_arn, lambda_arn)
    _wait_http_ok(ctx, f"http://{dns_name}/", "sim2real-alb-lambda-target-ok")


# ===== helpers =====


def _get_subnets(ctx) -> tuple[str, list[str]]:
    """Create-or-adopt: use the account's default VPC when it has >=2 AZ subnets, else
    provision a minimal internet-routable VPC of our own so a fresh account still passes."""
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    by_az: dict[str, dict] = {}
    for s in resp.get("Subnets", []):
        by_az.setdefault(s["AvailabilityZone"], s)
    if len(by_az) >= 2:
        chosen = list(by_az.values())[:2]
        return chosen[0]["VpcId"], [s["SubnetId"] for s in chosen]
    return _create_public_vpc(ctx)


def _create_public_vpc(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.create_tags(
        Resources=[vpc_id], Tags=_tags_kv() + [{"Key": "Name", "Value": ctx.unique_name("sim2real-albcfn-vpc-")}]
    )

    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))

    rtb_id = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rtb_id))
    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
    subnet_ids = []
    for i in range(2):
        az = azs[i % len(azs)]["ZoneName"]
        sid = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.0.{i}.0/24", AvailabilityZone=az)["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=sid: ec2.delete_subnet(SubnetId=sid))
        ec2.modify_subnet_attribute(SubnetId=sid, MapPublicIpOnLaunch={"Value": True})
        ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=sid)
        subnet_ids.append(sid)
    return vpc_id, subnet_ids


def _default_vpc_subnets_and_sg(ctx) -> tuple[str, list[str], str]:
    ec2 = ctx.client("ec2")
    vpc_id, subnet_ids = _get_subnets(ctx)

    sg_name = ctx.unique_name("sim2real-alb-sg-")
    sg = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real behavioral check: allow inbound HTTP",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": _tags_kv() + [{"Key": "Name", "Value": sg_name}]}
        ],
    )
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()],
            }
        ],
    )

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
    return vpc_id, subnet_ids, sg_id


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-alb-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_tags_kv())
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


def _create_lambda_function(ctx, role_arn: str) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-alb-target-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", _LAMBDA_SRC)
    zip_bytes = buf.getvalue()

    deadline = time.monotonic() + 60.0
    while True:
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=10,
                Publish=True,
                Tags={"sim2real:managed": "true", "sim2real:check": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    return resp["FunctionArn"]


def _deploy_stack(ctx, stack_name: str, template_body: str, tags: list[dict] | None = None) -> dict[str, str]:
    cfn = ctx.client("cloudformation")

    def _cleanup() -> None:
        # An ALB stack deletes within a few minutes; the wait is bounded at 600 s.
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    kwargs = {"StackName": stack_name, "TemplateBody": template_body}
    if tags:
        kwargs["Tags"] = tags
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _wait_target_healthy(ctx, tg_arn: str, target_id: str, timeout_s: float = 120.0, interval_s: float = 5.0) -> None:
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        resp = elbv2.describe_target_health(TargetGroupArn=tg_arn, Targets=[{"Id": target_id}])
        descs = resp.get("TargetHealthDescriptions", [])
        if descs:
            last = descs[0]["TargetHealth"]["State"]
            if last == "healthy":
                return
        time.sleep(interval_s)
    raise AssertionError(f"lambda target never reached 'healthy', last observed state={last!r}")


def _wait_http_ok(ctx, url: str, expected_body: str, timeout_s: float = 180.0, interval_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_err = "never attempted"
    while time.monotonic() < deadline:
        try:
            _url, _route = ctx.endpoint_route(url)
            with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=10) as resp:  # noqa: S310
                body = resp.read().decode()
                if resp.status == 200 and body == expected_body:
                    return
                last_err = f"status={resp.status} body={body!r}"
        except (urllib.error.URLError, OSError) as exc:
            last_err = str(exc)
        time.sleep(interval_s)
    raise AssertionError(f"ALB never routed a request to the registered target: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
