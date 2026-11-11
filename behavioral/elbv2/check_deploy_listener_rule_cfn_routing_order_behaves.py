"""deploy-listener-rule-cfn-routing-order-behaves."""
from __future__ import annotations

import io
import json
import time
import urllib.error
import urllib.request
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-listener-rule-cfn-routing-order-behaves"
GROUP = "deploy"
SERVICES = ["elbv2"]

# Rule resources are declared out of numeric-priority order on purpose (100, then 10, then 50)
# to prove DescribeRules sorts by Priority rather than echoing template/creation order.
_TEMPLATE = json.dumps(
    {
        "Parameters": {
            "SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"},
            "SecurityGroupId": {"Type": "String"},
            "LambdaArn": {"Type": "String"},
        },
        "Resources": {
            "Alb": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Type": "application",
                    "Scheme": "internet-facing",
                    "Subnets": {"Ref": "SubnetIds"},
                    "SecurityGroups": [{"Ref": "SecurityGroupId"}],
                },
            },
            "TgHigh": {
                "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                "Properties": {"TargetType": "lambda", "Targets": [{"Id": {"Ref": "LambdaArn"}}]},
            },
            "TgLow": {
                "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                "Properties": {"TargetType": "lambda", "Targets": [{"Id": {"Ref": "LambdaArn"}}]},
            },
            "TgMid": {
                "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                "Properties": {"TargetType": "lambda", "Targets": [{"Id": {"Ref": "LambdaArn"}}]},
            },
            "Listener": {
                "Type": "AWS::ElasticLoadBalancingV2::Listener",
                "Properties": {
                    "LoadBalancerArn": {"Ref": "Alb"},
                    "Port": 80,
                    "Protocol": "HTTP",
                    "DefaultActions": [
                        {
                            "Type": "fixed-response",
                            "FixedResponseConfig": {
                                "StatusCode": "404",
                                "ContentType": "text/plain",
                                "MessageBody": "no-match",
                            },
                        }
                    ],
                },
            },
            "RuleHighPriority": {
                "Type": "AWS::ElasticLoadBalancingV2::ListenerRule",
                "Properties": {
                    "ListenerArn": {"Ref": "Listener"},
                    "Priority": 100,
                    "Conditions": [{"Field": "path-pattern", "Values": ["/*"]}],
                    "Actions": [{"Type": "forward", "TargetGroupArn": {"Ref": "TgHigh"}}],
                },
            },
            "RuleLowestPriority": {
                "Type": "AWS::ElasticLoadBalancingV2::ListenerRule",
                "Properties": {
                    "ListenerArn": {"Ref": "Listener"},
                    "Priority": 10,
                    "Conditions": [{"Field": "path-pattern", "Values": ["/test"]}],
                    "Actions": [{"Type": "forward", "TargetGroupArn": {"Ref": "TgLow"}}],
                },
            },
            "RuleMidPriority": {
                "Type": "AWS::ElasticLoadBalancingV2::ListenerRule",
                "Properties": {
                    "ListenerArn": {"Ref": "Listener"},
                    "Priority": 50,
                    "Conditions": [{"Field": "path-pattern", "Values": ["/test"]}],
                    "Actions": [{"Type": "forward", "TargetGroupArn": {"Ref": "TgMid"}}],
                },
            },
        },
        "Outputs": {
            "ListenerArn": {"Value": {"Ref": "Listener"}},
            "LoadBalancerArn": {"Value": {"Ref": "Alb"}},
            "LoadBalancerDnsName": {"Value": {"Fn::GetAtt": ["Alb", "DNSName"]}},
            "TgHighArn": {"Value": {"Ref": "TgHigh"}},
            "TgLowArn": {"Value": {"Ref": "TgLow"}},
            "TgMidArn": {"Value": {"Ref": "TgMid"}},
        },
    }
)

_LAMBDA_CODE = (
    "def handler(event, context):\n"
    "    tg_arn = event.get('requestContext', {}).get('elb', {}).get('targetGroupArn', 'unknown')\n"
    "    return {\n"
    "        'statusCode': 200,\n"
    "        'statusDescription': '200 OK',\n"
    "        'isBase64Encoded': False,\n"
    "        'headers': {'Content-Type': 'text/plain'},\n"
    "        'body': tg_arn,\n"
    "    }\n"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Three CloudFormation listener rules declared with priorities 100, 10, 50 are listed by DescribeRules as
    10, 50, 100, and HTTP requests through the ALB reach the lowest-priority matching rule's target."""
    vpc_id, subnet_ids = _default_vpc_subnets(ctx)
    sg_id = _create_open_http_sg(ctx, vpc_id)
    role_arn = _create_lambda_role(ctx)
    lambda_arn = _create_lambda_function(ctx, role_arn, _LAMBDA_CODE)

    # CloudFormation registers the Lambda targets declared in each TargetGroup's "Targets"
    # property as part of stack creation, so the ELB service must already be permitted to invoke
    # the function *before* the stack is created (the target group ARNs don't exist yet, so the
    # permission is scoped to the account rather than to individual target-group ARNs).
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=lambda_arn,
        StatementId="AllowElbInvokeAnyTargetGroup",
        Action="lambda:InvokeFunction",
        Principal="elasticloadbalancing.amazonaws.com",
        SourceAccount=account_id,
    )

    outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        [
            {"ParameterKey": "SubnetIds", "ParameterValue": ",".join(subnet_ids)},
            {"ParameterKey": "SecurityGroupId", "ParameterValue": sg_id},
            {"ParameterKey": "LambdaArn", "ParameterValue": lambda_arn},
        ],
    )
    listener_arn = outputs["ListenerArn"]
    dns_name = outputs["LoadBalancerDnsName"]
    tg_high, tg_low, tg_mid = outputs["TgHighArn"], outputs["TgLowArn"], outputs["TgMidArn"]

    elbv2 = ctx.client("elbv2")
    rules = elbv2.describe_rules(ListenerArn=listener_arn)["Rules"]
    non_default = [r for r in rules if not r["IsDefault"]]
    priorities = [int(r["Priority"]) for r in non_default]
    assert priorities == sorted(priorities), f"DescribeRules did not return priority-sorted order: {priorities}"
    assert priorities == [10, 50, 100], f"expected the three declared priorities [10, 50, 100], got {priorities}"
    tg_by_priority = {int(r["Priority"]): r["Actions"][0]["TargetGroupArn"] for r in non_default}
    assert tg_by_priority[10] == tg_low, (
        f"expected priority-10 rule to forward to TgLow {tg_low!r}, got {tg_by_priority[10]!r}"
    )
    assert tg_by_priority[50] == tg_mid, (
        f"expected priority-50 rule to forward to TgMid {tg_mid!r}, got {tg_by_priority[50]!r}"
    )
    assert tg_by_priority[100] == tg_high, (
        f"expected priority-100 rule to forward to TgHigh {tg_high!r}, got {tg_by_priority[100]!r}"
    )

    # "/test" matches all three rules (Low/Mid via exact match, High via the wildcard); the
    # lowest-priority (10) rule must win the actual routing decision.
    body_test = _poll_http_body(ctx, f"http://{dns_name}/test", timeout_s=300, interval_s=5)
    assert body_test == tg_low, f"expected GET /test to be routed to the priority-10 target {tg_low!r}, got {body_test!r}"

    # "/other" only matches the wildcard (priority 100) rule.
    body_other = _poll_http_body(ctx, f"http://{dns_name}/other", timeout_s=60, interval_s=5)
    assert body_other == tg_high, (
        f"expected GET /other to be routed to the priority-100 target {tg_high!r}, got {body_other!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_http_body(ctx, url, *, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            _url, _route = ctx.endpoint_route(url)
            with urllib.request.urlopen(urllib.request.Request(_url, headers=_route), timeout=5) as resp:
                if resp.status == 200:
                    return resp.read().decode("utf-8")
        except (urllib.error.URLError, OSError) as exc:
            last_err = exc
        time.sleep(interval_s)
    raise AssertionError(f"http GET {url} never returned 200 within {timeout_s}s (last_err={last_err})")


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account has no shared network VPC to attach the load balancer to")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not have subnets in at least 2 distinct AZs")
    return vpc_id, subnet_ids


def _create_open_http_sg(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    sg_name = ctx.unique_name("sim2real-behav-sg-")
    resp = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real behavioral check: allow inbound HTTP for ALB routing test",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": sg_name}]}],
    )
    sg_id = resp["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}],
    )
    return sg_id


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_lambda_function(ctx, role_arn, code_str):
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code_str)
    zip_bytes = buf.getvalue()
    resp = None
    last_err = None
    for _ in range(15):
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=10,
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded (IAM propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _deploy_cfn(ctx, template_body, parameters):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(StackName=stack_name, TemplateBody=template_body, Parameters=parameters)
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


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
