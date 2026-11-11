"""deploy-alb-cfn-then-target-health-behaves."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-alb-cfn-then-target-health-behaves"
GROUP = "deploy"
SERVICES = ["elbv2"]

_TEMPLATE = json.dumps(
    {
        "Parameters": {
            "SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"},
        },
        "Resources": {
            "Alb": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Type": "application",
                    "Scheme": "internal",
                    "Subnets": {"Ref": "SubnetIds"},
                },
            },
            "Tg": {
                "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                "Properties": {
                    "TargetType": "lambda",
                    "HealthCheckEnabled": True,
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
            "LoadBalancerArn": {"Value": {"Ref": "Alb"}},
            "TargetGroupArn": {"Value": {"Ref": "Tg"}},
            "ListenerArn": {"Value": {"Ref": "Listener"}},
        },
    }
)

_LAMBDA_CODE = (
    "def handler(event, context):\n"
    "    return {'statusCode': 200, 'body': 'ok', 'isBase64Encoded': False}\n"
)

_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A target registered directly against a CloudFormation-deployed lambda-type target group
    (behind an ALB + listener, also deployed by that same stack) transitions to healthy, and the
    deployed resources are visible/consistent through DescribeLoadBalancers/DescribeTargetGroups."""
    subnet_ids = _setup_network(ctx)
    role_arn = _create_lambda_role(ctx)
    lambda_arn = _create_lambda_function(ctx, role_arn, _LAMBDA_CODE)

    outputs = _deploy_cfn(
        ctx, _TEMPLATE, [{"ParameterKey": "SubnetIds", "ParameterValue": ",".join(subnet_ids)}]
    )
    lb_arn = outputs["LoadBalancerArn"]
    tg_arn = outputs["TargetGroupArn"]
    listener_arn = outputs["ListenerArn"]

    elbv2 = ctx.client("elbv2")

    lb = _poll_until(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0],
        lambda lb: lb["State"]["Code"] == "active",
        timeout_s=240,
        interval_s=10,
    )
    assert lb["State"]["Code"] == "active", f"expected active, got {lb['State']['Code']!r} for {lb_arn}"

    tg_before = elbv2.describe_target_groups(TargetGroupArns=[tg_arn])["TargetGroups"][0]
    assert lb_arn in tg_before["LoadBalancerArns"], (
        f"expected {lb_arn} in target group's LoadBalancerArns, got {tg_before['LoadBalancerArns']}"
    )

    listener = elbv2.describe_listeners(ListenerArns=[listener_arn])["Listeners"][0]
    default_action = listener["DefaultActions"][0]
    assert default_action["Type"] == "forward" and default_action["TargetGroupArn"] == tg_arn, (
        f"expected the CFN-created listener to forward to {tg_arn}, got {default_action!r}"
    )

    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=lambda_arn,
        StatementId="AllowElbInvoke",
        Action="lambda:InvokeFunction",
        Principal="elasticloadbalancing.amazonaws.com",
        SourceArn=tg_arn,
    )

    elbv2.register_targets(TargetGroupArn=tg_arn, Targets=[{"Id": lambda_arn}])

    def _health():
        resp = elbv2.describe_target_health(TargetGroupArn=tg_arn, Targets=[{"Id": lambda_arn}])
        return resp["TargetHealthDescriptions"][0]["TargetHealth"]["State"]

    state = _poll_until(_health, lambda s: s == "healthy", timeout_s=180, interval_s=5)
    assert state == "healthy", f"expected registered lambda target to become healthy, got {state!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _setup_network(ctx, num_subnets=2):
    """Adopt the shared network's subnets if it has enough distinct AZs; otherwise create our own."""
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ])["Subnets"]
        by_az: dict[str, str] = {}
        for s in sorted(subnets, key=lambda s: s["SubnetId"]):
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        subnet_ids = [by_az[az] for az in sorted(by_az)][:num_subnets]
        if len(subnet_ids) >= num_subnets:
            return subnet_ids

    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": _TAGS_KV}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
    if len(azs) < num_subnets:
        raise AssertionError(f"region has only {len(azs)} available AZ(s), need {num_subnets}")
    subnet_ids = []
    for i in range(num_subnets):
        az = azs[i]["ZoneName"]
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.0.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _TAGS_KV}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: ec2.delete_subnet(SubnetId=sid))
    return subnet_ids


def _create_lambda_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAGS_KV
    )["Role"]["Arn"]
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
                Tags={kv["Key"]: kv["Value"] for kv in _TAGS_KV},
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

    cfn.create_stack(
        StackName=stack_name, TemplateBody=template_body, Parameters=parameters, Tags=_TAGS_KV
    )
    ctx.on_cleanup(_cleanup)
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
    except Exception as exc:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        failures = [
            f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
            for e in events
            if e.get("ResourceStatus", "").endswith("FAILED") and "cancelled" not in e.get("ResourceStatusReason", "")
        ]
        reason = failures[0] if failures else "?"
        raise AssertionError(f"REASON={reason}") from exc
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
