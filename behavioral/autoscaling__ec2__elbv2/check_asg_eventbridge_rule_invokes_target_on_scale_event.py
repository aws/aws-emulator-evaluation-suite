"""asg-eventbridge-rule-invokes-target-on-scale-event."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "asg-eventbridge-rule-invokes-target-on-scale-event"
GROUP = "event-propagation"
SERVICES = ["autoscaling", "ec2", "elbv2"]

_LAMBDA_CODE = """
import os
import boto3

def handler(event, context):
    table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
    detail = event.get("detail", {})
    table.put_item(Item={
        "pk": detail.get("EC2InstanceId", "unknown"),
        "asg": detail.get("AutoScalingGroupName", ""),
        "detail_type": event.get("detail-type", ""),
    })
    return {"ok": True}
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule matching Auto Scaling launch events invokes a Lambda function that
    receives the launched EC2InstanceId and AutoScalingGroupName and writes them to DynamoDB."""
    asg_name = ctx.unique_name("sim2real-asg-")
    _, subnet_id = _default_vpc_subnet(ctx)
    ami_id = _latest_al2023_ami(ctx)
    lt_id = _create_launch_template(ctx, ami_id)

    table_name, table_arn = _create_ddb_table(ctx)
    role_arn = _create_lambda_role(ctx, table_arn)
    fn_arn = _create_lambda_function(ctx, role_arn, table_name)

    events = ctx.client("events")
    lam = ctx.client("lambda")
    pattern = {
        "source": ["aws.autoscaling"],
        "detail-type": ["EC2 Instance Launch Successful"],
        "detail": {"AutoScalingGroupName": [asg_name]},
    }
    rule_name = ctx.unique_name("sim2real-rule-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    lam.add_permission(
        FunctionName=fn_arn,
        StatementId="AllowEventBridgeInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    events.put_targets(Rule=rule_name, Targets=[{"Id": "target-1", "Arn": fn_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["target-1"]))

    asg = ctx.client("autoscaling")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=1,
        MaxSize=1,
        DesiredCapacity=1,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": "true", "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(
        lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )

    instance_ids = _wait_for_in_service(ctx, asg_name, count=1, timeout_s=300.0)
    instance_id = instance_ids[0]

    ddb = ctx.client("dynamodb")
    item = _poll_until(
        lambda: ddb.get_item(TableName=table_name, Key={"pk": {"S": instance_id}}).get("Item"),
        lambda i: i is not None,
        timeout_s=180.0,
        interval_s=5.0,
        description=f"DynamoDB item for {instance_id} written by the invoked Lambda",
    )
    assert item["asg"]["S"] == asg_name, (
        f"expected the invoked Lambda to write AutoScalingGroupName={asg_name!r}, "
        f"got asg={item['asg']['S']!r}"
    )
    assert item["detail_type"]["S"] == "EC2 Instance Launch Successful", (
        "expected the invoked Lambda to have received detail-type="
        f"'EC2 Instance Launch Successful', got {item['detail_type']['S']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _default_vpc_subnet(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to launch a test instance into")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to launch a test instance into")
    return vpc_id, subnets[0]["SubnetId"]


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "true"}]}
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _wait_for_in_service(ctx, asg_name: str, count: int = 1, timeout_s: float = 300.0) -> list[str]:
    asg = ctx.client("autoscaling")

    def probe():
        groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ]
        if not groups:
            return []
        return [i["InstanceId"] for i in groups[0]["Instances"] if i["LifecycleState"] == "InService"]

    return _poll_until(
        probe,
        lambda ids: len(ids) >= count,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"{asg_name} InService instances",
    )


def _create_ddb_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-tbl-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    _poll_until(
        lambda: ddb.describe_table(TableName=table_name)["Table"]["TableStatus"],
        lambda s: s == "ACTIVE",
        timeout_s=60.0,
        interval_s=2.0,
        description=f"table {table_name} ACTIVE",
    )
    arn = ddb.describe_table(TableName=table_name)["Table"]["TableArn"]
    return table_name, arn


def _create_lambda_role(ctx, table_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    basic_exec_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn))

    policy_name = "dynamodb-put-item"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _lambda_zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda_function(ctx, role_arn: str, table_name: str) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _lambda_zip_bytes(_LAMBDA_CODE)

    deadline = time.monotonic() + 60.0
    last_err: Exception | None = None
    fn_arn = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": {"TABLE_NAME": table_name}},
                Tags={"sim2real": "true"},
            )
            fn_arn = resp["FunctionArn"]
            break
        except ClientError as exc:  # IAM role/trust not yet propagated
            last_err = exc
            time.sleep(3)
    if fn_arn is None:
        raise AssertionError(f"could not create Lambda function {fn_name}: {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=fn_name)["Configuration"]["State"],
        lambda s: s in ("Active", "Failed"),
        timeout_s=60.0,
        interval_s=3.0,
        description=f"lambda {fn_name} Active",
    )
    state = lam.get_function(FunctionName=fn_name)["Configuration"]["State"]
    if state != "Active":
        raise AssertionError(f"lambda {fn_name} reached state {state!r}, expected Active")
    return fn_arn


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
