"""deploy-ec2-flow-log-deliver-logs-permission-arn-to-cloudwatch-logs-round-trip-and-delete."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-ec2-flow-log-deliver-logs-permission-arn-to-cloudwatch-logs-round-trip-and-delete"
GROUP = "deploy-cfn-resource-existence"
SERVICES = ["cloudformation", "ec2", "iam", "logs"]

VPC_BLOCK = "10.88.0.0/16"
_DELIVER_STATUS_POLL_S = 120.0


def _template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": VPC_BLOCK}},
            "LogGroup": {"Type": "AWS::Logs::LogGroup", "Properties": {"RetentionInDays": 1}},
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "sim2real-xsvc-flowlog-cwl",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
                                            "logs:DescribeLogGroups",
                                            "logs:DescribeLogStreams",
                                        ],
                                        "Resource": {"Fn::GetAtt": ["LogGroup", "Arn"]},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "FlowLog": {
                "Type": "AWS::EC2::FlowLog",
                "Properties": {
                    "ResourceId": {"Ref": "Vpc"},
                    "ResourceType": "VPC",
                    "TrafficType": "ALL",
                    "LogDestinationType": "cloud-watch-logs",
                    "LogGroupName": {"Ref": "LogGroup"},
                    "DeliverLogsPermissionArn": {"Fn::GetAtt": ["Role", "Arn"]},
                },
            },
        },
        "Outputs": {
            "FlowLogId": {"Value": {"Ref": "FlowLog"}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            "LogGroupName": {"Value": {"Ref": "LogGroup"}},
        },
    }


def _wait_create(cfn, stack_id: str, max_attempts: int = 300) -> dict[str, Any]:
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts}
        )
    except WaiterError:
        pass
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _delete_stack_and_wait(cfn, stack_id: str, max_attempts: int = 300) -> None:
    cfn.delete_stack(StackName=stack_id)
    try:
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts}
        )
    except WaiterError:
        pass
    final = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    if final["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(
            f"stack {stack_id} delete ended {final['StackStatus']!r}: "
            f"{final.get('StackStatusReason')!r}"
        )


def _poll_flow_log(
    ec2, flow_log_id: str, timeout_s: float = _DELIVER_STATUS_POLL_S
) -> dict[str, Any]:
    """Poll DescribeFlowLogs until DeliverLogsStatus leaves the empty/absent starting state."""
    deadline = time.monotonic() + timeout_s
    while True:
        fl = ec2.describe_flow_logs(FlowLogIds=[flow_log_id])["FlowLogs"][0]
        if fl.get("DeliverLogsStatus") or time.monotonic() > deadline:
            return fl
        time.sleep(2)


def _expect_error(fn, code: str, message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code!r} but the call succeeded: {result!r}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN AWS::EC2::FlowLog to CloudWatch Logs declaring DeliverLogsPermissionArn reads back
    through DescribeFlowLogs with the stack's role ARN and log group; deleting the stack deletes
    the flow log, the role and the log group."""
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    logs = ctx.client("logs")

    name = ctx.unique_name("sim2real-xsvc-flowlogcwl-")
    stack_id = cfn.create_stack(
        StackName=name,
        TemplateBody=json.dumps(_template()),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    stack = _wait_create(cfn, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), "
        f"expected 'CREATE_COMPLETE'"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    flow_log_id, role_arn, log_group_name = (
        outputs["FlowLogId"],
        outputs["RoleArn"],
        outputs["LogGroupName"],
    )

    fl = _poll_flow_log(ec2, flow_log_id)
    assert fl["DeliverLogsPermissionArn"] == role_arn, (
        f"EC2 reports DeliverLogsPermissionArn {fl['DeliverLogsPermissionArn']!r}, expected the "
        f"stack's role {role_arn!r}"
    )
    assert fl["LogDestinationType"] == "cloud-watch-logs", (
        f"EC2 reports LogDestinationType {fl['LogDestinationType']!r}, expected 'cloud-watch-logs'"
    )
    assert fl["LogGroupName"] == log_group_name, (
        f"EC2 reports LogGroupName {fl['LogGroupName']!r}, expected {log_group_name!r}"
    )
    assert (
        fl["ResourceId"]
        == cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Vpc")[
            "StackResourceDetail"
        ]["PhysicalResourceId"]
    ), f"EC2 reports ResourceId {fl['ResourceId']!r}, expected the stack's VPC"

    role_name = role_arn.rsplit("/", 1)[-1]
    role = iam.get_role(RoleName=role_name)["Role"]
    assert role["Arn"] == role_arn, f"IAM reports role Arn {role['Arn']!r}, expected {role_arn!r}"
    groups = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
    assert [g["logGroupName"] for g in groups if g["logGroupName"] == log_group_name] == [
        log_group_name
    ], f"CloudWatch Logs does not list the stack's log group {log_group_name!r}: {groups!r}"

    _delete_stack_and_wait(cfn, stack_id)
    flow_log_gone = ec2.describe_flow_logs(FlowLogIds=[flow_log_id])["FlowLogs"]
    assert flow_log_gone == [], (
        f"expected no flow log for {flow_log_id!r} once the stack is deleted, EC2 reports "
        f"{flow_log_gone!r}"
    )
    role_gone = ("NoSuchEntity", f"The role with name {role_name} cannot be found.")
    _expect_error(lambda: iam.get_role(RoleName=role_name), *role_gone)
    groups_after = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
    assert not any(g["logGroupName"] == log_group_name for g in groups_after), (
        f"expected no log group named {log_group_name!r} once the stack is deleted, CloudWatch "
        f"Logs still lists {groups_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
