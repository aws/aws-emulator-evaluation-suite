"""deploy-ec2-flow-log-missing-deliver-logs-permission-arn-rejected-and-rolled-back."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-ec2-flow-log-missing-deliver-logs-permission-arn-rejected-and-rolled-back"
GROUP = "deploy-ec2-resource-sweep"
SERVICES = ["cloudformation", "ec2", "iam", "logs"]

_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)
_REJECTED_MESSAGE = (
    "DeliverLogsPermissionArn can't be empty if LogDestinationType is cloud-watch-logs. "
    "(Service: Ec2, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)"
)
_REJECTED = (_REJECTED_MESSAGE, "InvalidRequest")
_DELIVER_STATUS_POLL_S = 120.0


def _masked(text: str) -> str:
    text = re.sub(r"Request ID: [^,;)]+", "Request ID: <id>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    return text


def _handler_reason(reason: str | None) -> tuple[str, str]:
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return _masked(m["message"]), m["code"]


def _bad_template(vpc_cidr: str) -> dict[str, Any]:
    """Declares a cloud-watch-logs FlowLog with no DeliverLogsPermissionArn."""
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": vpc_cidr}},
            "LogGroup": {"Type": "AWS::Logs::LogGroup", "Properties": {"RetentionInDays": 1}},
            "FlowLog": {
                "Type": "AWS::EC2::FlowLog",
                "Properties": {
                    "ResourceId": {"Ref": "Vpc"},
                    "ResourceType": "VPC",
                    "TrafficType": "ALL",
                    "LogDestinationType": "cloud-watch-logs",
                    "LogGroupName": {"Ref": "LogGroup"},
                },
            },
        },
    }


def _good_template(vpc_cidr: str) -> dict[str, Any]:
    """The legal neighbor: the same shape, with a role and DeliverLogsPermissionArn set."""
    t = _bad_template(vpc_cidr)
    t["Resources"]["Role"] = {
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
                    "PolicyName": "sim2real-xsvc-flowlogneg-cwl",
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
    }
    t["Resources"]["FlowLog"]["Properties"]["DeliverLogsPermissionArn"] = {
        "Fn::GetAtt": ["Role", "Arn"]
    }
    t["Outputs"] = {
        "FlowLogId": {"Value": {"Ref": "FlowLog"}},
        "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
    }
    return t


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


def _failed_reason(cfn, stack_id: str, logical_id: str, status: str = "CREATE_FAILED") -> str:
    events = [
        e
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
        for e in page["StackEvents"]
    ]
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def _poll_flow_log(
    ec2, flow_log_id: str, timeout_s: float = _DELIVER_STATUS_POLL_S
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while True:
        fl = ec2.describe_flow_logs(FlowLogIds=[flow_log_id])["FlowLogs"][0]
        if fl.get("DeliverLogsStatus") or time.monotonic() > deadline:
            return fl
        time.sleep(2)


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CFN AWS::EC2::FlowLog to CloudWatch Logs with no DeliverLogsPermissionArn fails with
    EC2's exact error and the rollback deletes the log group and VPC; the same shape naming a role
    the stack created deploys a flow log EC2 reads back with that role's ARN."""
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    bad_stack = ctx.unique_name("sim2real-flowlogneg-")
    bad_stack_id = cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=json.dumps(_bad_template("10.89.0.0/16")),
        Tags=[{"Key": "sim2real", "Value": bad_stack}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, bad_stack_id))

    status = _wait_create(cfn, bad_stack_id)["StackStatus"]
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )
    got = _handler_reason(_failed_reason(cfn, bad_stack_id, "FlowLog"))
    assert got == _REJECTED, f"CREATE_FAILED reason: expected {_REJECTED!r}, got {got!r}"

    resources = cfn.describe_stack_resources(StackName=bad_stack_id)["StackResources"]
    vpc_id = next(
        r["PhysicalResourceId"] for r in resources if r["ResourceType"] == "AWS::EC2::VPC"
    )
    log_group_name = next(
        r["PhysicalResourceId"] for r in resources if r["ResourceType"] == "AWS::Logs::LogGroup"
    )
    vpc_gone = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
    _expect_error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), *vpc_gone)
    groups = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
    assert not any(g["logGroupName"] == log_group_name for g in groups), (
        f"the rollback must remove log group {log_group_name!r}; it is still listed: {groups!r}"
    )
    _delete_stack_and_wait(cfn, bad_stack_id)

    # Positive control: the legal neighbor (a role, DeliverLogsPermissionArn set) deploys.
    good_stack = ctx.unique_name("sim2real-flowlogneg-")
    good_stack_id = cfn.create_stack(
        StackName=good_stack,
        TemplateBody=json.dumps(_good_template("10.90.0.0/16")),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": good_stack}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, good_stack_id))
    good_status = _wait_create(cfn, good_stack_id)
    assert good_status["StackStatus"] == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status['StackStatus']!r}, expected "
        f"CREATE_COMPLETE"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in good_status.get("Outputs", [])}
    fl = _poll_flow_log(ec2, outputs["FlowLogId"])
    assert fl["DeliverLogsPermissionArn"] == outputs["RoleArn"], (
        f"expected DeliverLogsPermissionArn {outputs['RoleArn']!r}, EC2 reports "
        f"{fl['DeliverLogsPermissionArn']!r}"
    )
    role_name = outputs["RoleArn"].rsplit("/", 1)[-1]
    role = iam.get_role(RoleName=role_name)["Role"]
    assert role["Arn"] == outputs["RoleArn"], (
        f"IAM reports role Arn {role['Arn']!r}, expected {outputs['RoleArn']!r}"
    )


def _expect_error(fn, code: str, message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code!r} but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
