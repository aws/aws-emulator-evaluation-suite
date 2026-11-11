"""cfn-ssm-maintenance-window-missing-service-role-negative."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-maintenance-window-missing-service-role-negative"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "ec2", "ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/systems-manager/latest/userguide/reference-cron-and-rate-expressions.html
@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "cap:c7",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A maintenance window task whose role ssm.amazonaws.com cannot assume leaves its instance
    running and fails with "maximum error count" and no invocation records, while a sibling task
    with a correctly trusted role stops its own instance (positive control)."""
    template = json.dumps(
        {
            "Parameters": {
                "ImageId": {
                    "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                    "Default": _AMI_PARAM,
                }
            },
            "Resources": {
                "InstanceGood": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": {"Ref": "ImageId"},
                        "InstanceType": "t3.micro",
                        "Tags": _xsvc_tags_kv()
                        + [{"Key": "sim2real-role-test", "Value": "good"}],
                        "SubnetId": ctx.network().subnet_ids[0],
                    },
                },
                "InstanceBad": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": {"Ref": "ImageId"},
                        "InstanceType": "t3.micro",
                        "Tags": _xsvc_tags_kv()
                        + [{"Key": "sim2real-role-test", "Value": "bad"}],
                        "SubnetId": ctx.network().subnet_ids[0],
                    },
                },
                "GoodRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "ssm.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/service-role/AmazonSSMMaintenanceWindowRole"
                        ],
                        "Policies": [
                            {
                                "PolicyName": "StopEc2",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "ec2:DescribeInstances",
                                                "ec2:DescribeInstanceStatus",
                                                "ec2:StopInstances",
                                            ],
                                            "Resource": "*",
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                # BadRole's trust policy never allows ssm.amazonaws.com to assume it, so
                # RegisterTaskWithMaintenanceWindow accepts the ARN (it is a syntactically
                # valid, existing role) but every invocation attempt fails at AssumeRole.
                "BadRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        }
                    },
                },
                "Window": {
                    "Type": "AWS::SSM::MaintenanceWindow",
                    "Properties": {
                        "Name": ctx.unique_name("sim2real-xsvc-mw-"),
                        "Schedule": "cron(0/1 * * * ? *)",
                        "Duration": 1,
                        "Cutoff": 0,
                        "AllowUnassociatedTargets": False,
                    },
                },
                "TargetGood": {
                    "Type": "AWS::SSM::MaintenanceWindowTarget",
                    "Properties": {
                        "WindowId": {"Ref": "Window"},
                        "ResourceType": "INSTANCE",
                        "Targets": [
                            {"Key": "InstanceIds", "Values": [{"Ref": "InstanceGood"}]}
                        ],
                    },
                },
                "TargetBad": {
                    "Type": "AWS::SSM::MaintenanceWindowTarget",
                    "Properties": {
                        "WindowId": {"Ref": "Window"},
                        "ResourceType": "INSTANCE",
                        "Targets": [
                            {"Key": "InstanceIds", "Values": [{"Ref": "InstanceBad"}]}
                        ],
                    },
                },
                "TaskGood": {
                    "Type": "AWS::SSM::MaintenanceWindowTask",
                    "Properties": {
                        "WindowId": {"Ref": "Window"},
                        "TaskArn": "AWS-StopEC2Instance",
                        "TaskType": "AUTOMATION",
                        "ServiceRoleArn": {"Fn::GetAtt": ["GoodRole", "Arn"]},
                        "Priority": 1,
                        "MaxConcurrency": "1",
                        "MaxErrors": "1",
                        "Targets": [
                            {
                                "Key": "WindowTargetIds",
                                "Values": [{"Ref": "TargetGood"}],
                            }
                        ],
                        "TaskInvocationParameters": {
                            "MaintenanceWindowAutomationParameters": {
                                "Parameters": {"InstanceId": ["{{RESOURCE_ID}}"]}
                            }
                        },
                    },
                },
                "TaskBad": {
                    "Type": "AWS::SSM::MaintenanceWindowTask",
                    "Properties": {
                        "WindowId": {"Ref": "Window"},
                        "TaskArn": "AWS-StopEC2Instance",
                        "TaskType": "AUTOMATION",
                        "ServiceRoleArn": {"Fn::GetAtt": ["BadRole", "Arn"]},
                        "Priority": 1,
                        "MaxConcurrency": "1",
                        "MaxErrors": "1",
                        "Targets": [
                            {"Key": "WindowTargetIds", "Values": [{"Ref": "TargetBad"}]}
                        ],
                        "TaskInvocationParameters": {
                            "MaintenanceWindowAutomationParameters": {
                                "Parameters": {"InstanceId": ["{{RESOURCE_ID}}"]}
                            }
                        },
                    },
                },
            },
            "Outputs": {
                "WindowId": {"Value": {"Ref": "Window"}},
                "InstanceGoodId": {"Value": {"Ref": "InstanceGood"}},
                "InstanceBadId": {"Value": {"Ref": "InstanceBad"}},
                "TaskBadId": {"Value": {"Ref": "TaskBad"}},
                "BadRoleArn": {"Value": {"Fn::GetAtt": ["BadRole", "Arn"]}},
            },
        }
    )

    stack = _deploy_cfn(ctx, template, timeout_s=300)
    window_id = stack["outputs"]["WindowId"]
    instance_good = stack["outputs"]["InstanceGoodId"]
    instance_bad = stack["outputs"]["InstanceBadId"]
    task_bad_id = stack["outputs"]["TaskBadId"]
    bad_role_arn = stack["outputs"]["BadRoleArn"]

    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    def _state(instance_id: str) -> str:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        return resp["Reservations"][0]["Instances"][0]["State"]["Name"]

    # positive control: the correctly-trusted role's task actually stops its instance.
    _poll_until(
        lambda: _state(instance_good),
        lambda s: s == "stopped",
        timeout_s=420.0,
        interval_s=10.0,
        description="positive-control instance stopped by the valid-role MW task",
    )

    # the bad-role task can never succeed (AssumeRole is permanently denied), so by the time
    # the good task has succeeded across several cron ticks, its instance is provably untouched.
    assert _state(instance_bad) == "running", (
        "bad-role task unexpectedly affected its instance"
    )

    # A task whose ServiceRoleArn cannot be assumed never creates a per-target invocation record;
    # the failure is visible only at the task-execution level, correlated by ServiceRole ARN
    # (both tasks share TaskArn AWS-StopEC2Instance, so TaskArn cannot disambiguate them).
    def _bad_task_execution():
        execs = ssm.describe_maintenance_window_executions(WindowId=window_id)[
            "WindowExecutions"
        ]
        for execution in execs:
            tasks = ssm.describe_maintenance_window_execution_tasks(
                WindowExecutionId=execution["WindowExecutionId"]
            )["WindowExecutionTaskIdentities"]
            for t in tasks:
                detail = ssm.get_maintenance_window_execution_task(
                    WindowExecutionId=execution["WindowExecutionId"],
                    TaskId=t["TaskExecutionId"],
                )
                if detail.get("ServiceRole") == bad_role_arn:
                    return execution["WindowExecutionId"], detail
        return None, None

    execution_id, detail = _poll_until(
        _bad_task_execution,
        lambda pair: pair[1] is not None and pair[1]["Status"] == "FAILED",
        timeout_s=180.0,
        interval_s=10.0,
        description="bad-role task execution recorded as FAILED (AssumeRole denied)",
    )
    status_details = (detail.get("StatusDetails") or "").lower()
    assert "maximum error count" in status_details, (
        f"expected the AssumeRole failure to exhaust MaxErrors, got StatusDetails={detail.get('StatusDetails')!r}"
    )

    bad_invocations = ssm.describe_maintenance_window_execution_task_invocations(
        WindowExecutionId=execution_id, TaskId=task_bad_id
    )["WindowExecutionTaskInvocationIdentities"]
    assert bad_invocations == [], (
        "an AssumeRole-denied maintenance-window task should never create a per-target "
        f"invocation record, got {bad_invocations}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
