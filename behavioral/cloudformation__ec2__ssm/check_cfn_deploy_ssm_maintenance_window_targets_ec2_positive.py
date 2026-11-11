"""cfn-deploy-ssm-maintenance-window-targets-ec2-positive."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-ssm-maintenance-window-targets-ec2-positive"
GROUP = "event-propagation"
SERVICES = ["cloudformation", "ec2", "ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


# timing:real-time — schedule: 60 s https://docs.aws.amazon.com/systems-manager/latest/userguide/reference-cron-and-rate-expressions.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A CFN-defined SSM maintenance window fires its AUTOMATION task on schedule against a
    tagged EC2 instance, and the automation actually stops that instance."""
    tag_value = ctx.unique_name("mw-target-")
    template = json.dumps(
        {
            "Parameters": {
                "ImageId": {
                    "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                    "Default": _AMI_PARAM,
                }
            },
            "Resources": {
                "Instance": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": {"Ref": "ImageId"},
                        "InstanceType": "t3.micro",
                        # The tag-based INSTANCE target only resolves SSM-managed instances;
                        # without this profile every tick yields "No invocations to execute."
                        "IamInstanceProfile": {"Ref": "SsmInstanceProfile"},
                        "Tags": _xsvc_tags_kv()
                        + [{"Key": "sim2real-mw-target", "Value": tag_value}],
                        "SubnetId": ctx.network().subnet_ids[0],
                    },
                },
                "SsmInstanceRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "ec2.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
                        ],
                    },
                },
                "SsmInstanceProfile": {
                    "Type": "AWS::IAM::InstanceProfile",
                    "Properties": {"Roles": [{"Ref": "SsmInstanceRole"}]},
                },
                "MWRole": {
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
                "Target": {
                    "Type": "AWS::SSM::MaintenanceWindowTarget",
                    "Properties": {
                        "WindowId": {"Ref": "Window"},
                        "ResourceType": "INSTANCE",
                        "Targets": [
                            {"Key": "tag:sim2real-mw-target", "Values": [tag_value]}
                        ],
                    },
                },
                "Task": {
                    "Type": "AWS::SSM::MaintenanceWindowTask",
                    "Properties": {
                        "WindowId": {"Ref": "Window"},
                        "TaskArn": "AWS-StopEC2Instance",
                        "TaskType": "AUTOMATION",
                        "ServiceRoleArn": {"Fn::GetAtt": ["MWRole", "Arn"]},
                        "Priority": 1,
                        "MaxConcurrency": "1",
                        "MaxErrors": "1",
                        "Targets": [
                            {"Key": "WindowTargetIds", "Values": [{"Ref": "Target"}]}
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
                "InstanceId": {"Value": {"Ref": "Instance"}},
            },
        }
    )

    stack = _deploy_cfn(ctx, template, timeout_s=300)
    window_id = stack["outputs"]["WindowId"]
    instance_id = stack["outputs"]["InstanceId"]

    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    def _instance_state() -> str:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        return resp["Reservations"][0]["Instances"][0]["State"]["Name"]

    def _ssm_ping_status() -> str:
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"]
        return info[0]["PingStatus"] if info else "Unregistered"

    _poll_until(
        _ssm_ping_status,
        lambda s: s == "Online",
        timeout_s=300.0,
        interval_s=10.0,
        description="EC2 instance registered as an Online SSM managed instance "
        "(required for the window's tag-based INSTANCE target to resolve it)",
    )

    def _probe() -> dict[str, Any]:
        execs = ssm.describe_maintenance_window_executions(WindowId=window_id)[
            "WindowExecutions"
        ]
        tasks = []
        if execs:
            latest = sorted(execs, key=lambda e: e.get("StartTime") or "")[-1]
            tasks = ssm.describe_maintenance_window_execution_tasks(
                WindowExecutionId=latest["WindowExecutionId"]
            )["WindowExecutionTaskIdentities"]
        return {
            "instance_state": _instance_state(),
            "executions": [
                {"status": e.get("Status"), "detail": e.get("StatusDetails")}
                for e in execs
            ],
            "latest_tasks": [
                {
                    "status": t.get("Status"),
                    "detail": t.get("StatusDetails"),
                    "type": t.get("TaskType"),
                }
                for t in tasks
            ],
        }

    _poll_until(
        _probe,
        lambda r: r["instance_state"] == "stopped",
        timeout_s=420.0,
        interval_s=10.0,
        description="EC2 instance stopped by MW automation task",
    )

    execs = ssm.describe_maintenance_window_executions(WindowId=window_id)[
        "WindowExecutions"
    ]
    assert len(execs) >= 1, "maintenance window never fired an execution"


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
    from pathlib import Path

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
