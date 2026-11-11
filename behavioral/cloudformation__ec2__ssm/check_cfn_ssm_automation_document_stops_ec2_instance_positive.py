"""cfn-ssm-automation-document-stops-ec2-instance-positive."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-automation-document-stops-ec2-instance-positive"
GROUP = "event-propagation"
SERVICES = ["cloudformation", "ec2", "ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A custom SSM Automation document deployed by CFN (aws:changeInstanceState -> stopped),
    when executed via StartAutomationExecution, actually stops the real target EC2 instance."""
    template = json.dumps(
        {
            "Parameters": {
                "ImageId": {
                    "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                    "Default": _AMI_PARAM,
                }
            },
            "Resources": {
                "AutomationRole": {
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
                "Instance": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": {"Ref": "ImageId"},
                        "InstanceType": "t3.micro",
                        "Tags": _xsvc_tags_kv(),
                        "SubnetId": ctx.network().subnet_ids[0],
                    },
                },
                "StopDoc": {
                    "Type": "AWS::SSM::Document",
                    "Properties": {
                        "Name": ctx.unique_name("sim2real-xsvc-stopdoc-"),
                        "DocumentType": "Automation",
                        "Content": {
                            "schemaVersion": "0.3",
                            "parameters": {
                                "InstanceId": {"type": "String"},
                                "AutomationAssumeRole": {
                                    "type": "String",
                                    "default": {
                                        "Fn::GetAtt": ["AutomationRole", "Arn"]
                                    },
                                },
                            },
                            "mainSteps": [
                                {
                                    "name": "stopInstance",
                                    "action": "aws:changeInstanceState",
                                    "maxAttempts": 3,
                                    "timeoutSeconds": 180,
                                    "onFailure": "Abort",
                                    "inputs": {
                                        "InstanceIds": ["{{ InstanceId }}"],
                                        "DesiredState": "stopped",
                                    },
                                }
                            ],
                        },
                    },
                },
            },
            "Outputs": {
                "InstanceId": {"Value": {"Ref": "Instance"}},
                "DocumentName": {"Value": {"Ref": "StopDoc"}},
            },
        }
    )

    stack = _deploy_cfn(ctx, template, timeout_s=240)
    instance_id = stack["outputs"]["InstanceId"]
    doc_name = stack["outputs"]["DocumentName"]

    ssm = ctx.client("ssm")
    execution_id = ssm.start_automation_execution(
        DocumentName=doc_name, Parameters={"InstanceId": [instance_id]}
    )["AutomationExecutionId"]

    status = _poll_until(
        lambda: ssm.get_automation_execution(AutomationExecutionId=execution_id)[
            "AutomationExecution"
        ]["AutomationExecutionStatus"],
        lambda s: s in {"Success", "Failed", "TimedOut", "Cancelled"},
        timeout_s=240.0,
        interval_s=5.0,
        description="automation execution reaches a terminal status",
    )
    assert status == "Success", f"automation ended in {status}"

    ec2 = ctx.client("ec2")

    def _state() -> str:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        return resp["Reservations"][0]["Instances"][0]["State"]["Name"]

    final_state = _poll_until(
        _state,
        lambda s: s == "stopped",
        timeout_s=120.0,
        interval_s=5.0,
        description="EC2 instance transitions to stopped",
    )
    assert final_state == "stopped", (
        f"expected instance {instance_id} to be stopped, got {final_state}"
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
