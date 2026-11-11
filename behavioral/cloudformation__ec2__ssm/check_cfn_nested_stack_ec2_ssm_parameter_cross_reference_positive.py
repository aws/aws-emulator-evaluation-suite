"""cfn-nested-stack-ec2-ssm-parameter-cross-reference-positive."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-nested-stack-ec2-ssm-parameter-cross-reference-positive"
GROUP = "arn-resolution"
SERVICES = ["cloudformation", "ec2", "ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_INSTANCE_TYPE_VALUE = "t3.micro"


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:e2e",
    "plane:control",
)
def run(ctx) -> None:
    """A stack creates an SSM parameter and outputs its name; a sibling stack given only that name as
    an AWS::SSM::Parameter::Value<String> parameter launches an EC2 instance whose InstanceType equals
    the parameter's live value."""
    template_a = json.dumps(
        {
            "Parameters": {
                "InstanceTypeValue": {"Type": "String", "Default": _INSTANCE_TYPE_VALUE}
            },
            "Resources": {
                "TypeParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {"Ref": "InstanceTypeValue"},
                    },
                }
            },
            "Outputs": {
                "ParamName": {"Value": {"Ref": "TypeParam"}},
                "InstanceTypeValue": {"Value": {"Ref": "InstanceTypeValue"}},
            },
        }
    )
    stack_a = _deploy_cfn(ctx, template_a, timeout_s=180)
    param_name = stack_a["outputs"]["ParamName"]
    expected_instance_type = stack_a["outputs"]["InstanceTypeValue"]
    assert expected_instance_type == _INSTANCE_TYPE_VALUE

    template_b = json.dumps(
        {
            "Parameters": {
                "ImageId": {
                    "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                    "Default": _AMI_PARAM,
                },
                # No Default: the value is fed in below as an actual CreateStack Parameter,
                # simulating a caller wiring stack A's SSM-parameter-name Output into stack B.
                "InstanceTypeFromSsm": {"Type": "AWS::SSM::Parameter::Value<String>"},
            },
            "Resources": {
                "Instance": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": {"Ref": "ImageId"},
                        "InstanceType": {"Ref": "InstanceTypeFromSsm"},
                        "Tags": _xsvc_tags_kv(),
                        "SubnetId": ctx.network().subnet_ids[0],
                    },
                }
            },
            "Outputs": {"InstanceId": {"Value": {"Ref": "Instance"}}},
        }
    )
    stack_b = _deploy_cfn(
        ctx, template_b, parameters={"InstanceTypeFromSsm": param_name}, timeout_s=180
    )
    instance_id = stack_b["outputs"]["InstanceId"]

    ec2 = ctx.client("ec2")
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    actual_instance_type = resp["Reservations"][0]["Instances"][0]["InstanceType"]
    assert actual_instance_type == expected_instance_type

    ssm = ctx.client("ssm")
    live_value = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert live_value == expected_instance_type == actual_instance_type


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
