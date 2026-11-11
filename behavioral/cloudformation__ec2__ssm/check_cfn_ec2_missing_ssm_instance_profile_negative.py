"""cfn-ec2-missing-ssm-instance-profile-negative."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-missing-ssm-instance-profile-negative"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "ec2", "ssm"]


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:e2e",
    "plane:control",
)
def run(ctx) -> None:
    """An EC2 instance a stack launches without an SSM-enabled instance profile is absent from SSM's
    managed instances, while a sibling instance in the same stack with the profile registers Online
    (positive control), so the missing profile is the cause."""
    ami_id = _latest_al2_ami(ctx)
    template = json.dumps(_two_instance_template(ctx))
    deployed = _deploy_cfn(ctx, template, parameters={"AmiId": ami_id}, timeout_s=600)
    with_profile_id = deployed["outputs"]["WithProfileInstanceId"]
    without_profile_id = deployed["outputs"]["WithoutProfileInstanceId"]

    ssm = ctx.client("ssm")

    # Positive control: the instance WITH the SSM profile registers Online.
    info = _poll_until(
        lambda: ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [with_profile_id]}]
        )["InstanceInformationList"],
        lambda lst: len(lst) == 1 and lst[0]["PingStatus"] == "Online",
        timeout_s=420.0,
        interval_s=15.0,
        description="control instance SSM registration",
    )
    assert info[0]["PingStatus"] == "Online", (
        f"control instance {with_profile_id} (WITH SSM instance profile) expected PingStatus "
        f"'Online', got {info[0]['PingStatus']!r}"
    )

    # Negative: the instance WITHOUT a profile is given the same generous window and never
    # shows up at all — the effect (registration) is absent, not merely delayed.
    absent = ssm.describe_instance_information(
        Filters=[{"Key": "InstanceIds", "Values": [without_profile_id]}]
    )["InstanceInformationList"]
    assert absent == [], (
        f"instance {without_profile_id} (WITHOUT SSM instance profile) expected to be absent "
        f"from describe_instance_information, got {absent!r}"
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


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind: str) -> str:
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
        timeout_s=180,
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
    timeout_s=600.0,
):
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    kwargs = {
        "StackName": name,
        "TemplateBody": template,
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


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _two_instance_template(ctx) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"AmiId": {"Type": "String"}},
        "Resources": {
            "SsmRole": {
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
                    "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
                },
            },
            "SsmInstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {"Roles": [{"Ref": "SsmRole"}]},
            },
            "WithProfileInstance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": {"Ref": "AmiId"},
                    "InstanceType": "t3.micro",
                    "IamInstanceProfile": {"Ref": "SsmInstanceProfile"},
                    "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
                    "SubnetId": ctx.network().subnet_ids[0],
                },
            },
            "WithoutProfileInstance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": {"Ref": "AmiId"},
                    "InstanceType": "t3.micro",
                    "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
                    "SubnetId": ctx.network().subnet_ids[0],
                },
            },
        },
        "Outputs": {
            "WithProfileInstanceId": {"Value": {"Ref": "WithProfileInstance"}},
            "WithoutProfileInstanceId": {"Value": {"Ref": "WithoutProfileInstance"}},
        },
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
