"""cfn-update-ec2-instance-type-triggers-ssm-reregistration-positive."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-update-ec2-instance-type-triggers-ssm-reregistration-positive"
GROUP = "deployment-order"
SERVICES = ["cloudformation", "ec2", "ssm"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:e2e",
    "plane:control",
)
def run(ctx) -> None:
    """A stack update changing an EC2 instance's AMI replaces the instance: the update completes, the
    old instance id is terminated or shutting down, and the new, different id registers with SSM as a
    managed instance."""
    old_ami = _latest_al2_ami(ctx)
    new_ami = _latest_al2023_ami(ctx)
    if old_ami == new_ami:
        raise AssertionError(
            "AL2 and AL2023 latest AMI ids resolved identically in this region"
        )

    template = json.dumps(_ssm_instance_template(ctx))
    deployed = _deploy_cfn(ctx, template, parameters={"AmiId": old_ami}, timeout_s=600)
    stack_name = deployed["stack_name"]
    old_instance_id = deployed["outputs"]["InstanceId"]

    ssm = ctx.client("ssm")
    ec2 = ctx.client("ec2")
    _poll_until(
        lambda: ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [old_instance_id]}]
        )["InstanceInformationList"],
        lambda lst: len(lst) == 1 and lst[0]["PingStatus"] == "Online",
        timeout_s=420.0,
        interval_s=15.0,
        description="original instance SSM registration",
    )

    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[{"ParameterKey": "AmiId", "ParameterValue": new_ami}],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "UPDATE_COMPLETE",
                "UPDATE_FAILED",
                "UPDATE_ROLLBACK_COMPLETE",
                "UPDATE_ROLLBACK_FAILED",
            }
        ),
        timeout_s=600.0,
        interval_s=10.0,
        description="stack update",
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"expected UPDATE_COMPLETE after AMI change, got {stack['StackStatus']!r}"
    )
    new_instance_id = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}[
        "InstanceId"
    ]
    assert new_instance_id != old_instance_id, (
        f"expected a replacement instance id, got the same id back: {new_instance_id!r}"
    )

    # The old instance is actually gone (terminated), not merely left running under the old id.
    old_state = _poll_until(
        lambda: ec2.describe_instances(InstanceIds=[old_instance_id])["Reservations"][
            0
        ]["Instances"][0]["State"]["Name"],
        lambda s: s in {"terminated", "shutting-down"},
        timeout_s=180.0,
        interval_s=10.0,
        description="old instance termination",
    )
    assert old_state in {"terminated", "shutting-down"}, (
        f"expected the replaced instance {old_instance_id!r} to be terminating, got state {old_state!r}"
    )

    # The new instance registers as a brand-new managed instance.
    new_info = _poll_until(
        lambda: ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [new_instance_id]}]
        )["InstanceInformationList"],
        lambda lst: len(lst) == 1 and lst[0]["PingStatus"] == "Online",
        timeout_s=420.0,
        interval_s=15.0,
        description="replacement instance SSM registration",
    )
    assert new_info[0]["InstanceId"] == new_instance_id, (
        f"expected SSM to report the replacement instance {new_instance_id!r}, "
        f"got {new_info[0]['InstanceId']!r}"
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


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _ssm_instance_template(ctx) -> dict:
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
                },
            },
            "SsmInstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {"Roles": [{"Ref": "SsmRole"}]},
            },
            "Instance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": {"Ref": "AmiId"},
                    "InstanceType": "t3.micro",
                    "IamInstanceProfile": {"Ref": "SsmInstanceProfile"},
                    "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
                    "SubnetId": ctx.network().subnet_ids[0],
                },
            },
        },
        "Outputs": {"InstanceId": {"Value": {"Ref": "Instance"}}},
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
