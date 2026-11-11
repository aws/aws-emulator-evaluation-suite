"""cfn-ec2-tag-propagation-to-ssm-inventory-positive."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-tag-propagation-to-ssm-inventory-positive"
GROUP = "data-format"
SERVICES = ["cloudformation", "ec2", "ssm"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:e2e",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A custom tag CloudFormation applies to an EC2 instance carries its exact value on the EC2 tag,
    and SSM's tag-based DescribeInstanceInformation filter on that tag returns exactly that instance,
    the resolution maintenance windows and associations use for targets."""
    ami_id = _latest_al2_ami(ctx)
    tag_key = "Sim2realEnv"
    tag_value = ctx.unique_name("env-")
    template = json.dumps(_tagged_instance_template(tag_key, tag_value, ctx=ctx))
    deployed = _deploy_cfn(ctx, template, parameters={"AmiId": ami_id}, timeout_s=600)
    instance_id = deployed["outputs"]["InstanceId"]

    ssm = ctx.client("ssm")
    _poll_until(
        lambda: ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"],
        lambda lst: len(lst) == 1 and lst[0]["PingStatus"] == "Online",
        timeout_s=420.0,
        interval_s=15.0,
        description="SSM managed-instance registration",
    )

    # 1) The EC2-side tag (the source of truth SSM reads for tag-based targeting) reflects the
    # CFN-applied tag exactly. (SSM's ListTagsForResource/ManagedInstance ResourceType is only
    # for on-premises hybrid nodes — "mi-*" IDs — not EC2-backed managed instances, so we assert
    # against the EC2 tag directly, which is what SSM's tag-based filters actually key off.)
    ec2 = ctx.client("ec2")
    ec2_tags = ec2.describe_tags(
        Filters=[
            {"Name": "resource-id", "Values": [instance_id]},
            {"Name": "key", "Values": [tag_key]},
        ]
    )["Tags"]
    tag_map = {t["Key"]: t["Value"] for t in ec2_tags}
    assert tag_map.get(tag_key) == tag_value, (
        f"expected EC2 tag {tag_key}={tag_value!r} on {instance_id}, got {tag_map.get(tag_key)!r}"
    )

    # 2) Filtering describe-instance-information by that same tag resolves this instance — the
    # exact mechanism tag-based association/maintenance-window targets rely on.
    filtered = ssm.describe_instance_information(
        Filters=[{"Key": f"tag:{tag_key}", "Values": [tag_value]}]
    )["InstanceInformationList"]
    got_ids = [i["InstanceId"] for i in filtered]
    assert got_ids == [instance_id], (
        f"expected describe_instance_information(tag:{tag_key}={tag_value!r}) to resolve to "
        f"[{instance_id!r}], got {got_ids!r}"
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


def _tagged_instance_template(tag_key: str, tag_value: str, *, ctx) -> dict:
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
                    "Tags": [
                        {"Key": "sim2real:managed", "Value": "true"},
                        {"Key": tag_key, "Value": tag_value},
                    ],
                    "SubnetId": ctx.network().subnet_ids[0],
                },
            },
        },
        "Outputs": {"InstanceId": {"Value": {"Ref": "Instance"}}},
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
