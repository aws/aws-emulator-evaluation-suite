"""cfn-ssm-maintenance-window-registers-ec2-target-positive."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-maintenance-window-registers-ec2-target-positive"
GROUP = "event-propagation"
SERVICES = ["cloudformation", "ec2", "ssm"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CFN-created SSM Maintenance Window registers its tag-based EC2 target, and the stored tag
    filter resolves to the tagged instance via SSM DescribeInstanceInformation."""
    ami_id = _latest_al2_ami(ctx)
    tag_key = "Sim2realMwTarget"
    tag_value = ctx.unique_name("mw-")
    template = json.dumps(_maintenance_window_template(tag_key, tag_value, ctx=ctx))
    deployed = _deploy_cfn(ctx, template, parameters={"AmiId": ami_id}, timeout_s=600)
    instance_id = deployed["outputs"]["InstanceId"]
    window_id = deployed["outputs"]["WindowId"]

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

    window_targets = ssm.describe_maintenance_window_targets(WindowId=window_id)[
        "Targets"
    ]
    assert len(window_targets) == 1, (
        f"expected exactly 1 target on window {window_id}, got {len(window_targets)}: {window_targets!r}"
    )
    stored_targets = window_targets[0]["Targets"]
    expected_targets = [{"Key": f"tag:{tag_key}", "Values": [tag_value]}]
    assert stored_targets == expected_targets, (
        f"expected stored Targets {expected_targets!r}, got {stored_targets!r}"
    )

    # The tag definition the window stores resolves, through SSM's own tag filter, to exactly
    # this instance — proving the target actually matches, not just that a row was stored.
    resolved = ssm.describe_instance_information(
        Filters=[{"Key": f"tag:{tag_key}", "Values": [tag_value]}]
    )["InstanceInformationList"]
    resolved_ids = [i["InstanceId"] for i in resolved]
    assert resolved_ids == [instance_id], (
        f"tag:{tag_key}={tag_value} should resolve to exactly [{instance_id}] via "
        f"describe_instance_information, got {resolved_ids!r}"
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


def _maintenance_window_template(tag_key: str, tag_value: str, *, ctx) -> dict:
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
            "MaintenanceWindow": {
                "Type": "AWS::SSM::MaintenanceWindow",
                "Properties": {
                    "Name": "sim2real-mw",
                    "Schedule": "cron(0 12 * * ? *)",
                    "Duration": 2,
                    "Cutoff": 1,
                    "AllowUnassociatedTargets": False,
                },
            },
            "MaintenanceWindowTarget": {
                "Type": "AWS::SSM::MaintenanceWindowTarget",
                "Properties": {
                    "WindowId": {"Ref": "MaintenanceWindow"},
                    "ResourceType": "INSTANCE",
                    "Targets": [{"Key": f"tag:{tag_key}", "Values": [tag_value]}],
                },
            },
        },
        "Outputs": {
            "InstanceId": {"Value": {"Ref": "Instance"}},
            "WindowId": {"Value": {"Ref": "MaintenanceWindow"}},
        },
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
