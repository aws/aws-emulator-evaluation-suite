"""cfn-delete-stack-deregisters-ec2-from-ssm-positive."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-delete-stack-deregisters-ec2-from-ssm-positive"
GROUP = "deployment-order"
SERVICES = ["cloudformation", "ec2", "ssm"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:deploy",
    "concern:e2e",
    "plane:control",
)
def run(ctx) -> None:
    """Deleting a CFN stack terminates its EC2 instance, and its SSM managed-instance entry
    stops being an Online managed instance in DescribeInstanceInformation rather than lingering
    as a phantom Online entry."""
    ami_id = _latest_al2_ami(ctx)
    template = json.dumps(_ssm_instance_template(ctx))
    deployed = _deploy_cfn(ctx, template, parameters={"AmiId": ami_id}, timeout_s=600)
    stack_name = deployed["stack_name"]
    instance_id = deployed["outputs"]["InstanceId"]

    ssm = ctx.client("ssm")
    ec2 = ctx.client("ec2")
    _poll_until(
        lambda: ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"],
        lambda lst: len(lst) == 1 and lst[0]["PingStatus"] == "Online",
        timeout_s=420.0,
        interval_s=15.0,
        description="SSM managed-instance registration",
    )

    # Delete the stack now (on_cleanup registered by _deploy_cfn will no-op if this already
    # succeeded, and will still run the teardown if this assertion fails first).
    _delete_stack_and_wait(ctx, stack_name)

    ec2_state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
        "Instances"
    ][0]["State"]["Name"]
    assert ec2_state in {"terminated", "shutting-down"}, (
        f"expected instance {instance_id} terminated/shutting-down after stack delete, "
        f"got {ec2_state!r}"
    )

    remaining = _poll_until(
        lambda: ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"],
        lambda lst: lst == [] or lst[0]["PingStatus"] != "Online",
        timeout_s=300.0,
        interval_s=15.0,
        description="SSM managed-instance deregistration after stack delete",
    )
    if remaining:
        # PingStatus is a closed enum (Online | ConnectionLost | Inactive); pin the
        # non-Online member instead of re-asserting the poll's own exit predicate.
        assert remaining[0]["PingStatus"] in {"ConnectionLost", "Inactive"}, (
            f"expected a non-Online PingStatus from the modelled enum after "
            f"deregistration, got {remaining[0]['PingStatus']!r}"
        )


# ===== helpers =====
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
            if "does not exist" not in str(exc):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=180,
        interval_s=2.0,
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
