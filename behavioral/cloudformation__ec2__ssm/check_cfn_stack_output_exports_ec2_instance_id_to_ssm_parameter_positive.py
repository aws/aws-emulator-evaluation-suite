"""cfn-stack-output-exports-ec2-instance-id-to-ssm-parameter-positive."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-stack-output-exports-ec2-instance-id-to-ssm-parameter-positive"
GROUP = "arn-resolution"
SERVICES = ["cloudformation", "ec2", "ssm"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A stack creating an EC2 instance and an AWS::SSM::Parameter whose Value is !Ref <instance>
    stores the instance id: GetParameter returns the same i- id as the stack output, and EC2
    describes that instance as pending or running."""
    ami_id = _latest_al2_ami(ctx)
    param_name = _xname(ctx, "instance-id-param")
    template = json.dumps(_export_template(ctx))
    deployed = _deploy_cfn(
        ctx,
        template,
        parameters={"AmiId": ami_id, "ParamName": param_name},
        timeout_s=300,
    )
    instance_id_output = deployed["outputs"]["InstanceId"]

    ssm = ctx.client("ssm")
    stored = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert stored == instance_id_output, (
        f"SSM parameter {param_name!r} should hold the same instance id CFN reported as the "
        f"stack output, not a placeholder or unresolved reference string: "
        f"ssm={stored!r}, stack_output={instance_id_output!r}"
    )
    assert stored.startswith("i-"), (
        f"parameter value should be a real EC2 instance id: got {stored!r}"
    )

    ec2 = ctx.client("ec2")
    instance = ec2.describe_instances(InstanceIds=[instance_id_output])["Reservations"][
        0
    ]["Instances"][0]
    assert instance["InstanceId"] == instance_id_output, (
        f"EC2 itself should recognize the id CFN and SSM both reported as a real instance: "
        f"describe_instances returned {instance['InstanceId']!r}, expected {instance_id_output!r}"
    )
    assert instance["State"]["Name"] in {"pending", "running"}, (
        f"the id CFN exported and SSM stored should refer to a genuinely launched, "
        f"non-terminated EC2 instance, not a fabricated id: state={instance['State']['Name']!r}"
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


def _export_template(ctx) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "AmiId": {"Type": "String"},
            "ParamName": {"Type": "String"},
        },
        "Resources": {
            "Instance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": {"Ref": "AmiId"},
                    "InstanceType": "t3.micro",
                    "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
                    "SubnetId": ctx.network().subnet_ids[0],
                },
            },
            "InstanceIdParam": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": {"Ref": "ParamName"},
                    "Type": "String",
                    "Value": {"Ref": "Instance"},
                },
            },
        },
        "Outputs": {"InstanceId": {"Value": {"Ref": "Instance"}}},
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
