"""deploy-ec2-launch-template-read-back-and-removed."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-ec2-launch-template-read-back-and-removed"
GROUP = "deploy-cfn-resource-existence"
SERVICES = ["cloudformation", "ec2"]

INSTANCE_TYPE = "t3.micro"
AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


def _template(name: str) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Ami": {"Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                     "Default": AMI_PARAMETER},
        },
        "Resources": {
            "Lt": {"Type": "AWS::EC2::LaunchTemplate", "Properties": {
                "LaunchTemplateName": name,
                "LaunchTemplateData": {
                    "ImageId": {"Ref": "Ami"},
                    "InstanceType": INSTANCE_TYPE,
                },
            }},
        },
        "Outputs": {
            "LaunchTemplateId": {"Value": {"Ref": "Lt"}},
            "DefaultVersionNumber": {"Value": {"Fn::GetAtt": ["Lt", "DefaultVersionNumber"]}},
            "LatestVersionNumber": {"Value": {"Fn::GetAtt": ["Lt", "LatestVersionNumber"]}},
        },
    }


def _wait_create(cfn, stack_id: str, max_attempts: int = 150) -> dict[str, Any]:
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts})
    except WaiterError:
        pass
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _delete_stack_and_wait(cfn, stack_id: str, max_attempts: int = 150) -> None:
    cfn.delete_stack(StackName=stack_id)
    try:
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts})
    except WaiterError:
        pass
    final = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    if final["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(
            f"stack {stack_id} delete ended {final['StackStatus']!r}: "
            f"{final.get('StackStatusReason')!r}"
        )


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-created launch template reads back through EC2's DescribeLaunchTemplates and
    DescribeLaunchTemplateVersions with every property and Fn::GetAtt value the template carries,
    and deleting the stack makes EC2 answer the template id with its own NotFound.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    expected_ami = ssm.get_parameter(Name=AMI_PARAMETER)["Parameter"]["Value"]

    name = ctx.unique_name("sim2real-xsvc-lt-")
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=json.dumps(_template(name)),
        Tags=[{"Key": "sim2real", "Value": name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    stack = _wait_create(cfn, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), "
        f"expected 'CREATE_COMPLETE'"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    lt_id = outputs["LaunchTemplateId"]

    resolved_ami_param = next(
        p["ResolvedValue"] for p in stack["Parameters"] if p["ParameterKey"] == "Ami")
    assert resolved_ami_param == expected_ami, (
        f"the stack resolved {AMI_PARAMETER!r} to {resolved_ami_param!r}, but SSM itself answers "
        f"{expected_ami!r} for the same parameter"
    )

    lt = ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])["LaunchTemplates"][0]
    assert lt["LaunchTemplateName"] == name, (
        f"EC2 reports launch template name {lt['LaunchTemplateName']!r}, expected {name!r}"
    )
    assert str(lt["DefaultVersionNumber"]) == outputs["DefaultVersionNumber"], (
        f"EC2's DefaultVersionNumber {lt['DefaultVersionNumber']!r} disagrees with the stack's "
        f"Fn::GetAtt value {outputs['DefaultVersionNumber']!r}"
    )
    assert str(lt["LatestVersionNumber"]) == outputs["LatestVersionNumber"], (
        f"EC2's LatestVersionNumber {lt['LatestVersionNumber']!r} disagrees with the stack's "
        f"Fn::GetAtt value {outputs['LatestVersionNumber']!r}"
    )

    version = ec2.describe_launch_template_versions(
        LaunchTemplateId=lt_id, Versions=["$Latest"])["LaunchTemplateVersions"][0]
    data = version["LaunchTemplateData"]
    assert data["ImageId"] == expected_ami, (
        f"the launch template's ImageId is {data['ImageId']!r}, expected the resolved AMI "
        f"{expected_ami!r}"
    )
    assert data["InstanceType"] == INSTANCE_TYPE, (
        f"the launch template's InstanceType is {data['InstanceType']!r}, expected "
        f"{INSTANCE_TYPE!r}"
    )

    _delete_stack_and_wait(cfn, stack_id)
    code, message = _error(lambda: ec2.describe_launch_templates(LaunchTemplateIds=[lt_id]))
    assert code == "InvalidLaunchTemplateId.NotFound", (
        f"expected InvalidLaunchTemplateId.NotFound once the stack is deleted, got {code}: "
        f"{message!r}"
    )
    assert message == "At least one of the launch templates specified in the request does not exist.", (
        f"unexpected message {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
