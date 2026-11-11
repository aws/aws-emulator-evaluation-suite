"""deploy-ec2-launch-template-duplicate-name-rejected."""
from __future__ import annotations

import json
import re
from typing import Any

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-ec2-launch-template-duplicate-name-rejected"
GROUP = "deploy-cfn-resource-existence"
SERVICES = ["cloudformation", "ec2"]

INSTANCE_TYPE = "t3.micro"
AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"

# EC2's error as the launch-template handler relays it, optionally inside CloudFormation's
# resource-handler wrapper; the request id and token vary.
_REASON = re.compile(
    r'^(?:Resource handler returned message: ")?(?P<message>.*) \(Service: [A-Za-z0-9]+; '
    r"Status Code: (?P<status>\d+); Error Code: (?P<code>[A-Za-z0-9.]+); Request ID: [^;)]*; "
    r'Proxy: null\)(?:" \(RequestToken: [^,]*, HandlerErrorCode: [A-Za-z]+\))?$'
)


def _template(launch_template_name: str) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Ami": {"Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                     "Default": AMI_PARAMETER},
        },
        "Resources": {
            "Lt": {"Type": "AWS::EC2::LaunchTemplate", "Properties": {
                "LaunchTemplateName": launch_template_name,
                "LaunchTemplateData": {"ImageId": {"Ref": "Ami"}, "InstanceType": INSTANCE_TYPE},
            }},
        },
        "Outputs": {"LaunchTemplateId": {"Value": {"Ref": "Lt"}}},
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


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes mean
    the resource is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN launch template naming an already-registered LaunchTemplateName is rejected by EC2
    and the stack creates no launch template of its own; the identical template under a name EC2
    has never seen succeeds.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    taken_name = ctx.unique_name("sim2real-xsvc-ltdup-")
    pre_existing = ec2.create_launch_template(
        LaunchTemplateName=taken_name, LaunchTemplateData={"InstanceType": INSTANCE_TYPE})
    pre_existing_id = pre_existing["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(_teardown(
        lambda: ec2.delete_launch_template(LaunchTemplateId=pre_existing_id),
        "InvalidLaunchTemplateId.NotFound"))

    stack_name = ctx.unique_name("sim2real-xsvc-ltdupstack-")
    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=json.dumps(_template(taken_name)),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    stack = _wait_create(cfn, stack_id)
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"a launch template reusing the already-registered name {taken_name!r} ended "
        f"{stack['StackStatus']!r}, expected 'ROLLBACK_COMPLETE'"
    )
    events = cfn.describe_stack_events(StackName=stack_id)["StackEvents"]
    failed = [e for e in events if e.get("ResourceStatus") == "CREATE_FAILED"]
    assert [e["LogicalResourceId"] for e in failed] == ["Lt"], (
        f"expected exactly the launch template to fail creation; CREATE_FAILED events were "
        f"{[(e['LogicalResourceId'], e.get('ResourceStatusReason')) for e in failed]!r}"
    )
    reason = failed[0].get("ResourceStatusReason") or ""
    match = _REASON.match(reason)
    assert match is not None, f"the launch template failure reason is not an EC2 error: {reason!r}"
    got_error = (match["message"], match["status"], match["code"])
    want_error = ("Launch template name already in use.", "400", "InvalidLaunchTemplateName.AlreadyExistsException")
    assert got_error == want_error, f"CREATE_FAILED reason: expected {want_error!r}, got {got_error!r}"

    # Effect-absent: the pre-existing template is untouched (still exactly one version, still
    # the original InstanceType) and the stack's own attempt never registered a second one.
    versions = ec2.describe_launch_template_versions(
        LaunchTemplateId=pre_existing_id)["LaunchTemplateVersions"]
    assert [v["VersionNumber"] for v in versions] == [1], (
        f"the pre-existing launch template gained versions from the failed stack: {versions!r}"
    )
    assert versions[0]["LaunchTemplateData"]["InstanceType"] == INSTANCE_TYPE, (
        f"the pre-existing template's data changed to {versions[0]['LaunchTemplateData']!r}"
    )

    _delete_stack_and_wait(cfn, stack_id)

    # Positive control: the identical shape under a name EC2 has never seen succeeds.
    free_name = ctx.unique_name("sim2real-xsvc-ltfree-")
    control_stack_name = ctx.unique_name("sim2real-xsvc-ltfreestack-")
    control_stack_id = cfn.create_stack(
        StackName=control_stack_name, TemplateBody=json.dumps(_template(free_name)),
        Tags=[{"Key": "sim2real", "Value": control_stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, control_stack_id))

    control_stack = _wait_create(cfn, control_stack_id)
    assert control_stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the same launch template under an unused name ended {control_stack['StackStatus']!r} "
        f"({control_stack.get('StackStatusReason')!r}), expected 'CREATE_COMPLETE'"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in control_stack.get("Outputs", [])}
    control = ec2.describe_launch_templates(
        LaunchTemplateIds=[outputs["LaunchTemplateId"]])["LaunchTemplates"][0]
    assert control["LaunchTemplateName"] == free_name, (
        f"the control launch template is named {control['LaunchTemplateName']!r}, expected "
        f"{free_name!r}"
    )

    _delete_stack_and_wait(cfn, control_stack_id)
    code, message = _error(lambda: ec2.describe_launch_templates(LaunchTemplateIds=[outputs["LaunchTemplateId"]]))
    assert code == "InvalidLaunchTemplateId.NotFound", (
        f"the control stack's launch template after its stack delete answered {code!r}: {message!r}"
    )
    assert message == "At least one of the launch templates specified in the request does not exist.", (
        f"unexpected not-found message {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
