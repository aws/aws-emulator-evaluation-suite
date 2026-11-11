"""deploy-ec2-vpc-gateway-attachment-round-trip-and-delete."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-vpc-gateway-attachment-round-trip-and-delete"
GROUP = "deploy-ec2-resource-sweep"
SERVICES = ["cloudformation", "ec2"]

_VPC_CIDR = "10.71.0.0/16"


def _template(tag_value: str) -> str:
    t = [{"Key": "sim2real", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
            "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {"Tags": t}},
            "Attachment": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}},
            },
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "IgwId": {"Value": {"Ref": "Igw"}},
            "AttachmentId": {"Value": {"Ref": "Attachment"}},
        },
    })


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) the call raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return str(err["Code"]), str(err["Message"])
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError":
                return
            raise

    return run_undo


def _delete_stack_and_wait(cfn, stack: str) -> None:
    try:
        cfn.describe_stacks(StackName=stack)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return
        raise
    cfn.delete_stack(StackName=stack)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloudFormation CREATE_COMPLETE for AWS::EC2::VPCGatewayAttachment leaves the gateway
    attached to the named VPC in EC2's own Attachments view, and deleting the stack detaches
    then deletes it: DescribeInternetGateways then raises InvalidInternetGatewayID.NotFound.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpcgatewayattachment.html
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-ec2vgw-")

    cfn.create_stack(StackName=stack, TemplateBody=_template(CHECK))
    ctx.on_cleanup(lambda: _teardown(lambda: _delete_stack_and_wait(cfn, stack))())

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}
    vpc_id, igw_id, attachment_id = outputs["VpcId"], outputs["IgwId"], outputs["AttachmentId"]
    assert vpc_id.startswith("vpc-"), f"VpcId output {vpc_id!r} does not look like a VPC id"
    assert igw_id.startswith("igw-"), f"IgwId output {igw_id!r} does not look like an IGW id"
    # AWS::EC2::VPCGatewayAttachment's Ref returns the attachment itself; CloudFormation mints
    # it as "IGW|<vpc-id>" from the two resources it joins.
    assert attachment_id == f"IGW|{vpc_id}", (
        f"expected the attachment id 'IGW|{vpc_id}', got {attachment_id!r}"
    )

    before = ec2.describe_internet_gateways(InternetGatewayIds=[igw_id])["InternetGateways"]
    assert before, f"DescribeInternetGateways({igw_id!r}) returned no gateways"
    attachments = before[0]["Attachments"]
    assert attachments == [{"VpcId": vpc_id, "State": "available"}], (
        f"expected exactly one 'available' attachment to {vpc_id!r}, EC2 reports {attachments!r}"
    )

    _delete_stack_and_wait(cfn, stack)
    final_status = _error(lambda: cfn.describe_stacks(StackName=stack))
    assert final_status == ("ValidationError", f"Stack with id {stack} does not exist"), (
        f"after delete, DescribeStacks({stack!r}) raised {final_status!r}, expected the "
        f"name not to resolve"
    )

    code, message = _error(lambda: ec2.describe_internet_gateways(InternetGatewayIds=[igw_id]))
    assert code == "InvalidInternetGatewayID.NotFound", (
        f"expected InvalidInternetGatewayID.NotFound reading the detached, deleted gateway, "
        f"got {code!r}: {message!r}"
    )
    want_message = f"The internetGateway ID '{igw_id}' does not exist"
    assert message == want_message, f"expected message {want_message!r}, got {message!r}"

    code, message = _error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]))
    assert code == "InvalidVpcID.NotFound", (
        f"expected InvalidVpcID.NotFound reading the deleted VPC, got {code!r}: {message!r}"
    )
    want_message = f"The vpc ID '{vpc_id}' does not exist"
    assert message == want_message, f"expected message {want_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
