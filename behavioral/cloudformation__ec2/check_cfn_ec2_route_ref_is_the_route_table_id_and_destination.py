"""cfn-ec2-route-ref-is-the-route-table-id-and-destination."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-route-ref-is-the-route-table-id-and-destination"
GROUP = "deploy-ec2-resource-sweep"
SERVICES = ["cloudformation", "ec2"]

_VPC_CIDR = "10.74.0.0/16"
_DEST_CIDR = "0.0.0.0/0"


def _template() -> str:
    t = [{"Key": "sim2real", "Value": "1"}]
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
                "Igw": {"Type": "AWS::EC2::InternetGateway", "Properties": {"Tags": t}},
                "Attachment": {
                    "Type": "AWS::EC2::VPCGatewayAttachment",
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}},
                },
                "RouteTable": {
                    "Type": "AWS::EC2::RouteTable",
                    "Properties": {"VpcId": {"Ref": "Vpc"}, "Tags": t},
                },
                "Route": {
                    "Type": "AWS::EC2::Route",
                    "DependsOn": "Attachment",
                    "Properties": {
                        "RouteTableId": {"Ref": "RouteTable"},
                        "DestinationCidrBlock": _DEST_CIDR,
                        "GatewayId": {"Ref": "Igw"},
                    },
                },
            },
            "Outputs": {
                "RouteTableId": {"Value": {"Ref": "RouteTable"}},
                "RouteRef": {"Value": {"Ref": "Route"}},
            },
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::EC2::Route's Ref and physical id are '<route table id>|<destination>'.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-route.html
    """
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-ec2rtref-")

    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, cfn, stack))
    cfn.create_stack(StackName=stack, TemplateBody=_template())
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack,
        WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 300.0) // 2))},
    )
    described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {described['StackStatus']!r}, expected CREATE_COMPLETE"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in described["Outputs"]}
    want = f"{outputs['RouteTableId']}|{_DEST_CIDR}"
    assert outputs["RouteRef"] == want, (
        f"Ref of the AWS::EC2::Route returned {outputs['RouteRef']!r}, expected {want!r}"
    )

    physical = cfn.describe_stack_resource(StackName=stack, LogicalResourceId="Route")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    assert physical == want, (
        f"DescribeStackResource reports the route's PhysicalResourceId {physical!r}, expected "
        f"{want!r}, the same value as its Ref"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, capped by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _delete_stack_and_wait(ctx, cfn, stack: str) -> None:
    """Delete the stack if it exists and wait until it is gone; a failed delete raises."""
    try:
        cfn.describe_stacks(StackName=stack)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return
        raise
    cfn.delete_stack(StackName=stack)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack,
        WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 300.0) // 2))},
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
