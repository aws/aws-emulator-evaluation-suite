"""deploy-ec2-route-round-trip-and-delete."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-route-round-trip-and-delete"
GROUP = "deploy-ec2-resource-sweep"
SERVICES = ["cloudformation", "ec2"]

_VPC_CIDR = "10.73.0.0/16"
_DEST_CIDR = "0.0.0.0/0"


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
            "IgwId": {"Value": {"Ref": "Igw"}},
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "RouteCidrAtt": {"Value": {"Fn::GetAtt": ["Route", "CidrBlock"]}},
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
    """A CloudFormation AWS::EC2::Route is an active route to the attached gateway with Fn::GetAtt
    CidrBlock as declared; the stack delete removes the route table, gateway and VPC
    (InvalidRouteTableID.NotFound, InvalidInternetGatewayID.NotFound, InvalidVpcID.NotFound).

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-route.html
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-ec2rte-")

    cfn.create_stack(StackName=stack, TemplateBody=_template(CHECK))
    ctx.on_cleanup(lambda: _teardown(lambda: _delete_stack_and_wait(cfn, stack))())

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}
    rt_id, igw_id, cidr_att = outputs["RouteTableId"], outputs["IgwId"], outputs["RouteCidrAtt"]
    vpc_id = outputs["VpcId"]
    assert rt_id.startswith("rtb-"), f"RouteTableId output {rt_id!r} does not look like a RT id"
    assert igw_id.startswith("igw-"), f"IgwId output {igw_id!r} does not look like an IGW id"
    assert cidr_att == _DEST_CIDR, (
        f"Fn::GetAtt Route.CidrBlock returned {cidr_att!r}, expected the declared destination "
        f"{_DEST_CIDR!r}"
    )

    before = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"]
    assert before, f"DescribeRouteTables({rt_id!r}) returned no route tables"
    routes = [r for r in before[0]["Routes"] if r.get("DestinationCidrBlock") == _DEST_CIDR]
    assert len(routes) == 1, (
        f"expected exactly one route to {_DEST_CIDR!r}, route table {rt_id!r} reports routes "
        f"{before[0]['Routes']!r}"
    )
    route = routes[0]
    assert route["GatewayId"] == igw_id, (
        f"expected the route's GatewayId to be {igw_id!r}, EC2 reports {route['GatewayId']!r}"
    )
    assert route["State"] == "active", (
        f"expected the route's State to be 'active', EC2 reports {route['State']!r}"
    )
    assert route["Origin"] == "CreateRoute", (
        f"expected the route's Origin to be 'CreateRoute', EC2 reports {route['Origin']!r}"
    )

    _delete_stack_and_wait(cfn, stack)
    final_status = _error(lambda: cfn.describe_stacks(StackName=stack))
    assert final_status == ("ValidationError", f"Stack with id {stack} does not exist"), (
        f"after delete, DescribeStacks({stack!r}) raised {final_status!r}, expected the "
        f"name not to resolve"
    )

    code, message = _error(lambda: ec2.describe_route_tables(RouteTableIds=[rt_id]))
    assert code == "InvalidRouteTableID.NotFound", (
        f"expected InvalidRouteTableID.NotFound reading the deleted route table, got {code!r}: "
        f"{message!r}"
    )
    want_message = f"The routeTable ID '{rt_id}' does not exist"
    assert message == want_message, f"expected message {want_message!r}, got {message!r}"

    code, message = _error(lambda: ec2.describe_internet_gateways(InternetGatewayIds=[igw_id]))
    assert code == "InvalidInternetGatewayID.NotFound", (
        f"expected InvalidInternetGatewayID.NotFound reading the deleted gateway, got {code!r}: "
        f"{message!r}"
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
