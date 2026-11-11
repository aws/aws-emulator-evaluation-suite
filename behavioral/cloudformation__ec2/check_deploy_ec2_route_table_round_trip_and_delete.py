"""deploy-ec2-route-table-round-trip-and-delete."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-route-table-round-trip-and-delete"
GROUP = "deploy-ec2-resource-sweep"
SERVICES = ["cloudformation", "ec2"]

_VPC_CIDR = "10.72.0.0/16"


def _template(tag_value: str, name_value: str) -> str:
    t = [{"Key": "sim2real", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
            "RouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "Tags": t + [{"Key": "Name", "Value": name_value}],
                },
            },
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "RouteTableId": {"Value": {"Ref": "RouteTable"}},
            "RouteTableIdAtt": {"Value": {"Fn::GetAtt": ["RouteTable", "RouteTableId"]}},
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
    """A CloudFormation AWS::EC2::RouteTable sits in the declared VPC with its tags, one local route
    and Fn::GetAtt RouteTableId matching Ref; the stack delete removes it and the VPC
    (InvalidRouteTableID.NotFound, InvalidVpcID.NotFound).

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-routetable.html
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-ec2rtb-")
    name_value = ctx.unique_name("sim2real-ec2rtb-name-")

    cfn.create_stack(StackName=stack, TemplateBody=_template(CHECK, name_value))
    ctx.on_cleanup(lambda: _teardown(lambda: _delete_stack_and_wait(cfn, stack))())

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack)["Stacks"][0]["Outputs"]}
    vpc_id, rt_id, rt_id_att = outputs["VpcId"], outputs["RouteTableId"], outputs["RouteTableIdAtt"]
    assert vpc_id.startswith("vpc-"), f"VpcId output {vpc_id!r} does not look like a VPC id"
    assert rt_id.startswith("rtb-"), f"RouteTableId output {rt_id!r} does not look like a RT id"
    assert rt_id_att == rt_id, (
        f"Fn::GetAtt RouteTable.RouteTableId returned {rt_id_att!r}, expected it to match "
        f"Ref's {rt_id!r}"
    )

    before = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"]
    assert before, f"DescribeRouteTables({rt_id!r}) returned no route tables"
    rt = before[0]
    assert rt["VpcId"] == vpc_id, (
        f"expected the route table's VpcId to be {vpc_id!r}, EC2 reports {rt['VpcId']!r}"
    )
    got_tags = {t["Key"]: t["Value"] for t in rt["Tags"]}
    assert got_tags.get("sim2real") == CHECK, (
        f"expected the sim2real tag to carry {CHECK!r}, EC2 reports tags {got_tags!r}"
    )
    assert got_tags.get("Name") == name_value, (
        f"expected the Name tag to carry {name_value!r}, EC2 reports tags {got_tags!r}"
    )
    # A route table CloudFormation just created carries only the implicit local route.
    local_routes = [r for r in rt["Routes"] if r.get("GatewayId") == "local"]
    assert len(local_routes) == 1, (
        f"expected exactly one implicit local route, EC2 reports routes {rt['Routes']!r}"
    )
    assert local_routes[0].get("DestinationCidrBlock") == _VPC_CIDR, (
        f"expected the local route to cover the VPC CIDR {_VPC_CIDR!r}, EC2 reports "
        f"{local_routes[0]!r}"
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

    code, message = _error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]))
    assert code == "InvalidVpcID.NotFound", (
        f"expected InvalidVpcID.NotFound reading the deleted VPC, got {code!r}: {message!r}"
    )
    want_message = f"The vpc ID '{vpc_id}' does not exist"
    assert message == want_message, f"expected message {want_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
