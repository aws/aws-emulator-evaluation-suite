"""cfn-elbv2-listener-resource-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-elbv2-listener-resource-lifecycle"
GROUP = "cloudformation"
SERVICES = ["cloudformation", "ec2", "elbv2"]

_TAG = [{"Key": "sim2real", "Value": "behavioral"}]
_BODY = "cfn-elbv2-listener-resource-lifecycle-ok"

_TEMPLATE = json.dumps(
    {
        "Resources": {
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {"CidrBlock": "10.94.0.0/16", "Tags": _TAG},
            },
            "SubnetA": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.94.1.0/24",
                    "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                    "Tags": _TAG,
                },
            },
            "SubnetB": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.94.2.0/24",
                    "AvailabilityZone": {"Fn::Select": [1, {"Fn::GetAZs": ""}]},
                    "Tags": _TAG,
                },
            },
            "AlbSg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "sim2real cfn-elbv2-listener-resource-lifecycle",
                    "VpcId": {"Ref": "Vpc"},
                    "Tags": _TAG,
                },
            },
            "Alb": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Type": "application",
                    "Scheme": "internal",
                    "Subnets": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                    "SecurityGroups": [{"Ref": "AlbSg"}],
                    "Tags": _TAG,
                },
            },
            "Listener": {
                "Type": "AWS::ElasticLoadBalancingV2::Listener",
                "Properties": {
                    "LoadBalancerArn": {"Ref": "Alb"},
                    "Port": 8080,
                    "Protocol": "HTTP",
                    "DefaultActions": [
                        {
                            "Type": "fixed-response",
                            "FixedResponseConfig": {
                                "StatusCode": "200",
                                "ContentType": "text/plain",
                                "MessageBody": _BODY,
                            },
                        }
                    ],
                },
            },
        },
        "Outputs": {
            "AlbRef": {"Value": {"Ref": "Alb"}},
            "ListenerRef": {"Value": {"Ref": "Listener"}},
            "ListenerGetAttArn": {"Value": {"Fn::GetAtt": ["Listener", "ListenerArn"]}},
        },
    }
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; a success is a failure."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_stack(cfn, stack_name, waiter_name, max_attempts=300):
    cfn.get_waiter(waiter_name).wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts}
    )


def _delete_stack_and_wait(cfn, stack_name):
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise
    try:
        _wait_stack(cfn, stack_name, "stack_delete_complete")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ValidationError":
            raise


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::ElasticLoadBalancingV2::Listener reads back through
    DescribeListeners with the template's properties and its Fn::GetAtt value, then the
    stack delete leaves it unreadable with the exact ListenerNotFound error.
    """
    cfn = ctx.client("cloudformation")
    elbv2 = ctx.client("elbv2")

    stack_name = ctx.unique_name("sim2real-behav-lsnrstack-")
    cfn.create_stack(
        StackName=stack_name, TemplateBody=_TEMPLATE, Tags=_TAG,
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    _wait_stack(cfn, stack_name, "stack_create_complete")

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    listener_physical_id = cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId="Listener"
    )["StackResourceDetail"]["PhysicalResourceId"]
    assert outputs["ListenerRef"] == listener_physical_id, (
        f"Ref Listener {outputs['ListenerRef']!r} must equal the stack's own "
        f"PhysicalResourceId {listener_physical_id!r}"
    )

    described = elbv2.describe_listeners(ListenerArns=[listener_physical_id])["Listeners"]
    assert len(described) == 1, f"expected exactly one listener, got {described!r}"
    listener = described[0]

    assert listener["Port"] == 8080, f"expected Port 8080, got {listener['Port']!r}"
    assert listener["Protocol"] == "HTTP", f"expected Protocol HTTP, got {listener['Protocol']!r}"
    assert listener["LoadBalancerArn"] == outputs["AlbRef"], (
        f"expected LoadBalancerArn {outputs['AlbRef']!r}, got {listener['LoadBalancerArn']!r}"
    )
    actions = listener["DefaultActions"]
    assert len(actions) == 1 and actions[0]["Type"] == "fixed-response", (
        f"expected one fixed-response default action, got {actions!r}"
    )
    fixed = actions[0]["FixedResponseConfig"]
    assert (fixed["StatusCode"], fixed["ContentType"], fixed["MessageBody"]) == (
        "200", "text/plain", _BODY,
    ), f"expected the template's fixed response, got {fixed!r}"

    assert outputs["ListenerGetAttArn"] == listener["ListenerArn"], (
        f"Fn::GetAtt ListenerArn {outputs['ListenerGetAttArn']!r} must equal "
        f"DescribeListeners' ListenerArn {listener['ListenerArn']!r}"
    )
    assert outputs["ListenerGetAttArn"] == listener_physical_id, (
        f"Fn::GetAtt ListenerArn {outputs['ListenerGetAttArn']!r} must equal the stack's "
        f"own PhysicalResourceId {listener_physical_id!r}"
    )

    network = _network_ids(cfn, stack_name)
    _delete_stack_and_wait(cfn, stack_name)

    code, message = _error(
        lambda: elbv2.describe_listeners(ListenerArns=[listener_physical_id])
    )
    assert (code, message) == ("ListenerNotFound", "One or more listeners not found"), (
        f"the deleted listener {listener_physical_id!r} must be gone (ListenerNotFound), "
        f"got {(code, message)!r}"
    )

    alb_arn = outputs["AlbRef"]
    got = _error(lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn]))
    assert got == ("LoadBalancerNotFound", "One or more load balancers not found"), (
        f"the stack's ALB {alb_arn!r} must be gone after the stack delete, got {got!r}"
    )
    _assert_network_gone(ctx.client("ec2"), network)


# What EC2 answers for each network resource the stack created, once the stack delete removed it.
_EC2_GONE = {
    "AWS::EC2::VPC": ("describe_vpcs", "VpcIds", "InvalidVpcID.NotFound", "The vpc ID '{}' does not exist"),
    "AWS::EC2::Subnet": (
        "describe_subnets", "SubnetIds", "InvalidSubnetID.NotFound", "The subnet ID '{}' does not exist"
    ),
    "AWS::EC2::SecurityGroup": (
        "describe_security_groups", "GroupIds", "InvalidGroup.NotFound", "The security group '{}' does not exist"
    ),
}


def _network_ids(cfn, stack: str) -> list[tuple[str, str]]:
    """``(resource type, physical id)`` of every VPC, subnet and security group in the stack."""
    return sorted(
        (r["ResourceType"], r["PhysicalResourceId"])
        for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
        if r["ResourceType"] in _EC2_GONE
    )


def _assert_network_gone(ec2, network: list[tuple[str, str]]) -> None:
    """Each network resource answers EC2's own not-found code and message."""
    for rtype, physical_id in network:
        op, param, code, message = _EC2_GONE[rtype]
        try:
            found = getattr(ec2, op)(**{param: [physical_id]})
        except ClientError as exc:
            got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        else:
            raise AssertionError(f"{rtype} {physical_id} still described after the stack delete: {found!r}")
        assert got == (code, message.format(physical_id)), (
            f"{rtype} {physical_id} after the stack delete: {got!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
