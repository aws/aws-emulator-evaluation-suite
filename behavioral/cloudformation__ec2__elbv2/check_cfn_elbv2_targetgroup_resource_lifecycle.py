"""cfn-elbv2-targetgroup-resource-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-elbv2-targetgroup-resource-lifecycle"
GROUP = "cloudformation"
SERVICES = ["cloudformation", "ec2", "elbv2"]

_TAG = [{"Key": "sim2real", "Value": "behavioral"}]

_TEMPLATE = json.dumps(
    {
        "Resources": {
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {"CidrBlock": "10.93.0.0/16", "Tags": _TAG},
            },
            "TargetGroup": {
                "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "Protocol": "HTTP",
                    "Port": 8080,
                    "TargetType": "ip",
                    "HealthCheckProtocol": "HTTP",
                    "HealthCheckPath": "/healthz",
                    "Tags": _TAG,
                },
            },
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "TargetGroupRef": {"Value": {"Ref": "TargetGroup"}},
            "TargetGroupGetAttArn": {"Value": {"Fn::GetAtt": ["TargetGroup", "TargetGroupArn"]}},
            "TargetGroupGetAttFullName": {
                "Value": {"Fn::GetAtt": ["TargetGroup", "TargetGroupFullName"]}
            },
            "TargetGroupGetAttLoadBalancerArns": {
                "Value": {"Fn::Join": [",", {"Fn::GetAtt": ["TargetGroup", "LoadBalancerArns"]}]}
            },
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
    """A CloudFormation-deployed AWS::ElasticLoadBalancingV2::TargetGroup reads back through
    DescribeTargetGroups with the template's properties and every Fn::GetAtt value, then the
    stack delete leaves it unreadable with the exact TargetGroupNotFound error.
    """
    cfn = ctx.client("cloudformation")
    elbv2 = ctx.client("elbv2")

    stack_name = ctx.unique_name("sim2real-behav-tgstack-")
    cfn.create_stack(
        StackName=stack_name, TemplateBody=_TEMPLATE, Tags=_TAG,
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    _wait_stack(cfn, stack_name, "stack_create_complete")

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    tg_physical_id = cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId="TargetGroup"
    )["StackResourceDetail"]["PhysicalResourceId"]
    assert outputs["TargetGroupRef"] == tg_physical_id, (
        f"Ref TargetGroup {outputs['TargetGroupRef']!r} must equal the stack's own "
        f"PhysicalResourceId {tg_physical_id!r}"
    )

    described = elbv2.describe_target_groups(TargetGroupArns=[tg_physical_id])["TargetGroups"]
    assert len(described) == 1, f"expected exactly one target group, got {described!r}"
    tg = described[0]

    assert tg["Protocol"] == "HTTP", f"expected Protocol HTTP, got {tg['Protocol']!r}"
    assert tg["Port"] == 8080, f"expected Port 8080, got {tg['Port']!r}"
    assert tg["VpcId"] == outputs["VpcId"], (
        f"expected VpcId {outputs['VpcId']!r}, got {tg['VpcId']!r}"
    )
    assert tg["TargetType"] == "ip", f"expected TargetType ip, got {tg['TargetType']!r}"
    assert tg["HealthCheckProtocol"] == "HTTP", (
        f"expected HealthCheckProtocol HTTP, got {tg['HealthCheckProtocol']!r}"
    )
    assert tg["HealthCheckPath"] == "/healthz", (
        f"expected HealthCheckPath /healthz, got {tg['HealthCheckPath']!r}"
    )

    assert outputs["TargetGroupGetAttArn"] == tg["TargetGroupArn"], (
        f"Fn::GetAtt TargetGroupArn {outputs['TargetGroupGetAttArn']!r} must equal "
        f"DescribeTargetGroups' TargetGroupArn {tg['TargetGroupArn']!r}"
    )
    assert outputs["TargetGroupGetAttArn"] == tg_physical_id, (
        f"Fn::GetAtt TargetGroupArn {outputs['TargetGroupGetAttArn']!r} must equal the stack's "
        f"own PhysicalResourceId {tg_physical_id!r}"
    )
    arn_resource = tg["TargetGroupArn"].split(":", 5)[-1]
    assert arn_resource == outputs["TargetGroupGetAttFullName"], (
        f"Fn::GetAtt TargetGroupFullName {outputs['TargetGroupGetAttFullName']!r} must be the "
        f"ARN's resource id {arn_resource!r}"
    )
    assert outputs["TargetGroupGetAttLoadBalancerArns"] == "", (
        f"a TargetGroup created with no LoadBalancer attachment must report an empty "
        f"Fn::GetAtt LoadBalancerArns, got {outputs['TargetGroupGetAttLoadBalancerArns']!r}"
    )
    assert tg["LoadBalancerArns"] == [], (
        f"DescribeTargetGroups must agree the target group has no load balancer attached, "
        f"got LoadBalancerArns={tg['LoadBalancerArns']!r}"
    )

    network = _network_ids(cfn, stack_name)
    _delete_stack_and_wait(cfn, stack_name)

    code, message = _error(
        lambda: elbv2.describe_target_groups(TargetGroupArns=[tg_physical_id])
    )
    assert (code, message) == ("TargetGroupNotFound", "One or more target groups not found"), (
        f"the deleted target group {tg_physical_id!r} must be gone (TargetGroupNotFound), "
        f"got {(code, message)!r}"
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
