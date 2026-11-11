"""cfn-elbv2-loadbalancer-resource-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-elbv2-loadbalancer-resource-lifecycle"
GROUP = "cloudformation"
SERVICES = ["cloudformation", "ec2", "elbv2"]

_TAG = [{"Key": "sim2real", "Value": "behavioral"}]

_TEMPLATE = json.dumps(
    {
        "Resources": {
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {"CidrBlock": "10.92.0.0/16", "Tags": _TAG},
            },
            "SubnetA": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.92.1.0/24",
                    "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                    "Tags": _TAG,
                },
            },
            "SubnetB": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.92.2.0/24",
                    "AvailabilityZone": {"Fn::Select": [1, {"Fn::GetAZs": ""}]},
                    "Tags": _TAG,
                },
            },
            "AlbSg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "sim2real cfn-elbv2-loadbalancer-resource-lifecycle",
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
        },
        "Outputs": {
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetAId": {"Value": {"Ref": "SubnetA"}},
            "SubnetBId": {"Value": {"Ref": "SubnetB"}},
            "AlbSgId": {"Value": {"Ref": "AlbSg"}},
            "AlbRef": {"Value": {"Ref": "Alb"}},
            "AlbCanonicalHostedZoneID": {"Value": {"Fn::GetAtt": ["Alb", "CanonicalHostedZoneID"]}},
            "AlbDNSName": {"Value": {"Fn::GetAtt": ["Alb", "DNSName"]}},
            "AlbLoadBalancerArn": {"Value": {"Fn::GetAtt": ["Alb", "LoadBalancerArn"]}},
            "AlbLoadBalancerFullName": {"Value": {"Fn::GetAtt": ["Alb", "LoadBalancerFullName"]}},
            "AlbLoadBalancerName": {"Value": {"Fn::GetAtt": ["Alb", "LoadBalancerName"]}},
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
    """A CloudFormation-deployed internal AWS::ElasticLoadBalancingV2::LoadBalancer reads back
    through DescribeLoadBalancers with the template's properties and every Fn::GetAtt value, then
    the stack delete leaves it unreadable with the exact LoadBalancerNotFound error.
    """
    cfn = ctx.client("cloudformation")
    elbv2 = ctx.client("elbv2")

    stack_name = ctx.unique_name("sim2real-behav-albstack-")
    cfn.create_stack(
        StackName=stack_name, TemplateBody=_TEMPLATE, Tags=_TAG,
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    _wait_stack(cfn, stack_name, "stack_create_complete")

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    alb_physical_id = cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId="Alb"
    )["StackResourceDetail"]["PhysicalResourceId"]
    assert outputs["AlbRef"] == alb_physical_id, (
        f"Ref Alb {outputs['AlbRef']!r} must equal the stack's own "
        f"PhysicalResourceId {alb_physical_id!r}"
    )

    described = elbv2.describe_load_balancers(LoadBalancerArns=[alb_physical_id])["LoadBalancers"]
    assert len(described) == 1, f"expected exactly one load balancer, got {described!r}"
    lb = described[0]

    assert lb["Type"] == "application", f"expected Type application, got {lb['Type']!r}"
    assert lb["Scheme"] == "internal", f"expected Scheme internal, got {lb['Scheme']!r}"
    assert lb["VpcId"] == outputs["VpcId"], (
        f"expected VpcId {outputs['VpcId']!r}, got {lb['VpcId']!r}"
    )
    assert lb["State"]["Code"] == "active", f"expected State.Code active, got {lb['State']!r}"
    got_subnets = sorted(az["SubnetId"] for az in lb["AvailabilityZones"])
    want_subnets = sorted([outputs["SubnetAId"], outputs["SubnetBId"]])
    assert got_subnets == want_subnets, f"expected subnets {want_subnets!r}, got {got_subnets!r}"
    assert lb["SecurityGroups"] == [outputs["AlbSgId"]], (
        f"expected SecurityGroups {[outputs['AlbSgId']]!r}, got {lb['SecurityGroups']!r}"
    )

    assert outputs["AlbLoadBalancerArn"] == lb["LoadBalancerArn"], (
        f"Fn::GetAtt LoadBalancerArn {outputs['AlbLoadBalancerArn']!r} must equal "
        f"DescribeLoadBalancers' LoadBalancerArn {lb['LoadBalancerArn']!r}"
    )
    assert outputs["AlbLoadBalancerArn"] == alb_physical_id, (
        f"Fn::GetAtt LoadBalancerArn {outputs['AlbLoadBalancerArn']!r} must equal the stack's "
        f"own PhysicalResourceId {alb_physical_id!r}"
    )
    assert outputs["AlbDNSName"] == lb["DNSName"], (
        f"Fn::GetAtt DNSName {outputs['AlbDNSName']!r} must equal DescribeLoadBalancers' "
        f"DNSName {lb['DNSName']!r}"
    )
    assert outputs["AlbCanonicalHostedZoneID"] == lb["CanonicalHostedZoneId"], (
        f"Fn::GetAtt CanonicalHostedZoneID {outputs['AlbCanonicalHostedZoneID']!r} must equal "
        f"DescribeLoadBalancers' CanonicalHostedZoneId {lb['CanonicalHostedZoneId']!r}"
    )
    arn_resource = lb["LoadBalancerArn"].split(":", 5)[-1]
    assert arn_resource == f"loadbalancer/{outputs['AlbLoadBalancerFullName']}", (
        f"Fn::GetAtt LoadBalancerFullName {outputs['AlbLoadBalancerFullName']!r} must be the "
        f"ARN's resource id {arn_resource!r} minus its 'loadbalancer/' prefix"
    )
    assert outputs["AlbLoadBalancerName"] == lb["LoadBalancerName"], (
        f"Fn::GetAtt LoadBalancerName {outputs['AlbLoadBalancerName']!r} must equal "
        f"DescribeLoadBalancers' LoadBalancerName {lb['LoadBalancerName']!r}"
    )

    network = _network_ids(cfn, stack_name)
    _delete_stack_and_wait(cfn, stack_name)

    code, message = _error(
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[alb_physical_id])
    )
    assert (code, message) == ("LoadBalancerNotFound", "One or more load balancers not found"), (
        f"the deleted ALB {alb_physical_id!r} must be gone (LoadBalancerNotFound), "
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
