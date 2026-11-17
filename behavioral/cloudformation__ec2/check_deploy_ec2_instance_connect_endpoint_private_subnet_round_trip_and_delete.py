"""deploy-ec2-instance-connect-endpoint-private-subnet-round-trip-and-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-instance-connect-endpoint-private-subnet-round-trip-and-delete"
GROUP = "deploy-ec2-resource-sweep"
SERVICES = ["cloudformation", "ec2"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "IMPORT_ROLLBACK_FAILED",
    }
)
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=900.0):
    """Poll DescribeStacks by StackId every 5 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(5)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice."""
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in (
        "DELETE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
    ):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic()
    )
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                "ValidationError",
                f"Stack with id {name} does not exist",
            ):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name>; cleanup registered before the call."""
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def poll(probe, predicate, *, timeout_s, interval_s=10.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


# ---- Check-specific: the template, then run(). ----

_VPC_CIDR = "10.133.0.0/16"
_SUBNET_CIDR = "10.133.1.0/24"


def _available_zone(ec2) -> str:
    """The lexically-first AZ this region reports available right now."""
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )
    assert zones, "no available availability zone in this region"
    return zones[0]


def _template(tag_value: str, zone: str) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
                "Subnet": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {
                        "VpcId": {"Ref": "Vpc"},
                        "CidrBlock": _SUBNET_CIDR,
                        "AvailabilityZone": zone,
                        "Tags": t,
                    },
                },
                "Sg1": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "sim2real instance connect endpoint security group one",
                        "VpcId": {"Ref": "Vpc"},
                        "Tags": t,
                    },
                },
                "Sg2": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "sim2real instance connect endpoint security group two",
                        "VpcId": {"Ref": "Vpc"},
                        "Tags": t,
                    },
                },
                "Endpoint": {
                    "Type": "AWS::EC2::InstanceConnectEndpoint",
                    "Properties": {
                        "SubnetId": {"Ref": "Subnet"},
                        "SecurityGroupIds": [{"Ref": "Sg1"}, {"Ref": "Sg2"}],
                        "PreserveClientIp": False,
                        "Tags": t,
                    },
                },
            },
            "Outputs": {
                "VpcId": {"Value": {"Ref": "Vpc"}},
                "SubnetId": {"Value": {"Ref": "Subnet"}},
                "Sg1Id": {"Value": {"Ref": "Sg1"}},
                "Sg2Id": {"Value": {"Ref": "Sg2"}},
                "EndpointId": {"Value": {"Ref": "Endpoint"}},
                "EndpointGetAttId": {"Value": {"Fn::GetAtt": ["Endpoint", "Id"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation AWS::EC2::InstanceConnectEndpoint in a private subnet (no route to an
    internet gateway) reaches create-complete and reads back through DescribeInstanceConnectEndpoints
    with its subnet, security groups and PreserveClientIp; a stack delete removes it."""
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-ec2ice-")
    zone = _available_zone(ec2)

    stack_id = create_stack(ctx, cfn, stack, _template(CHECK, zone))

    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"
    )

    outputs = stack_outputs(cfn, stack_id)
    vpc_id, subnet_id = outputs["VpcId"], outputs["SubnetId"]
    sg_ids = sorted((outputs["Sg1Id"], outputs["Sg2Id"]))
    endpoint_id = outputs["EndpointId"]
    assert outputs["EndpointGetAttId"] == endpoint_id, (
        f"Ref Endpoint {endpoint_id!r} and GetAtt Endpoint.Id {outputs['EndpointGetAttId']!r} must "
        f"agree"
    )

    # The subnet's main route table carries only the VPC-local route: no internet gateway,
    # so the subnet the endpoint deployed into is private.
    route_tables = ec2.describe_route_tables(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "association.main", "Values": ["true"]},
        ]
    )["RouteTables"]
    assert len(route_tables) == 1, (
        f"expected one main route table for {vpc_id!r}, got {route_tables!r}"
    )
    destinations = sorted(r.get("DestinationCidrBlock") for r in route_tables[0]["Routes"])
    assert destinations == [_VPC_CIDR], (
        f"expected the private subnet's main route table to carry only the local route "
        f"{_VPC_CIDR!r}, EC2 reports destinations {destinations!r}"
    )

    endpoints = poll(
        lambda: ec2.describe_instance_connect_endpoints(InstanceConnectEndpointIds=[endpoint_id])[
            "InstanceConnectEndpoints"
        ],
        lambda eps: eps and eps[0]["State"] == "create-complete",
        timeout_s=300.0,
        description=f"endpoint {endpoint_id} create-complete",
    )
    ep = endpoints[0]
    assert ep["State"] == "create-complete", f"EC2 reports endpoint state {ep['State']!r}"
    assert ep["SubnetId"] == subnet_id, (
        f"expected SubnetId {subnet_id!r}, EC2 reports {ep['SubnetId']!r}"
    )
    assert sorted(ep["SecurityGroupIds"]) == sg_ids, (
        f"expected SecurityGroupIds {sg_ids!r}, EC2 reports {sorted(ep['SecurityGroupIds'])!r}"
    )
    assert ep["PreserveClientIp"] is False, (
        f"expected PreserveClientIp False, EC2 reports {ep['PreserveClientIp']!r}"
    )
    assert ep["VpcId"] == vpc_id, f"expected VpcId {vpc_id!r}, EC2 reports {ep['VpcId']!r}"

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)

    deleted = poll(
        lambda: ec2.describe_instance_connect_endpoints(InstanceConnectEndpointIds=[endpoint_id])[
            "InstanceConnectEndpoints"
        ],
        lambda eps: eps and eps[0]["State"] == "delete-complete",
        timeout_s=300.0,
        description=f"endpoint {endpoint_id} delete-complete",
    )
    assert deleted[0]["State"] == "delete-complete", (
        f"after the stack delete, EC2 reports endpoint state {deleted[0]['State']!r}"
    )

    vpcs_gone = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), *vpcs_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
