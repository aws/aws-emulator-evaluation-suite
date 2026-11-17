"""deploy-subnet-ipv6-getatt-on-ipv4-subnet-rejected-and-rolled-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-subnet-ipv6-getatt-on-ipv4-subnet-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

_TAGS = [{"Key": "sim2real", "Value": "deploy-subnet-ipv6-getatt"}]


def _template(owner: str) -> str:
    """An IPv4-only VPC and subnet, outputting the joined Ipv6CidrBlocks of ``owner``."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.43.0.0/16", "Tags": _TAGS}},
            "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.43.1.0/24",
                "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]}, "Tags": _TAGS}},
        },
        "Outputs": {"Ipv6": {"Value": {"Fn::Join": [",", {"Fn::GetAtt": [owner, "Ipv6CidrBlocks"]}]}}},
    })


def _wait(cf, stack_id: str, budget_s: float = 600.0) -> dict:
    """The stack once it leaves every *_IN_PROGRESS state."""
    deadline = time.monotonic() + budget_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"stack still {stack['StackStatus']!r} after {budget_s}s")
        time.sleep(4)


def _delete_stack(cf, stack_id: str):
    """A cleanup that deletes the stack and raises unless it reaches DELETE_COMPLETE."""

    def run_delete() -> None:
        cf.delete_stack(StackName=stack_id)
        status = _wait(cf, stack_id)["StackStatus"]
        if status != "DELETE_COMPLETE":
            raise AssertionError(f"stack delete ended {status!r}")

    return run_delete


def _events(cf, stack_id: str) -> list:
    events = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return events


def _error(fn) -> tuple:
    """(Error.Code, Error.Message) ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Fn::GetAtt Ipv6CidrBlocks on an IPv4-only subnet fails the create and rolls the network back,
    while the same attribute on the IPv4-only VPC resolves to an empty list."""
    cf = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    stacks = {}
    for owner in ("Vpc", "Subnet"):
        name = ctx.unique_name(f"sim2real-behav-ip6{owner.lower()}-")
        stack_id = cf.create_stack(StackName=name, TemplateBody=_template(owner),
                                   Tags=[{"Key": "sim2real", "Value": name}])["StackId"]
        ctx.on_cleanup(_delete_stack(cf, stack_id))
        stacks[owner] = (name, stack_id)

    control = _wait(cf, stacks["Vpc"][1])
    assert control["StackStatus"] == "CREATE_COMPLETE", f"control stack ended {control['StackStatus']!r}"
    outputs = [(o["OutputKey"], o["OutputValue"]) for o in control.get("Outputs", [])]
    assert outputs == [("Ipv6", "")], f"VPC Ipv6CidrBlocks output {outputs!r}"

    name, stack_id = stacks["Subnet"]
    broken = _wait(cf, stack_id)
    assert broken["StackStatus"] == "ROLLBACK_COMPLETE", f"subnet stack ended {broken['StackStatus']!r}"
    assert "Outputs" not in broken, f"rolled-back stack shows outputs {broken['Outputs']!r}"
    events = _events(cf, stack_id)
    reasons = [e.get("ResourceStatusReason") for e in events
               if e["LogicalResourceId"] == name and e["ResourceStatus"] == "ROLLBACK_IN_PROGRESS"]
    assert reasons == ["Attribute 'Ipv6CidrBlocks' does not exist. Rollback requested by user."], (
        f"rollback reasons {reasons!r}"
    )
    created = {e["LogicalResourceId"]: e["PhysicalResourceId"] for e in events
               if e["ResourceStatus"] == "CREATE_COMPLETE" and e["LogicalResourceId"] in ("Vpc", "Subnet")}
    assert sorted(created) == ["Subnet", "Vpc"], f"resources created before the failure: {sorted(created)!r}"
    deleted = sorted(e["LogicalResourceId"] for e in events if e["ResourceStatus"] == "DELETE_COMPLETE")
    assert deleted == ["Subnet", "Vpc"], f"resources the rollback deleted: {deleted!r}"
    code, msg = _error(lambda: ec2.describe_subnets(SubnetIds=[created["Subnet"]]))
    assert code == "InvalidSubnetID.NotFound", f"rolled-back subnet lookup code {code!r}"
    assert msg == f"The subnet ID '{created['Subnet']}' does not exist", f"subnet lookup message {msg!r}"
    code, msg = _error(lambda: ec2.describe_vpcs(VpcIds=[created["Vpc"]]))
    assert code == "InvalidVpcID.NotFound", f"rolled-back VPC lookup code {code!r}"
    assert msg == f"The vpc ID '{created['Vpc']}' does not exist", f"VPC lookup message {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
