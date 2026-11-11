"""cfn-ec2-vpc-create-update-in-place-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ec2-vpc-create-update-in-place-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: EC2 reads are eventually consistent: a change can take a moment to reach every Describe.
_PROPAGATE_CAP_S = 30.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_CIDR = "10.80.0.0/16"

#: EC2's refusal of a VPC that no longer exists.
_NOT_FOUND = ("InvalidVpcID.NotFound", "The vpc ID '{}' does not exist")


def _template(name: str, dns_hostnames: bool) -> str:
    # AWS::EC2::VPC replaces only on CidrBlock (or Ipv4IpamPoolId), and a replacement holds two
    # VPCs at once; the check keeps to one VPC, so it exercises the in-place path only.
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {
                        "CidrBlock": _CIDR,
                        "EnableDnsSupport": True,
                        "EnableDnsHostnames": dns_hostnames,
                        "InstanceTenancy": "default",
                        "Tags": _TAGS + [{"Key": "Name", "Value": name}],
                    },
                },
            },
            "Outputs": {
                "VpcId": {"Value": {"Fn::GetAtt": ["Vpc", "VpcId"]}},
                "CidrBlock": {"Value": {"Fn::GetAtt": ["Vpc", "CidrBlock"]}},
                "DefaultSecurityGroup": {"Value": {"Fn::GetAtt": ["Vpc", "DefaultSecurityGroup"]}},
                "DefaultNetworkAcl": {"Value": {"Fn::GetAtt": ["Vpc", "DefaultNetworkAcl"]}},
            },
        }
    )


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation VPC reads back as templated; its main route table routes its CIDR locally.

    EnableDnsHostnames and Name changes update the same VPC in place; delete: InvalidVpcID.NotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpc.html
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    stack_name = ctx.unique_name("sim2real-cfnvpc-")
    first = ctx.unique_name("sim2real-cfnvpc-a-")
    second = ctx.unique_name("sim2real-cfnvpc-b-")
    ref = {"stack": stack_name}
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: CloudFormation's view, EC2's view, and the VPC's implicit routing
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(first, False), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    vpc_id = _physical_ids(cfn, ref["stack"])["Vpc"]
    outputs = _outputs(stack)
    assert {k: outputs[k] for k in ("VpcId", "CidrBlock")} == {
        "VpcId": vpc_id,
        "CidrBlock": _CIDR,
    }, f"GetAtt outputs {outputs!r} must name the VPC {vpc_id!r} and {_CIDR!r}"
    stamped = _stack_tags(stack_name, ref["stack"], "Vpc")

    def read_vpc() -> dict:
        vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        got = {
            k: vpc.get(k) for k in ("VpcId", "CidrBlock", "State", "InstanceTenancy", "IsDefault")
        }
        got["Tags"] = _tag_map(vpc.get("Tags"))
        return got

    _wait_for(
        ctx,
        read_vpc,
        {
            "VpcId": vpc_id,
            "CidrBlock": _CIDR,
            "State": "available",
            "InstanceTenancy": "default",
            "IsDefault": False,
            "Tags": {"sim2real": CHECK, "Name": first, **stamped},
        },
        f"DescribeVpcs {vpc_id}",
    )
    _wait_for(
        ctx,
        lambda: _dns(ec2, vpc_id),
        {"enableDnsSupport": True, "enableDnsHostnames": False},
        f"DescribeVpcAttribute {vpc_id}",
    )

    # The VPC does its job: AWS gives it one main route table whose only route delivers the
    # VPC's own CIDR locally, plus the default security group and network ACL GetAtt names.
    local = {
        "DestinationCidrBlock": _CIDR,
        "GatewayId": "local",
        "Origin": "CreateRouteTable",
        "State": "active",
    }
    _wait_for(
        ctx,
        lambda: [
            t["Routes"]
            for t in ec2.describe_route_tables(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "association.main", "Values": ["true"]},
                ]
            )["RouteTables"]
        ],
        [[local]],
        f"routes of the main route tables of {vpc_id}",
    )
    _wait_for(
        ctx,
        lambda: [
            g["GroupId"]
            for g in ec2.describe_security_groups(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "group-name", "Values": ["default"]},
                ]
            )["SecurityGroups"]
        ],
        [outputs["DefaultSecurityGroup"]],
        f"default security groups of {vpc_id} (GetAtt DefaultSecurityGroup)",
    )
    _wait_for(
        ctx,
        lambda: [
            a["NetworkAclId"]
            for a in ec2.describe_network_acls(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "default", "Values": ["true"]},
                ]
            )["NetworkAcls"]
        ],
        [outputs["DefaultNetworkAcl"]],
        f"default network ACLs of {vpc_id} (GetAtt DefaultNetworkAcl)",
    )

    # ---- 2. in-place: DNS hostnames on and a new Name tag, the same VPC
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(second, True), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Vpc"] == vpc_id, "an in-place update keeps the VPC"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Vpc"), vpc_id, "Vpc")
    _wait_for(
        ctx,
        lambda: _dns(ec2, vpc_id),
        {"enableDnsSupport": True, "enableDnsHostnames": True},
        f"DescribeVpcAttribute {vpc_id}",
    )
    _wait_for(
        ctx,
        lambda: _tag_map(ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0].get("Tags")),
        {"sim2real": CHECK, "Name": second, **stamped},
        f"tags of {vpc_id}",
    )

    # ---- 3. delete: EC2 no longer knows the VPC
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx, lambda: ec2.describe_vpcs(VpcIds=[vpc_id]), _NOT_FOUND[0], f"VPC {vpc_id}"
    )
    assert got == (_NOT_FOUND[0], _NOT_FOUND[1].format(vpc_id)), (
        f"DescribeVpcs after the stack delete answered {got!r}"
    )


def _dns(ec2, vpc_id: str) -> dict[str, bool]:
    return {
        attr: ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute=attr)[attr[0].upper() + attr[1:]][
            "Value"
        ]
        for attr in ("enableDnsSupport", "enableDnsHostnames")
    }


# ===== helpers =====


def _tag_map(tags: list[dict] | None) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in tags or []}


def _stack_tags(stack_name: str, stack_id: str, logical_id: str) -> dict[str, str]:
    """The tags CloudFormation itself stamps on an EC2 resource it creates."""
    return {
        "aws:cloudformation:stack-name": stack_name,
        "aws:cloudformation:stack-id": stack_id,
        "aws:cloudformation:logical-id": logical_id,
    }


def _wait_for(ctx, read, want, what: str):
    """Poll ``read()`` until it equals *want*: EC2 reads are eventually consistent."""
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        got = read()
        if got == want:
            return got
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended with {what} at {got!r}, expected {want!r}")
            raise AssertionError(f"{what}: {got!r}, expected {want!r}")
        time.sleep(_POLL_S)


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. ctx=None (teardown) waits the full cap;
    in a teardown, ctx.time_left() counts down the runner's cleanup timeout.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    quota = [reason for _, _, reason in failed if reason and "LimitExceeded" in reason]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
        + (f"; an account quota refused it, not the template: {quota!r}" if quota else "")
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o.get("OutputValue") for o in stack.get("Outputs", [])}


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Its waits pass ctx=None, so a body that ran out of time still gets the full stack cap.
    """
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(None, cfn, stack["StackId"])
    _delete_stack(None, cfn, stack["StackId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
