"""deploy-apigatewayv2-vpclink-round-trip-then-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigatewayv2-vpclink-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["apigatewayv2", "cloudformation", "ec2"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
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


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_NOT_FOUND = ("NotFoundException", "Invalid Vpc Link identifier specified")


def _list_vpc_links(apigwv2) -> list[dict]:
    """Every GetVpcLinks item across all pages.

    GetVpcLinks has no botocore paginator config, so this walks NextToken by hand instead of
    the generic ``paginate`` helper above.
    """
    items: list[dict] = []
    kwargs: dict = {}
    while True:
        page = apigwv2.get_vpc_links(**kwargs)
        items.extend(page.get("Items", []))
        token = page.get("NextToken")
        if not token:
            return items
        kwargs["NextToken"] = token


def _template(name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.221.0.0/16"}},
            "SubnetA": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.221.0.0/24",
                "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
            }},
            "SubnetB": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.221.1.0/24",
                "AvailabilityZone": {"Fn::Select": [1, {"Fn::GetAZs": ""}]},
            }},
            "Sg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
                "GroupDescription": "sim2real vpc link security group", "VpcId": {"Ref": "Vpc"},
            }},
            "VpcLink": {"Type": "AWS::ApiGatewayV2::VpcLink", "Properties": {
                "Name": name,
                "SubnetIds": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                "SecurityGroupIds": [{"Ref": "Sg"}],
            }},
        },
        "Outputs": {
            "VpcLinkRef": {"Value": {"Ref": "VpcLink"}},
            "VpcLinkId": {"Value": {"Fn::GetAtt": ["VpcLink", "VpcLinkId"]}},
            "SubnetA": {"Value": {"Ref": "SubnetA"}},
            "SubnetB": {"Value": {"Ref": "SubnetB"}},
            "Sg": {"Value": {"Ref": "Sg"}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation VpcLink over a dedicated VPC reaches AVAILABLE with Ref as its id and the
    templated subnets and security group reading back through API Gateway V2's own GetVpcLink and
    an independent GetVpcLinks listing; deleting the stack removes it and its network.
    """
    cf = ctx.client("cloudformation")
    apigwv2 = ctx.client("apigatewayv2")
    ec2 = ctx.client("ec2")
    stack = ctx.unique_name("sim2real-apigwv2vl-")
    link_name = ctx.unique_name("sim2real-apigwv2vl-link-")

    stack_id = create_stack(ctx, cf, stack, _template(link_name))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    vpc_link_id = out["VpcLinkId"]
    assert out["VpcLinkRef"] == vpc_link_id, (
        f"Ref {out['VpcLinkRef']!r} != GetAtt VpcLinkId {vpc_link_id!r}"
    )

    # Ref against an independent read (GetVpcLinks by the declared Name), never a read keyed by
    # the Ref.
    matches = [l for l in _list_vpc_links(apigwv2) if l["Name"] == link_name]
    assert len(matches) == 1, f"GetVpcLinks found {matches!r} for Name {link_name!r}"
    listed = matches[0]
    assert listed["VpcLinkId"] == vpc_link_id, (
        f"GetVpcLinks reports VpcLinkId {listed['VpcLinkId']!r}, Ref/GetAtt was {vpc_link_id!r}"
    )

    # The network parents through EC2, found by the propagated stack tag, never by an Output.
    by_tag = [{"Name": "tag:sim2real", "Values": [stack]}]
    vpcs = paginate(ec2, "describe_vpcs", "Vpcs", Filters=by_tag)
    assert [v["CidrBlock"] for v in vpcs] == ["10.221.0.0/16"], f"DescribeVpcs found {vpcs!r}"
    in_vpc = [{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}]
    subnets = {s["SubnetId"]: s["CidrBlock"]
               for s in paginate(ec2, "describe_subnets", "Subnets", Filters=in_vpc)}
    assert sorted(subnets.values()) == ["10.221.0.0/24", "10.221.1.0/24"], f"subnets {subnets!r}"
    assert sorted(subnets) == sorted([out["SubnetA"], out["SubnetB"]]), (
        f"DescribeSubnets ids {sorted(subnets)!r} != the subnet Refs"
    )
    groups = [g for g in paginate(ec2, "describe_security_groups", "SecurityGroups", Filters=in_vpc)
              if g["GroupName"] != "default"]
    got = [(g["GroupId"], g["Description"]) for g in groups]
    assert got == [(out["Sg"], "sim2real vpc link security group")], f"security groups {got!r}"

    # Every templated property, through a direct GetVpcLink by the GetAtt id.
    direct = apigwv2.get_vpc_link(VpcLinkId=vpc_link_id)
    assert direct["VpcLinkStatus"] == "AVAILABLE", (
        f"expected AVAILABLE once CREATE_COMPLETE, GetVpcLink reports {direct['VpcLinkStatus']!r}"
    )
    assert direct["Name"] == link_name, f"GetVpcLink Name {direct['Name']!r} != {link_name!r}"
    assert sorted(direct["SubnetIds"]) == sorted(subnets), (
        f"GetVpcLink SubnetIds {direct['SubnetIds']!r}, expected {sorted(subnets)!r}"
    )
    assert direct["SecurityGroupIds"] == [out["Sg"]], (
        f"GetVpcLink SecurityGroupIds {direct['SecurityGroupIds']!r}, expected {[out['Sg']]!r}"
    )
    own_tags = {k: v for k, v in direct.get("Tags", {}).items() if not k.startswith("aws:")}
    assert own_tags == {"sim2real": stack}, f"non-CloudFormation tags were {own_tags!r}"

    delete_stack(cf, stack_id)
    until_raises(lambda: apigwv2.get_vpc_link(VpcLinkId=vpc_link_id))
    expect_error(lambda: apigwv2.get_vpc_link(VpcLinkId=vpc_link_id), *_NOT_FOUND)
    survivors = [l for l in _list_vpc_links(apigwv2) if l["Name"] == link_name]
    assert survivors == [], f"the deleted VpcLink is still listed: {survivors!r}"
    left = paginate(ec2, "describe_vpcs", "Vpcs", Filters=by_tag)
    assert left == [], f"the deleted stack's VPC is still described: {left!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
