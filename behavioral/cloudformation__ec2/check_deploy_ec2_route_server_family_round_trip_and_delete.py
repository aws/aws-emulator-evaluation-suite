"""deploy-ec2-route-server-family-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-route-server-family-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

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


_VPC_CIDR = "10.97.0.0/16"
_AMAZON_SIDE_ASN = 64512


def _not_associated(rs_id: str) -> tuple[str, str]:
    return ("InvalidRouteServerId.NotAssociated", f"Route Server {rs_id} is not associated with a VPC.")


def _template(tag_value: str, with_children: bool = True) -> str:
    resources = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
        "RouteTable": {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": {"Ref": "Vpc"}}},
        "RouteServer": {
            "Type": "AWS::EC2::RouteServer",
            "Properties": {"AmazonSideAsn": _AMAZON_SIDE_ASN,
                           "Tags": [{"Key": "sim2real-res", "Value": tag_value}]},
        },
    }
    outputs = {
        "VpcId": {"Value": {"Ref": "Vpc"}},
        "RouteTableId": {"Value": {"Ref": "RouteTable"}},
        "RouteServerId": {"Value": {"Ref": "RouteServer"}},
        "RouteServerArn": {"Value": {"Fn::GetAtt": ["RouteServer", "Arn"]}},
    }
    if with_children:
        resources["Association"] = {
            "Type": "AWS::EC2::RouteServerAssociation",
            "Properties": {"RouteServerId": {"Ref": "RouteServer"}, "VpcId": {"Ref": "Vpc"}},
        }
        resources["Propagation"] = {
            "Type": "AWS::EC2::RouteServerPropagation",
            "DependsOn": "Association",
            "Properties": {"RouteServerId": {"Ref": "RouteServer"},
                           "RouteTableId": {"Ref": "RouteTable"}},
        }
        outputs["AssociationRef"] = {"Value": {"Ref": "Association"}}
        outputs["PropagationRef"] = {"Value": {"Ref": "Propagation"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation route server, VPC association and route-table propagation read back.

    An update dropping the association and propagation leaves the same route server unassociated;
    deleting the stack leaves the route server in its 'deleted' tombstone state.
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-cfnrs-")
    tag_value = ctx.unique_name("sim2real-cfnrs-res-")

    stack_id = create_stack(ctx, cfn, stack, _template(tag_value))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    vpc_id, rt_id, rs_id = out["VpcId"], out["RouteTableId"], out["RouteServerId"]

    # RouteServer: Ref == the one route server carrying this run's tag; GetAtt Arn == the
    # documented ARN of that id (DescribeRouteServers carries no Arn field).
    tagged = paginate(ec2, "describe_route_servers", "RouteServers",
                      Filters=[{"Name": "tag:sim2real-res", "Values": [tag_value]}])
    assert [r["RouteServerId"] for r in tagged] == [rs_id], f"tagged route servers {tagged!r}"
    rs = tagged[0]
    want_arn = f"arn:{partition}:ec2:{ctx.region}:{ctx.account}:route-server/{rs_id}"
    assert out["RouteServerArn"] == want_arn, f"GetAtt Arn {out['RouteServerArn']!r} != {want_arn!r}"
    got = (rs["AmazonSideAsn"], rs["State"],
           {"Key": "sim2real-res", "Value": tag_value} in rs.get("Tags", []))
    assert got == (_AMAZON_SIDE_ASN, "available", True), f"route server reads {got!r}"

    # Association and Propagation: Ref is the "<RouteServerId>|<VpcId|RouteTableId>" compound id.
    assert (out["AssociationRef"], out["PropagationRef"]) == (f"{rs_id}|{vpc_id}", f"{rs_id}|{rt_id}"), (
        f"compound Refs {out['AssociationRef']!r}, {out['PropagationRef']!r}"
    )
    assocs = ec2.get_route_server_associations(RouteServerId=rs_id)["RouteServerAssociations"]
    got = [(a["RouteServerId"], a["VpcId"], a["State"]) for a in assocs]
    assert got == [(rs_id, vpc_id, "associated")], f"associations {got!r}"
    props = ec2.get_route_server_propagations(
        RouteServerId=rs_id, RouteTableId=rt_id)["RouteServerPropagations"]
    got = [(p["RouteServerId"], p["RouteTableId"], p["State"]) for p in props]
    assert got == [(rs_id, rt_id, "available")], f"propagations {got!r}"

    # Children before parent: an update dropping both leaves the same route server unassociated.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(tag_value, with_children=False))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"
    states = [r["State"] for r in ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"]]
    assert states == ["available"], f"route server after the update reads {states!r}"
    not_associated = _not_associated(rs_id)
    expect_error(lambda: ec2.get_route_server_associations(RouteServerId=rs_id), *not_associated)

    delete_stack(cfn, stack_id)
    # A deleted route server keeps listing in its documented tombstone state rather than 404ing.
    states = [r["State"] for r in ec2.describe_route_servers(RouteServerIds=[rs_id])["RouteServers"]]
    assert states == ["deleted"], f"route server after the stack delete reads {states!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
