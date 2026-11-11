"""deploy-cfn-ec2-transit-gateway-route-table-association-duplicate-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-ec2-transit-gateway-route-table-association-duplicate-rejected-and-rolled-back"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


# ---- Check-specific: the template, then run(). ----

_VPC_CIDR = "10.82.0.0/24"


def _template(name, az, second_association):
    """A gateway, one VPC attachment, two route tables, the attachment associated with the first;
    with ``second_association`` it is associated with the second as well."""
    resources = {
        "Tgw": {"Type": "AWS::EC2::TransitGateway", "Properties": {
            "Description": name,
            "DefaultRouteTableAssociation": "disable",
            "DefaultRouteTablePropagation": "disable",
        }},
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
        "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": _VPC_CIDR, "AvailabilityZone": az,
        }},
        "Attachment": {"Type": "AWS::EC2::TransitGatewayVpcAttachment", "Properties": {
            "TransitGatewayId": {"Ref": "Tgw"}, "VpcId": {"Ref": "Vpc"},
            "SubnetIds": [{"Ref": "Subnet"}],
        }},
        "RouteTableOne": {"Type": "AWS::EC2::TransitGatewayRouteTable",
                          "Properties": {"TransitGatewayId": {"Ref": "Tgw"}}},
        "RouteTableTwo": {"Type": "AWS::EC2::TransitGatewayRouteTable",
                          "Properties": {"TransitGatewayId": {"Ref": "Tgw"}}},
        "AssociationOne": {"Type": "AWS::EC2::TransitGatewayRouteTableAssociation", "Properties": {
            "TransitGatewayRouteTableId": {"Ref": "RouteTableOne"},
            "TransitGatewayAttachmentId": {"Ref": "Attachment"},
        }},
    }
    if second_association:
        resources["AssociationTwo"] = {
            "Type": "AWS::EC2::TransitGatewayRouteTableAssociation", "Properties": {
                "TransitGatewayRouteTableId": {"Ref": "RouteTableTwo"},
                "TransitGatewayAttachmentId": {"Ref": "Attachment"},
            }}
    outputs = {k: {"Value": {"Ref": k}} for k in
               ("Tgw", "Vpc", "Attachment", "RouteTableOne", "RouteTableTwo")}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _usable_az(ec2):
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert usable, "no available Availability Zone in this region"
    return usable[0]


def _associations(ec2, out):
    """``{route table id: [(attachment id, state)]}`` for both of the stack's route tables."""
    return {rt: [(a["TransitGatewayAttachmentId"], a["State"]) for a in paginate(
        ec2, "get_transit_gateway_route_table_associations", "Associations",
        TransitGatewayRouteTableId=rt)] for rt in (out["RouteTableOne"], out["RouteTableTwo"])}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A second CloudFormation TransitGatewayRouteTableAssociation for an attachment already
    associated elsewhere is refused AlreadyExists and rolls back, leaving only the first; the
    same stack without it deploys and reads back through EC2.
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-tgwassoc-")
    az = _usable_az(ec2)

    # Positive control: the attachment associated with one route table only.
    stack_id = create_stack(ctx, cfn, stack, _template(stack, az, False))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    attachments = paginate(ec2, "describe_transit_gateway_vpc_attachments",
                           "TransitGatewayVpcAttachments",
                           Filters=[{"Name": "tag:sim2real", "Values": [stack]}])
    got = [(a["TransitGatewayAttachmentId"], a["TransitGatewayId"], a["VpcId"], a["State"])
           for a in attachments]
    assert got == [(out["Attachment"], out["Tgw"], out["Vpc"], "available")], (
        f"attachments by stack tag {got!r}"
    )
    want = {out["RouteTableOne"]: [(out["Attachment"], "associated")], out["RouteTableTwo"]: []}
    assert _associations(ec2, out) == want, f"control associations {_associations(ec2, out)!r}"

    # The rejected update: the same attachment associated with the second route table too.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack, az, True))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_ROLLBACK_COMPLETE", f"rejected update ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, stack_id), "AssociationTwo"),
                         ctx.account)
    rejected = (f"Transit Gateway Attachment {out['Attachment']} is already associated to a "
                "route table. (Service: Ec2, Status Code: 400, Request ID: <id>) "
                "(SDK Attempt Count: <n>)", "AlreadyExists")
    assert got == rejected, f"AssociationTwo reason {got!r}, expected {rejected!r}"
    # Rollback leaves exactly the first association, read through EC2 before the delete.
    assert _associations(ec2, out) == want, f"associations after rollback {_associations(ec2, out)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
