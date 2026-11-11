"""deploy-directconnect-gateway-association-invalid-gateway-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-directconnect-gateway-association-invalid-gateway-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "directconnect", "ec2"]

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

# Account masked; a registry-handler failure reason carries the request id and SDK attempt count.
_REJECTED = (
    "The VirtualGateway vgw-00000000 for owner <account> does not exist (Service: DirectConnect, "
    "Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)

_BAD_VGW_ID = "vgw-00000000"
_VPC_CIDR = "10.202.0.0/16"


def _template(dgw_name: str, associated_gateway=None) -> str:
    """A VPC with an attached VPN gateway and a Direct Connect gateway associated with
    ``associated_gateway``, the stack's own VPN gateway by default."""
    t = [{"Key": "sim2real-check", "Value": dgw_name}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR, "Tags": t}},
            "Vgw": {"Type": "AWS::EC2::VPNGateway", "Properties": {"Type": "ipsec.1", "Tags": t}},
            "Attach": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "VpnGatewayId": {"Ref": "Vgw"}},
            },
            "Dgw": {
                "Type": "AWS::DirectConnect::DirectConnectGateway",
                "Properties": {"DirectConnectGatewayName": dgw_name, "Tags": t},
            },
            "Assoc": {
                "Type": "AWS::DirectConnect::DirectConnectGatewayAssociation",
                "DependsOn": "Attach",
                "Properties": {
                    "DirectConnectGatewayId": {"Fn::GetAtt": ["Dgw", "DirectConnectGatewayId"]},
                    "AssociatedGatewayId": associated_gateway or {"Ref": "Vgw"},
                },
            },
        },
        "Outputs": {
            "DgwArn": {"Value": {"Ref": "Dgw"}},
            "DgwId": {"Value": {"Fn::GetAtt": ["Dgw", "DirectConnectGatewayId"]}},
            "VgwId": {"Value": {"Ref": "Vgw"}},
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "AssocId": {"Value": {"Ref": "Assoc"}},
        },
    })


def _gateway_state(dc, dgw_id: str) -> str:
    gateways = dc.describe_direct_connect_gateways(directConnectGatewayId=dgw_id)["directConnectGateways"]
    assert len(gateways) == 1, f"expected one gateway record for {dgw_id!r}, got {len(gateways)}"
    return gateways[0]["directConnectGatewayState"]


def _poll_state(poll, want: str, *, deadline_s: float = 180.0, poll_s: float = 2.0) -> str:
    """Poll ``poll()`` until it returns ``want`` or the deadline passes; return the last value."""
    deadline = time.monotonic() + deadline_s
    while True:
        state = poll()
        if state == want or time.monotonic() >= deadline:
            return state
        time.sleep(poll_s)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AssociatedGatewayId naming a nonexistent VPN gateway fails with Direct
    Connect's exact error, and the rollback deletes the Direct Connect gateway, the VPN gateway
    and the VPC the stack had created.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-directconnect-directconnectgatewayassociation.html
    """
    dc = ctx.client("directconnect")
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    bad_stack = ctx.unique_name("sim2real-assocbad-")
    bad_dgw_name = ctx.unique_name("sim2real-dgw-")

    bad_id = create_stack(ctx, cfn, bad_stack, _template(bad_dgw_name, _BAD_VGW_ID))
    status = wait_stack(cfn, bad_id, timeout_s=600.0)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )

    got_reason = handler_reason(failed_reason(stack_events(cfn, bad_id), "Assoc"), ctx.account)
    assert got_reason == _REJECTED, (
        f"expected the Assoc CREATE_FAILED reason {_REJECTED!r}, got {got_reason!r}"
    )

    resources = cfn.describe_stack_resources(StackName=bad_id)["StackResources"]
    dgw_arns = [r["PhysicalResourceId"] for r in resources
                if r["ResourceType"] == "AWS::DirectConnect::DirectConnectGateway"]
    assert len(dgw_arns) == 1, f"expected exactly one gateway to have been created, got {len(dgw_arns)}"
    arn_match = re.fullmatch(
        rf"arn:aws[a-z-]*:directconnect::{re.escape(ctx.account)}:dx-gateway/([0-9a-f-]+)", dgw_arns[0]
    )
    assert arn_match, f"the rolled-back gateway's physical id {dgw_arns[0]!r} is not a dx-gateway ARN"
    bad_dgw_id = arn_match.group(1)

    # The rollback itself removed the gateway: Direct Connect says so before the stack is deleted.
    bad_gw_after = _poll_state(lambda: _gateway_state(dc, bad_dgw_id), "deleted")
    assert bad_gw_after == "deleted", (
        f"expected the rolled-back gateway's state to be 'deleted', Direct Connect reports "
        f"{bad_gw_after!r}"
    )
    # The rollback also removed the stack's VPN gateway and VPC, as EC2 reports.
    ec2_ids = {r["LogicalResourceId"]: r["PhysicalResourceId"] for r in resources
               if r["LogicalResourceId"] in ("Vgw", "Vpc")}
    assert set(ec2_ids) == {"Vgw", "Vpc"}, f"expected the stack's Vgw and Vpc, got {ec2_ids!r}"
    vgws = ec2.describe_vpn_gateways(VpnGatewayIds=[ec2_ids["Vgw"]])["VpnGateways"]
    assert [v["State"] for v in vgws] == ["deleted"], (
        f"expected the rolled-back VPN gateway's State to be 'deleted', EC2 reports {vgws!r}"
    )
    vpc_gone = ("InvalidVpcID.NotFound", f"The vpc ID '{ec2_ids['Vpc']}' does not exist")
    expect_error(lambda: ec2.describe_vpcs(VpcIds=[ec2_ids["Vpc"]]), *vpc_gone)
    delete_stack(cfn, bad_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
