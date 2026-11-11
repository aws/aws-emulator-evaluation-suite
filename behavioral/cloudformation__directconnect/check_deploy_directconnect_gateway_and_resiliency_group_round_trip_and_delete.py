"""deploy-directconnect-gateway-and-resiliency-group-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-directconnect-gateway-and-resiliency-group-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "directconnect"]

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

_ASN = "64512"
_MODEL = "basic-resiliency"


def _template(dgw_name: str, rg_name: str, tag_value: str) -> str:
    tags = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Dgw": {
                "Type": "AWS::DirectConnect::DirectConnectGateway",
                "Properties": {"DirectConnectGatewayName": dgw_name, "AmazonSideAsn": _ASN,
                               "Tags": tags},
            },
            "Rg": {
                "Type": "AWS::DirectConnect::ResiliencyGroup",
                "Properties": {"ResiliencyGroupName": rg_name,
                               "IntendedResiliencyModel": _MODEL, "Tags": tags},
            },
        },
        "Outputs": {
            "DgwArn": {"Value": {"Ref": "Dgw"}},
            "DgwId": {"Value": {"Fn::GetAtt": ["Dgw", "DirectConnectGatewayId"]}},
            "RgArn": {"Value": {"Ref": "Rg"}},
            "RgId": {"Value": {"Fn::GetAtt": ["Rg", "ResiliencyGroupId"]}},
        },
    })


def _list_resiliency_groups(dc) -> list[dict]:
    """Every ListResiliencyGroups item across all pages; botocore models no paginator for it."""
    out, kw = [], {}
    while True:
        page = dc.list_resiliency_groups(**kw)
        out += page["items"]
        if not page.get("nextToken"):
            return out
        kw["nextToken"] = page["nextToken"]


def _wait_terminal_state(poll, terminal: set[str], *, deadline_s: float = 120.0,
                          poll_s: float = 2.0) -> str:
    """Poll ``poll()`` (returns the resource's own state string) to one of ``terminal``."""
    deadline = time.monotonic() + deadline_s
    while True:
        state = poll()
        if state in terminal:
            return state
        assert time.monotonic() < deadline, f"still {state!r} after {deadline_s}s"
        time.sleep(poll_s)


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::DirectConnect::DirectConnectGateway and ResiliencyGroup each reach
    Direct Connect's own 'available' state with Ref, Fn::GetAtt and tags matching its record;
    deleting the stack drives both to Direct Connect's 'deleted' tombstone.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-directconnect-directconnectgateway.html
    """
    dc = ctx.client("directconnect")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-dcrgw-")
    dgw_name = ctx.unique_name("sim2real-dgw-")
    rg_name = ctx.unique_name("sim2real-rg-")

    stack_id = create_stack(ctx, cfn, stack, _template(dgw_name, rg_name, CHECK))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    dgw_arn, dgw_id = outputs["DgwArn"], outputs["DgwId"]
    rg_arn, rg_id = outputs["RgArn"], outputs["RgId"]
    assert dgw_arn == f"arn:{partition}:directconnect::{ctx.account}:dx-gateway/{dgw_id}", (
        f"expected Ref Dgw to be the gateway's ARN built from its GetAtt id {dgw_id!r}, "
        f"got {dgw_arn!r}"
    )
    assert rg_arn == f"arn:{partition}:directconnect::{ctx.account}:dx-resiliency-group/{rg_id}", (
        f"expected Ref Rg to be the group's ARN built from its GetAtt id {rg_id!r}, got {rg_arn!r}"
    )

    # Both GetAtt ids (and so both Refs) against an independent read by the declared names.
    listed = [g["directConnectGatewayId"]
              for g in paginate(dc, "describe_direct_connect_gateways", "directConnectGateways")
              if g["directConnectGatewayName"] == dgw_name]
    assert listed == [dgw_id], f"the gateways named {dgw_name!r} are {listed!r}, GetAtt {dgw_id!r}"
    listed = [(g["resiliencyGroupId"], g["resiliencyGroupArn"]) for g in _list_resiliency_groups(dc)
              if g["resiliencyGroupName"] == rg_name]
    assert listed == [(rg_id, rg_arn)], (
        f"the resiliency groups named {rg_name!r} are {listed!r}, GetAtt and Ref "
        f"{(rg_id, rg_arn)!r}"
    )

    gw = _wait_terminal_state(
        lambda: dc.describe_direct_connect_gateways(directConnectGatewayId=dgw_id)
        ["directConnectGateways"][0]["directConnectGatewayState"],
        {"available", "deleting", "deleted"},
    )
    assert gw == "available", f"expected the gateway's state to be 'available', Direct Connect reports {gw!r}"
    gw_record = dc.describe_direct_connect_gateways(directConnectGatewayId=dgw_id)["directConnectGateways"][0]
    assert gw_record["directConnectGatewayName"] == dgw_name, (
        f"expected DirectConnectGatewayName {dgw_name!r}, Direct Connect reports "
        f"{gw_record['directConnectGatewayName']!r}"
    )
    assert gw_record["amazonSideAsn"] == int(_ASN), (
        f"expected AmazonSideAsn {_ASN}, Direct Connect reports {gw_record['amazonSideAsn']!r}"
    )

    state = _wait_terminal_state(
        lambda: dc.get_resiliency_group(resiliencyGroupId=rg_id)["resiliencyGroup"]["state"],
        {"available", "deleting", "deleted"},
    )
    assert state == "available", f"expected the resiliency group's state to be 'available', Direct Connect reports {state!r}"
    rg = dc.get_resiliency_group(resiliencyGroupId=rg_id)["resiliencyGroup"]
    assert rg["resiliencyGroupArn"] == rg_arn, (
        f"expected the group's own ARN to equal Ref Rg {rg_arn!r}, Direct Connect reports "
        f"{rg['resiliencyGroupArn']!r}"
    )
    assert rg["resiliencyGroupName"] == rg_name, (
        f"expected ResiliencyGroupName {rg_name!r}, Direct Connect reports {rg['resiliencyGroupName']!r}"
    )
    # IntendedResiliencyModel is write-only: GetResiliencyGroup does not return it.
    assert rg["resiliencyGroupId"] == rg_id, (
        f"expected resiliencyGroupId {rg_id!r} (GetAtt ResiliencyGroupId), Direct Connect reports "
        f"{rg['resiliencyGroupId']!r}"
    )
    assert gw_record["directConnectGatewayId"] == dgw_id, (
        f"expected directConnectGatewayId {dgw_id!r}, Direct Connect reports "
        f"{gw_record['directConnectGatewayId']!r}"
    )
    # The template tag, exactly; the stack's own sim2real tag is not asserted here.
    rg_tags = {t["key"]: t.get("value") for t in rg.get("tags", [])}
    got = {k: v for k, v in rg_tags.items() if k != "sim2real" and not k.startswith("aws:")}
    assert got == {"sim2real-check": CHECK}, f"the resiliency group's tags are {rg_tags!r}"
    gw_tags = [
        {t["key"]: t.get("value") for t in r["tags"]}
        for r in dc.describe_tags(resourceArns=[dgw_arn])["resourceTags"] if r["resourceArn"] == dgw_arn
    ]
    got = [{k: v for k, v in t.items() if k != "sim2real" and not k.startswith("aws:")}
           for t in gw_tags]
    assert got == [{"sim2real-check": CHECK}], f"the gateway's tags are {gw_tags!r}"

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)

    # A deleted Direct Connect gateway and resiliency group are documented tombstones, not a
    # NotFound: each stays describable with its state set to 'deleted'.
    gw_after = _wait_terminal_state(
        lambda: dc.describe_direct_connect_gateways(directConnectGatewayId=dgw_id)
        ["directConnectGateways"][0]["directConnectGatewayState"],
        {"deleted"},
    )
    assert gw_after == "deleted", (
        f"expected the deleted gateway's state to be 'deleted', Direct Connect reports {gw_after!r}"
    )
    rg_after = _wait_terminal_state(
        lambda: dc.get_resiliency_group(resiliencyGroupId=rg_id)["resiliencyGroup"]["state"],
        {"deleted"},
    )
    assert rg_after == "deleted", (
        f"expected the deleted resiliency group's state to be 'deleted', Direct Connect reports "
        f"{rg_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
