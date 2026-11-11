"""deploy-flow-version-alias-round-trip-then-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-flow-version-alias-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["bedrock-agent", "cloudformation"]

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

_GET_FLOW_NOT_FOUND = (
    "ResourceNotFoundException",
    "Couldn't perform GetFlow operation. Failed to retrieve resource type Flow because it "
    "doesn't exist. Check the resource ID and retry your request.",
)


def _template(flow_name, alias_name, with_children=True):
    body = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "FlowExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "bedrock.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                            "Condition": {
                                "StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}},
                                "ArnLike": {"aws:SourceArn": {
                                    "Fn::Sub": "arn:${AWS::Partition}:bedrock:${AWS::Region}:"
                                               "${AWS::AccountId}:flow/*"
                                }},
                            },
                        }],
                    },
                },
            },
            "FlowResource": {
                "Type": "AWS::Bedrock::Flow",
                "Properties": {
                    "Name": flow_name,
                    "ExecutionRoleArn": {"Fn::GetAtt": ["FlowExecutionRole", "Arn"]},
                    "Definition": {
                        "Nodes": [
                            {"Name": "FlowInputNode", "Type": "Input",
                             "Configuration": {"Input": {}},
                             "Outputs": [{"Name": "document", "Type": "String"}]},
                            {"Name": "FlowOutputNode", "Type": "Output",
                             "Configuration": {"Output": {}},
                             "Inputs": [{"Name": "document", "Type": "String",
                                         "Expression": "$.data"}]},
                        ],
                        "Connections": [
                            {"Name": "InputToOutput", "Type": "Data", "Source": "FlowInputNode",
                             "Target": "FlowOutputNode",
                             "Configuration": {"Data": {"SourceOutput": "document",
                                                         "TargetInput": "document"}}},
                        ],
                    },
                },
            },
            "FlowVersionResource": {
                "Type": "AWS::Bedrock::FlowVersion",
                "Properties": {"FlowArn": {"Ref": "FlowResource"}},
            },
            "FlowAliasResource": {
                "Type": "AWS::Bedrock::FlowAlias",
                "Properties": {
                    "Name": alias_name,
                    "FlowArn": {"Ref": "FlowResource"},
                    "RoutingConfiguration": [
                        {"FlowVersion": {"Fn::GetAtt": ["FlowVersionResource", "Version"]}}
                    ],
                },
            },
        },
        "Outputs": {
            "FlowArn": {"Value": {"Ref": "FlowResource"}},
            "FlowId": {"Value": {"Fn::GetAtt": ["FlowResource", "Id"]}},
            "FlowVersionNum": {"Value": {"Fn::GetAtt": ["FlowVersionResource", "Version"]}},
            "FlowVersionRef": {"Value": {"Ref": "FlowVersionResource"}},
            "FlowAliasId": {"Value": {"Fn::GetAtt": ["FlowAliasResource", "Id"]}},
            "FlowAliasArn": {"Value": {"Fn::GetAtt": ["FlowAliasResource", "Arn"]}},
            "FlowAliasRef": {"Value": {"Ref": "FlowAliasResource"}},
        },
    }
    if not with_children:
        for logical in ("FlowVersionResource", "FlowAliasResource"):
            del body["Resources"][logical]
        body["Outputs"] = {k: v for k, v in body["Outputs"].items() if k in ("FlowArn", "FlowId")}
    return json.dumps(body)


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Flow, FlowVersion and FlowAlias read back through bedrock-agent.

    An update dropping the version and alias removes both from the same Flow, and deleting the
    stack removes the Flow.
    """
    cfn = ctx.client("cloudformation")
    bedrock_agent = ctx.client("bedrock-agent")
    stack = ctx.unique_name("sim2real-cfnflow-")
    flow_name = ctx.unique_name("sim2real-flow-")
    alias_name = ctx.unique_name("sim2real-falias-")

    stack_id = create_stack(ctx, cfn, stack, _template(flow_name, alias_name),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    out = stack_outputs(cfn, stack_id)
    flow_arn, flow_id = out["FlowArn"], out["FlowId"]
    version_num, version_ref = out["FlowVersionNum"], out["FlowVersionRef"]
    alias_id, alias_arn, alias_ref = out["FlowAliasId"], out["FlowAliasArn"], out["FlowAliasRef"]

    # FlowVersion's and FlowAlias's composite Ref, built from the service's own GetAtt values.
    assert version_ref == f"{flow_arn}|{version_num}", (
        f"FlowVersion Ref {version_ref!r} != FlowArn|Version {flow_arn}|{version_num}"
    )
    assert alias_ref == f"{alias_arn}|{flow_arn}", (
        f"FlowAlias Ref {alias_ref!r} != Arn|FlowArn {alias_arn}|{flow_arn}"
    )

    # Ref against an independent read (ListFlows by the declared name), never a read keyed by Ref.
    flows = paginate(bedrock_agent, "list_flows", "flowSummaries")
    matches = [f for f in flows if f["name"] == flow_name]
    assert len(matches) == 1, f"ListFlows found {matches!r} for name {flow_name!r}"
    assert matches[0]["id"] == flow_id, f"ListFlows id {matches[0]['id']!r} != {flow_id!r}"
    assert matches[0]["arn"] == flow_arn, f"ListFlows arn {matches[0]['arn']!r} != {flow_arn!r}"

    flow = bedrock_agent.get_flow(flowIdentifier=flow_id)
    assert (flow["id"], flow["arn"], flow["name"]) == (flow_id, flow_arn, flow_name), (
        f"GetFlow returned {(flow['id'], flow['arn'], flow['name'])!r}"
    )
    # AWS::Bedrock::Flow prepares as part of stack creation, unlike the raw CreateFlow API.
    assert flow["status"] == "Prepared", f"expected Prepared right after CFN deploy, got {flow['status']!r}"

    versions = paginate(bedrock_agent, "list_flow_versions", "flowVersionSummaries",
                        flowIdentifier=flow_id)
    vmatches = [v for v in versions if v["version"] == version_num]
    assert len(vmatches) == 1, f"ListFlowVersions found {vmatches!r} for version {version_num!r}"

    fv = bedrock_agent.get_flow_version(flowIdentifier=flow_id, flowVersion=version_num)
    assert (fv["arn"], fv["version"], fv["name"], fv["status"]) == (
        flow_arn, version_num, flow_name, "Prepared"
    ), f"GetFlowVersion returned {(fv['arn'], fv['version'], fv['name'], fv['status'])!r}"

    aliases = paginate(bedrock_agent, "list_flow_aliases", "flowAliasSummaries",
                       flowIdentifier=flow_id)
    amatches = [a for a in aliases if a["name"] == alias_name]
    assert len(amatches) == 1, f"ListFlowAliases found {amatches!r} for name {alias_name!r}"
    assert amatches[0]["id"] == alias_id, f"ListFlowAliases id {amatches[0]['id']!r} != {alias_id!r}"

    fa = bedrock_agent.get_flow_alias(flowIdentifier=flow_id, aliasIdentifier=alias_id)
    assert (fa["id"], fa["arn"], fa["flowId"], fa["name"]) == (
        alias_id, alias_arn, flow_id, alias_name
    ), f"GetFlowAlias returned {(fa['id'], fa['arn'], fa['flowId'], fa['name'])!r}"
    assert fa["routingConfiguration"] == [{"flowVersion": version_num}], (
        f"GetFlowAlias routingConfiguration {fa['routingConfiguration']!r} != "
        f"[{{'flowVersion': {version_num!r}}}]"
    )

    # Children before the parent: an update dropping the version and the alias removes both from
    # the same Flow (createdAt unchanged) while the Flow still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(flow_name, alias_name, False),
                     Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"
    left = ([a for a in paginate(bedrock_agent, "list_flow_aliases", "flowAliasSummaries",
                                 flowIdentifier=flow_id) if a["name"] == alias_name],
            [v for v in paginate(bedrock_agent, "list_flow_versions", "flowVersionSummaries",
                                 flowIdentifier=flow_id) if v["version"] == version_num])
    assert left == ([], []), f"the Flow still lists the removed alias / version: {left!r}"
    after = bedrock_agent.get_flow(flowIdentifier=flow_id)
    assert after["createdAt"] == flow["createdAt"], (
        f"the Flow createdAt changed across the update: {after['createdAt']!r}"
    )

    delete_stack(cfn, stack_id)
    until_raises(lambda: bedrock_agent.get_flow(flowIdentifier=flow_id))
    expect_error(lambda: bedrock_agent.get_flow(flowIdentifier=flow_id), *_GET_FLOW_NOT_FOUND)
    remaining = [f for f in paginate(bedrock_agent, "list_flows", "flowSummaries")
                 if f["name"] == flow_name]
    assert remaining == [], f"{flow_name!r} still listed by ListFlows after the stack delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
