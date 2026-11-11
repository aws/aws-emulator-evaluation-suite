"""deploy-neptune-graph-provisioned-memory-out-of-range-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-neptune-graph-provisioned-memory-out-of-range-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "neptune-graph"]

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


_CREATE_TIMEOUT_S = 900.0
_REJECTED = (
    "1 validation error detected: Value '1' at 'provisionedMemory' failed to satisfy "
    "constraint: Member must have value greater than or equal to 16 (Service: NeptuneGraph, "
    "Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _graph_template(graph_name: str, provisioned_memory: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Graph": {
                "Type": "AWS::NeptuneGraph::Graph",
                "Properties": {
                    "GraphName": graph_name,
                    "ProvisionedMemory": provisioned_memory,
                    "ReplicaCount": 0,
                    "DeletionProtection": False,
                    "PublicConnectivity": False,
                    "Tags": [{"Key": "sim2real-res", "Value": graph_name}],
                },
            }
        },
        "Outputs": {
            "GraphId": {"Value": {"Ref": "Graph"}},
            "GraphArn": {"Value": {"Fn::GetAtt": ["Graph", "GraphArn"]}},
        },
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation NeptuneGraph Graph with ProvisionedMemory below 16 is refused.

    The stack rolls back with NeptuneGraph's exact validation reason and ListGraphs has no graph
    of that name, while the same template with ProvisionedMemory 16 reads back AVAILABLE.
    """
    cfn = ctx.client("cloudformation")
    ng = ctx.client("neptune-graph")

    bad_graph_name = ctx.unique_name("sim2real-ngbad-")
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-ngbadstk-"),
                          _graph_template(bad_graph_name, 1))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"ProvisionedMemory=1 ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Graph"), ctx.account,
                         bad_graph_name)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Absence, through neptune-graph's own API, before this check deletes the stack.
    names = [g["name"] for g in paginate(ng, "list_graphs", "graphs")]
    assert bad_graph_name not in names, f"ListGraphs reports the rejected graph: {names!r}"

    # Positive control: the same template with ProvisionedMemory 16.
    good_graph_name = ctx.unique_name("sim2real-nggood-")
    good_stack = ctx.unique_name("sim2real-nggoodstk-")
    good_id = create_stack(ctx, cfn, good_stack, _graph_template(good_graph_name, 16))
    status = wait_stack(cfn, good_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "CREATE_COMPLETE", f"ProvisionedMemory=16 ended {status!r}"
    out = stack_outputs(cfn, good_id)
    listed = [g["id"] for g in paginate(ng, "list_graphs", "graphs") if g["name"] == good_graph_name]
    assert listed == [out["GraphId"]], f"ListGraphs ids for {good_graph_name!r}: {listed!r}"
    graph = ng.get_graph(graphIdentifier=out["GraphId"])
    got = (graph["name"], graph["arn"], graph["status"], graph["provisionedMemory"],
           graph["replicaCount"], graph["deletionProtection"], graph["publicConnectivity"])
    want = (good_graph_name, out["GraphArn"], "AVAILABLE", 16, 0, False, False)
    assert got == want, f"control graph reads {got!r}, expected {want!r}"
    graph_tags = {k: v for k, v in ng.list_tags_for_resource(resourceArn=graph["arn"])["tags"].items()
                  if not k.startswith("aws:")}
    want_tags = {"sim2real": good_stack, "sim2real-res": good_graph_name}
    assert graph_tags == want_tags, f"control graph tags {graph_tags!r}, expected {want_tags!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
