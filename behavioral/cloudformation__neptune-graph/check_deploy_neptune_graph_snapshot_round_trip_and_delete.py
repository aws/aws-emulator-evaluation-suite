"""deploy-neptune-graph-snapshot-round-trip-and-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-neptune-graph-snapshot-round-trip-and-delete"
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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


# ---- Check-specific: the template, then run(). ----

_CREATE_TIMEOUT_S = 1200.0


def _template(tag_value: str, graph_name: str, snapshot_name: str) -> str:
    t = [{"Key": "sim2real-res", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Graph": {
                "Type": "AWS::NeptuneGraph::Graph",
                "Properties": {
                    "GraphName": graph_name,
                    "ProvisionedMemory": 16,
                    "ReplicaCount": 0,
                    "DeletionProtection": False,
                    "PublicConnectivity": False,
                    "Tags": t,
                },
            },
            "Snapshot": {
                "Type": "AWS::NeptuneGraph::GraphSnapshot",
                "Properties": {
                    "GraphIdentifier": {"Ref": "Graph"},
                    "SnapshotName": snapshot_name,
                    "Tags": t,
                },
            },
        },
        "Outputs": {
            "GraphId": {"Value": {"Ref": "Graph"}},
            "GraphArn": {"Value": {"Fn::GetAtt": ["Graph", "GraphArn"]}},
            "GraphEndpoint": {"Value": {"Fn::GetAtt": ["Graph", "Endpoint"]}},
            "SnapshotArn": {"Value": {"Ref": "Snapshot"}},
            "SnapshotId": {"Value": {"Fn::GetAtt": ["Snapshot", "Id"]}},
        },
    })


def _user_tags(ng, arn: str) -> dict:
    tag_map = ng.list_tags_for_resource(resourceArn=arn)["tags"]
    return {k: v for k, v in tag_map.items() if not k.startswith("aws:")}


def _masked_error(fn, account: str) -> tuple[str, str]:
    """``(code, message with the account masked)`` of the error ``fn()`` must raise."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], masked(exc.response["Error"]["Message"], account)
    raise AssertionError(f"expected an error but the call succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation NeptuneGraph Graph and GraphSnapshot read back through neptune-graph.

    Each Ref, GetAtt, templated property and tag matches; deleting the stack removes both, each
    refused by its own exact NotFound.
    """
    cfn = ctx.client("cloudformation")
    ng = ctx.client("neptune-graph")
    stack = ctx.unique_name("sim2real-ngsnap-stack-")
    graph_name = ctx.unique_name("sim2real-ngraph-")
    snapshot_name = ctx.unique_name("sim2real-ngsnap-")
    tag_value = ctx.unique_name("sim2real-ngsnap-res-")
    want_tags = {"sim2real": stack, "sim2real-res": tag_value}

    stack_id = create_stack(ctx, cfn, stack, _template(tag_value, graph_name, snapshot_name))
    status = wait_stack(cfn, stack_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    graph_id, snapshot_id, snapshot_arn = out["GraphId"], out["SnapshotId"], out["SnapshotArn"]

    # Graph: Ref against an independent listing by name, then every templated property.
    listed = [g["id"] for g in paginate(ng, "list_graphs", "graphs") if g["name"] == graph_name]
    assert listed == [graph_id], f"ListGraphs ids for {graph_name!r}: {listed!r}, Ref {graph_id!r}"
    graph = ng.get_graph(graphIdentifier=graph_id)
    got = (graph["arn"], graph["endpoint"], graph["status"], graph["provisionedMemory"],
           graph["replicaCount"], graph["deletionProtection"], graph["publicConnectivity"])
    want = (out["GraphArn"], out["GraphEndpoint"], "AVAILABLE", 16, 0, False, False)
    assert got == want, f"graph reads {got!r}, expected {want!r}"
    graph_tags = _user_tags(ng, graph["arn"])
    assert graph_tags == want_tags, f"graph tags {graph_tags!r}, expected {want_tags!r}"

    # GraphSnapshot: Ref (the ARN) against the listing under the graph, then its properties.
    snaps = [(s["id"], s["arn"]) for s in paginate(
        ng, "list_graph_snapshots", "graphSnapshots", graphIdentifier=graph_id)
        if s["name"] == snapshot_name]
    assert snaps == [(snapshot_id, snapshot_arn)], (
        f"ListGraphSnapshots for {snapshot_name!r}: {snaps!r}"
    )
    snap = ng.get_graph_snapshot(snapshotIdentifier=snapshot_id)
    got = (snap["arn"], snap["name"], snap["sourceGraphId"], snap["status"])
    assert got == (snapshot_arn, snapshot_name, graph_id, "AVAILABLE"), f"snapshot reads {got!r}"
    snap_tags = _user_tags(ng, snapshot_arn)
    assert snap_tags == want_tags, f"snapshot tags {snap_tags!r}, expected {want_tags!r}"

    # A snapshot outlives its graph in Neptune Analytics, so its NotFound is its own delete.
    delete_stack(cfn, stack_id)
    got = _masked_error(lambda: ng.get_graph_snapshot(snapshotIdentifier=snapshot_id), ctx.account)
    want = ("ResourceNotFoundException",
            f"No snapshot found for customer [<account>] with snapshot id [{snapshot_id}]")
    assert got == want, f"GetGraphSnapshot after the delete: {got!r}, expected {want!r}"
    got = _masked_error(lambda: ng.get_graph(graphIdentifier=graph_id), ctx.account)
    want = ("ResourceNotFoundException",
            f"No graph found for customer [<account>] with graph id [{graph_id}]")
    assert got == want, f"GetGraph after the delete: {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
