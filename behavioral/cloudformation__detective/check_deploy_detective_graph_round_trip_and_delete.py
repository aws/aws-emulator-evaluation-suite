"""deploy-detective-graph-round-trip-and-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-detective-graph-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "detective"]

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


_TAG_KEY = "sim2real-graph"


def _template(tag_value: str) -> str:
    return f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Graph:
    Type: AWS::Detective::Graph
    Properties:
      Tags:
        - Key: {_TAG_KEY}
          Value: "{tag_value}"
Outputs:
  GraphArn:
    Value: !Ref Graph
  GraphArnAtt:
    Value: !GetAtt Graph.Arn
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control",
      "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Detective::Graph's Ref and GetAtt Arn equal the account's one
    behavior graph in an independent ListGraphs read, with its templated Tags read back through
    ListTagsForResource; deleting the stack removes the graph and its tags.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-detective-graph.html
    """
    d = ctx.client("detective")
    cfn = ctx.client("cloudformation")

    # One behavior graph per account and Region: a graph already there is never adopted, since
    # this stack's delete would remove it.
    existing = _list_all_graph_arns(d)
    if existing:
        raise AssertionError(f"precondition: this Region already has a behavior graph {existing!r}")

    stack_name = ctx.unique_name("sim2real-behav-detective-graph-")
    tag_value = ctx.unique_name("sim2real-detective-graph-")
    stack_id = create_stack(ctx, cfn, stack_name, _template(tag_value))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack_id!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cfn, stack_id)
    graph_arn = outputs["GraphArn"]
    graph_arn_att = outputs["GraphArnAtt"]
    assert graph_arn == graph_arn_att, (
        f"Ref {graph_arn!r} does not equal Fn::GetAtt Graph.Arn {graph_arn_att!r}"
    )

    # Independent read: Detective's own ListGraphs, never a describe keyed off the Ref itself.
    graphs = _list_all_graph_arns(d)
    assert graphs == [graph_arn], f"expected ListGraphs to show only {graph_arn!r}, got {graphs!r}"

    got_tags = {k: v for k, v in d.list_tags_for_resource(ResourceArn=graph_arn)["Tags"].items()
                if not k.startswith("aws:")}
    # AWS keeps only the template tag: the stack-level sim2real tag does not reach the graph.
    want_tags = {_TAG_KEY: tag_value}
    assert got_tags == want_tags, f"ListTagsForResource reads {got_tags!r}, expected {want_tags!r}"

    delete_stack(cfn, stack_id)

    remaining = _list_all_graph_arns(d)
    assert graph_arn not in remaining, (
        f"{graph_arn!r} still present in ListGraphs after stack delete: {remaining!r}"
    )

    tags_for_resource_gone = ("NotFoundException", "Resource was not found")
    expect_error(lambda: d.list_tags_for_resource(ResourceArn=graph_arn), *tags_for_resource_gone)


def _list_all_graph_arns(d) -> list[str]:
    arns: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = d.list_graphs(**kwargs)
        arns.extend(g["Arn"] for g in resp.get("GraphList", []))
        token = resp.get("NextToken")
        if not token:
            break
    return arns


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
