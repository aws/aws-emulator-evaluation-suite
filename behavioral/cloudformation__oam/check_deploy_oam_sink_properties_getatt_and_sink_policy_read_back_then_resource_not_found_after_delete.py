"""deploy-oam-sink-properties-getatt-and-sink-policy-read-back-then-resource-not-found-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-oam-sink-properties-getatt-and-sink-policy-read-back-then-resource-not-found-after-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "oam"]

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


def _policy(principal):
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": principal},
            "Action": ["oam:CreateLink", "oam:UpdateLink"],
            "Resource": "*",
        }],
    }


def _template(sink_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Sink": {
                "Type": "AWS::Oam::Sink",
                "Properties": {
                    "Name": sink_name,
                    "Policy": _policy({"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}),
                    "Tags": {"sim2real-oam": sink_name},
                },
            },
        },
        "Outputs": {
            "SinkRef": {"Value": {"Ref": "Sink"}},
            "SinkArn": {"Value": {"Fn::GetAtt": ["Sink", "Arn"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control",
      "resource:account-singleton:oam-sink")
def run(ctx) -> None:
    """A CloudFormation AWS::Oam::Sink is real at OAM: Ref and GetAtt Arn equal the listed sink,
    the declared Name, Policy and tags read back, and deleting the stack removes it from OAM.
    A region holds one sink per account, so the account must start with none.

    Reference: https://docs.aws.amazon.com/OAM/latest/APIReference/API_GetSink.html
    """
    cfn = ctx.client("cloudformation")
    oam = ctx.client("oam")
    prior = paginate(oam, "list_sinks", "Items")
    assert prior == [], f"precondition: the account already has a sink in this region: {prior!r}"
    stack_name = ctx.unique_name("sim2real-behav-cfn-oamsk-")
    sink_name = ctx.unique_name("sim2real-oam-sink-")

    stack_id = create_stack(ctx, cfn, stack_name, _template(sink_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    # Ref and GetAtt against the independent ListSinks entry, never a read keyed by the Ref.
    listed = paginate(oam, "list_sinks", "Items")
    assert [(s["Name"], s["Arn"]) for s in listed] == [(sink_name, outputs["SinkRef"])], (
        f"ListSinks {listed!r}, Ref {outputs['SinkRef']!r}"
    )
    assert outputs["SinkArn"] == listed[0]["Arn"], f"GetAtt Arn {outputs['SinkArn']!r}"
    sink_arn = listed[0]["Arn"]
    sink = oam.get_sink(Identifier=sink_arn)
    got_tags = {k: v for k, v in sink.get("Tags", {}).items() if not k.startswith("aws:")}
    assert (sink["Name"], got_tags) == (sink_name, {"sim2real": stack_name,
                                                    "sim2real-oam": sink_name}), (
        f"sink (name, tags) {(sink['Name'], got_tags)!r}"
    )
    want_policy = _policy(f"arn:{stack_id.split(':')[1]}:iam::{ctx.account}:root")
    got_policy = json.loads(oam.get_sink_policy(SinkIdentifier=sink_arn)["Policy"])
    assert got_policy == want_policy, f"sink policy {got_policy!r}, expected {want_policy!r}"

    delete_stack(cfn, stack_id)
    until_raises(lambda: oam.get_sink(Identifier=sink_arn))
    gone = ("ResourceNotFoundException", "Resource not found.")
    expect_error(lambda: oam.get_sink(Identifier=sink_arn), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
