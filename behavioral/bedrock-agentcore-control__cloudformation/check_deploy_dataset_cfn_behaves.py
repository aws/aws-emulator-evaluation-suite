"""deploy-dataset-cfn-behaves."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-dataset-cfn-behaves"
GROUP = "deploy"
SERVICES = ["bedrock-agentcore-control", "cloudformation"]

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


# ---- Check-specific: the template, then run(). ----

_EXAMPLE_TURNS = [{"role": "user", "input": "hello", "content": "hello"}]


def _template(name: str, with_turns: bool = True) -> str:
    example = {"scenario_id": "sim2real-scenario-1"}
    if with_turns:
        example["turns"] = _EXAMPLE_TURNS
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Dataset": {
                "Type": "AWS::BedrockAgentCore::Dataset",
                "Properties": {
                    "DatasetName": name,
                    "SchemaType": "AGENTCORE_EVALUATION_PREDEFINED_V1",
                    "Source": {"InlineExamples": {"Examples": [example]}},
                },
            },
        },
        "Outputs": {
            "DatasetArn": {"Value": {"Ref": "Dataset"}},
            "DatasetId": {"Value": {"Fn::GetAtt": ["Dataset", "DatasetId"]}},
        },
    })


def _datasets(control, name: str) -> list:
    return [(d["datasetId"], d["datasetArn"]) for d in paginate(control, "list_datasets", "datasets")
            if d["datasetName"] == name]


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "-")


def _poll(probe, predicate, timeout_s=300.0):
    """``probe()`` every 2 s until ``predicate`` holds (the resource settles asynchronously)."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() > deadline:
            raise AssertionError(f"not settled within {timeout_s:.0f}s: {last!r}")
        time.sleep(2)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AgentCore Dataset with one inline example reads back, then deletes.

    Its Ref and DatasetId are the dataset AgentCore lists by name, ACTIVE with the templated
    schema type and example; after the stack delete it answers the exact NotFound.
    """
    control = ctx.client("bedrock-agentcore-control")
    cfn = ctx.client("cloudformation")
    name = _alnum_name(ctx, "sim2realCfnDataset")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-dataset-"), _template(name))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    dataset_id = out["DatasetId"]
    assert _datasets(control, name) == [(dataset_id, out["DatasetArn"])], (
        f"datasets named {name!r}: {_datasets(control, name)!r}"
    )
    dataset = _poll(lambda: control.get_dataset(datasetId=dataset_id),
                    lambda r: r["status"] == "ACTIVE")
    got = (dataset["datasetName"], dataset["datasetArn"], dataset["schemaType"],
           dataset["exampleCount"])
    assert got == (name, out["DatasetArn"], "AGENTCORE_EVALUATION_PREDEFINED_V1", 1), (
        f"dataset reads {got!r}"
    )
    examples = paginate(control, "list_dataset_examples", "examples", datasetId=dataset_id)
    got = [(e.get("scenario_id"), e.get("turns")) for e in examples]
    assert got == [("sim2real-scenario-1", _EXAMPLE_TURNS)], f"dataset examples {examples!r}"

    delete_stack(cfn, stack_id)
    refused = ("ResourceNotFoundException", "The specified dataset does not exist. Please verify the datasetId and try again.")
    expect_error(lambda: control.get_dataset(datasetId=dataset_id), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
