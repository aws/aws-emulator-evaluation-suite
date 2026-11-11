"""deploy-codepipeline-custom-action-type-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-codepipeline-custom-action-type-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "codepipeline"]

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

def _template(category: str, provider: str, version: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ActionType": {
                "Type": "AWS::CodePipeline::CustomActionType",
                "Properties": {
                    "Category": category,
                    "Provider": provider,
                    "Version": version,
                    "InputArtifactDetails": {"MaximumCount": 1, "MinimumCount": 1},
                    "OutputArtifactDetails": {"MaximumCount": 1, "MinimumCount": 0},
                },
            },
        },
        "Outputs": {
            "ActionTypeRef": {"Value": {"Ref": "ActionType"}},
        },
    })


def _find_custom_action(cp, category: str, provider: str, version: str) -> dict | None:
    for action in paginate(cp, "list_action_types", "actionTypes", actionOwnerFilter="Custom"):
        aid = action["id"]
        if aid["category"] == category and aid["provider"] == provider and aid["version"] == version:
            return action
    return None


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation AWS::CodePipeline::CustomActionType is listed by CodePipeline's own
    ListActionTypes under the declared category, provider and version, carrying the template's
    artifact-count bounds; deleting the stack removes it from that listing.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codepipeline-customactiontype.html
    """
    cf = ctx.client("cloudformation")
    cp = ctx.client("codepipeline")

    category = "Build"
    provider = ctx.unique_name("Sim2realCAT").replace("-", "").replace("_", "")
    version = "1"
    stack = ctx.unique_name("sim2real-cpcat-stack-")

    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    stack_id = create_stack(ctx, cf, stack, _template(category, provider, version))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cf, stack_id))!r}"
    )

    outputs = stack_outputs(cf, stack_id)
    ref_value = outputs["ActionTypeRef"]
    want_ref = f"{category}|{provider}|{version}"
    assert ref_value == want_ref, (
        f"Ref resolved to {ref_value!r}, expected the composite primary identifier {want_ref!r}"
    )

    found = _find_custom_action(cp, category, provider, version)
    assert found is not None, (
        f"ListActionTypes(actionOwnerFilter='Custom') has no entry for category={category!r} "
        f"provider={provider!r} version={version!r}"
    )
    listed_id = found["id"]
    listed_key = f"{listed_id['category']}|{listed_id['provider']}|{listed_id['version']}"
    assert ref_value == listed_key, (
        f"Ref should be the listed action type's Category|Provider|Version {listed_key!r}, "
        f"got {ref_value!r}"
    )
    assert found["id"]["owner"] == "Custom", f"expected owner 'Custom', got {found['id']['owner']!r}"
    assert found["inputArtifactDetails"] == {"minimumCount": 1, "maximumCount": 1}, (
        f"inputArtifactDetails is {found['inputArtifactDetails']!r}, expected the template's "
        f"{{'minimumCount': 1, 'maximumCount': 1}}"
    )
    assert found["outputArtifactDetails"] == {"minimumCount": 0, "maximumCount": 1}, (
        f"outputArtifactDetails is {found['outputArtifactDetails']!r}, expected the template's "
        f"{{'minimumCount': 0, 'maximumCount': 1}}"
    )

    delete_stack(cf, stack_id)
    expect_error(lambda: cf.describe_stacks(StackName=stack), *stack_gone)

    gone = _find_custom_action(cp, category, provider, version)
    assert gone is None, (
        f"ListActionTypes(actionOwnerFilter='Custom') still carries category={category!r} "
        f"provider={provider!r} version={version!r} after the stack delete: {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
