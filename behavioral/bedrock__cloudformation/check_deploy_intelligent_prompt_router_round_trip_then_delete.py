"""deploy-intelligent-prompt-router-round-trip-then-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-intelligent-prompt-router-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["bedrock", "cloudformation"]

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

_LITE, _PRO = "amazon.nova-lite-v1:0", "amazon.nova-pro-v1:0"


def _model_arn(model_id):
    """The foundation model's ARN in the stack's own partition and Region."""
    return {"Fn::Sub": "arn:${AWS::Partition}:bedrock:${AWS::Region}::foundation-model/" + model_id}


def _template(router_name, response_quality_difference):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Router": {
                "Type": "AWS::Bedrock::IntelligentPromptRouter",
                "Properties": {
                    "PromptRouterName": router_name,
                    "Models": [
                        {"ModelArn": _model_arn(_LITE)},
                        {"ModelArn": _model_arn(_PRO)},
                    ],
                    "FallbackModel": {"ModelArn": _model_arn(_LITE)},
                    "RoutingCriteria": {"ResponseQualityDifference": response_quality_difference},
                },
            },
        },
        "Outputs": {
            "RouterArn": {"Value": {"Ref": "Router"}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation IntelligentPromptRouter reads back AVAILABLE through bedrock with its
    templated models and criteria, then the stack delete removes it, confirmed by GetPromptRouter.
    """
    cfn = ctx.client("cloudformation")
    bedrock = ctx.client("bedrock")
    stack = ctx.unique_name("sim2real-cfnrouter-")
    router_name = ctx.unique_name("sim2real-router-")

    stack_id = create_stack(ctx, cfn, stack, _template(router_name, 5.0))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    out = stack_outputs(cfn, stack_id)
    router_arn = out["RouterArn"]

    # Ref against an independent read (ListPromptRouters by name), never a read keyed by the Ref.
    # type="custom" scopes the listing to account-created routers, excluding AWS's own defaults.
    routers = paginate(bedrock, "list_prompt_routers", "promptRouterSummaries", type="custom")
    matches = [r for r in routers if r["promptRouterName"] == router_name]
    assert len(matches) == 1, f"ListPromptRouters found {matches!r} for {router_name!r}"
    assert matches[0]["promptRouterArn"] == router_arn, (
        f"ListPromptRouters arn {matches[0]['promptRouterArn']!r} != Ref {router_arn!r}"
    )

    router = bedrock.get_prompt_router(promptRouterArn=router_arn)
    assert router["promptRouterArn"] == router_arn, (
        f"GetPromptRouter arn {router['promptRouterArn']!r} != Ref {router_arn!r}"
    )
    assert router["promptRouterName"] == router_name, (
        f"GetPromptRouter name {router['promptRouterName']!r} != {router_name!r}"
    )
    assert router["status"] == "AVAILABLE", f"GetPromptRouter status {router['status']!r}"
    prefix = f"arn:{stack_id.split(':')[1]}:bedrock:{ctx.region}::foundation-model/"
    got_models = {m["modelArn"] for m in router["models"]}
    want_models = {prefix + _LITE, prefix + _PRO}
    assert got_models == want_models, f"GetPromptRouter models {got_models!r} != {want_models!r}"
    assert router["fallbackModel"]["modelArn"] == prefix + _LITE, (
        f"GetPromptRouter fallbackModel {router['fallbackModel']!r}"
    )
    assert router["routingCriteria"]["responseQualityDifference"] == 5.0, (
        f"GetPromptRouter routingCriteria {router['routingCriteria']!r} != 5.0"
    )

    delete_stack(cfn, stack_id)

    not_found = ("ResourceNotFoundException", f"Cannot find prompt router {router_arn}.")
    until_raises(lambda: bedrock.get_prompt_router(promptRouterArn=router_arn))
    expect_error(lambda: bedrock.get_prompt_router(promptRouterArn=router_arn), *not_found)

    remaining = paginate(bedrock, "list_prompt_routers", "promptRouterSummaries", type="custom")
    assert router_name not in {r["promptRouterName"] for r in remaining}, (
        f"{router_name!r} still listed by ListPromptRouters after the stack delete"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
