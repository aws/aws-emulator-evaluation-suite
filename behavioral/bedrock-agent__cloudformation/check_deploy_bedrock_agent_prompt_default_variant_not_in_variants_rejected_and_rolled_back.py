"""deploy-bedrock-agent-prompt-default-variant-not-in-variants-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-bedrock-agent-prompt-default-variant-not-in-variants-rejected-and-rolled-back"
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


# ---- Check-specific: the template, then run(). ----

_REJECTED = (
    "Default variant must be present in the variants list. Retry your request with the "
    "correct default variant. (Service: BedrockAgent, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _template(name: str, default_variant: str) -> str:
    """One Prompt with variant ``v1``; only ``DefaultVariant`` varies."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Prompt": {
                "Type": "AWS::Bedrock::Prompt",
                "Properties": {
                    "Name": name,
                    "DefaultVariant": default_variant,
                    "Variants": [{
                        "Name": "v1",
                        "TemplateType": "TEXT",
                        "TemplateConfiguration": {"Text": {"Text": "hello"}},
                    }],
                },
            },
        },
        "Outputs": {"PromptId": {"Value": {"Fn::GetAtt": ["Prompt", "Id"]}}},
    })


def _prompt_names(ba) -> list[str]:
    """The name of every prompt ListPrompts reports, all pages read."""
    return [p["name"] for p in paginate(ba, "list_prompts", "promptSummaries")]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Prompt whose DefaultVariant names no entry in Variants is refused, the
    stack rolls back and bedrock-agent lists no prompt by its name; the same template with the
    default variant naming its one variant deploys and reads back.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-bedrock-prompt.html
    """
    ba = ctx.client("bedrock-agent")
    cf = ctx.client("cloudformation")
    bad_stack = ctx.unique_name("sim2real-promptbad-")
    bad_name = ctx.unique_name("sim2real-promptbad-")

    # "missing" names no variant in Variants, which Bedrock rejects.
    bad_id = create_stack(ctx, cf, bad_stack, _template(bad_name, "missing"))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )

    reason = failed_reason(stack_events(cf, bad_id), "Prompt")
    got = handler_reason(reason, ctx.account, bad_stack, bad_name)
    assert got == _REJECTED, f"expected (masked message, handler code) {_REJECTED!r}, got {got!r}"

    resources = cf.describe_stack_resources(StackName=bad_id)["StackResources"]
    prompt_rows = [r for r in resources if r["LogicalResourceId"] == "Prompt"]
    assert len(prompt_rows) == 1 and prompt_rows[0].get("PhysicalResourceId") in (None, ""), (
        f"expected the rejected Prompt to carry no PhysicalResourceId, got {prompt_rows!r}"
    )
    assert bad_name not in _prompt_names(ba), (
        f"expected bedrock-agent to list no prompt named {bad_name!r} after the rollback"
    )

    delete_stack(cf, bad_id)

    # Positive control: the same template, the default variant naming its one variant.
    good_stack = ctx.unique_name("sim2real-promptgood-")
    good_name = ctx.unique_name("sim2real-promptgood-")
    good_id = create_stack(ctx, cf, good_stack, _template(good_name, "v1"))
    good_status = wait_stack(cf, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}, expected CREATE_COMPLETE"
    )
    good_prompt_id = stack_outputs(cf, good_id)["PromptId"]
    control = ba.get_prompt(promptIdentifier=good_prompt_id)
    got = (control["name"], control["defaultVariant"], [v["name"] for v in control["variants"]])
    assert got == (good_name, "v1", ["v1"]), (
        f"expected the control prompt's (name, defaultVariant, variant names) "
        f"{(good_name, 'v1', ['v1'])!r}, bedrock-agent reports {got!r}"
    )
    variant = control["variants"][0]
    got = (variant["templateType"], variant["templateConfiguration"]["text"]["text"])
    assert got == ("TEXT", "hello"), f"expected the control variant ('TEXT', 'hello'), got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
