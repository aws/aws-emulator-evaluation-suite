"""deploy-wisdom-aiprompt-mismatched-apiformat-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-wisdom-aiprompt-mismatched-apiformat-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "qconnect"]

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

_MODEL = "anthropic.claude-sonnet-4-5-20250929-v1:0"
_GEOGRAPHY = {"us": "us", "ca": "us", "eu": "eu", "ap": "apac"}
_PROMPT_TEXT = "prompt: |\n  Answer using {{$.contentExcerpt}} for the query {{$.query}}.\n"
_REJECTED = (
    "PromptAPIFormat is not supported for the provided PromptType. "
    "(Service: QConnect, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _model_id(region: str) -> str:
    """The cross-region inference profile of the model for the region's geography."""
    return f"{_GEOGRAPHY.get(region.split('-')[0], 'us')}.{_MODEL}"


def _template(name: str, api_format: str, model_id: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Assistant": {"Type": "AWS::Wisdom::Assistant", "Properties": {"Name": name, "Type": "AGENT"}},
            "Prompt": {
                "Type": "AWS::Wisdom::AIPrompt",
                "Properties": {
                    "AssistantId": {"Fn::GetAtt": ["Assistant", "AssistantId"]},
                    "Name": f"{name}-p",
                    "Type": "ANSWER_GENERATION",
                    "TemplateType": "TEXT",
                    "ApiFormat": api_format,
                    "ModelId": model_id,
                    "TemplateConfiguration": {
                        "TextFullAIPromptEditTemplateConfiguration": {"Text": _PROMPT_TEXT},
                    },
                },
            },
        },
        "Outputs": {
            "AssistantId": {"Value": {"Fn::GetAtt": ["Assistant", "AssistantId"]}},
            "PromptId": {"Value": {"Fn::GetAtt": ["Prompt", "AIPromptId"]}},
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ANSWER_GENERATION AIPrompt deploys with its required TEXT_COMPLETIONS api
    format and fails with Q in Connect's exact reason when the only change is an unsupported
    ApiFormat; the failed stack rolls back and leaves no assistant behind.
    """
    qc = ctx.client("qconnect")
    cfn = ctx.client("cloudformation")
    good_stack = ctx.unique_name("sim2real-promptfmtok-")
    bad_stack = ctx.unique_name("sim2real-promptfmtbad-")
    model_id = _model_id(ctx.region)

    # Positive control: the same template, ApiFormat given the supported value.
    good_id = create_stack(ctx, cfn, good_stack,
                           _template(good_stack, "TEXT_COMPLETIONS", model_id))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    out = stack_outputs(cfn, good_id)
    prompt = qc.get_ai_prompt(assistantId=out["AssistantId"], aiPromptId=out["PromptId"])["aiPrompt"]
    got = (prompt["name"], prompt["apiFormat"])
    assert got == (f"{good_stack}-p", "TEXT_COMPLETIONS"), f"control prompt reads {got!r}"

    bad_id = create_stack(ctx, cfn, bad_stack,
                          _template(bad_stack, "ANTHROPIC_CLAUDE_MESSAGES", model_id))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Prompt"), ctx.account)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through Q in Connect, by the assistant's declared name, before any delete.
    names = [a["name"] for a in paginate(qc, "list_assistants", "assistantSummaries")]
    assert bad_stack not in names, f"the rolled-back assistant {bad_stack!r} is listed"
    assert good_stack in names, f"the control assistant {good_stack!r} is not listed"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
