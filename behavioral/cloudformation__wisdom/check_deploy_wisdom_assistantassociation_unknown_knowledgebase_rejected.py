"""deploy-wisdom-assistantassociation-unknown-knowledgebase-rejected."""
from __future__ import annotations

import json
import re
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-wisdom-assistantassociation-unknown-knowledgebase-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "wisdom"]

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

_REJECTED = (
    "Knowledge Base does not exist. (Service: CloverKnowledge, Status Code: 404, Request ID: <id>) "
    "(SDK Attempt Count: <n>) (Service: QConnect, Status Code: 404, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "NotFound",
)


def _template(name: str, kb_name: str, association_kb_id=None) -> str:
    """The association targets the template's own KnowledgeBase unless ``association_kb_id``."""
    kb_ref = association_kb_id or {"Fn::GetAtt": ["KnowledgeBase", "KnowledgeBaseId"]}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Assistant": {"Type": "AWS::Wisdom::Assistant",
                          "Properties": {"Name": name, "Type": "AGENT"}},
            "KnowledgeBase": {
                "Type": "AWS::Wisdom::KnowledgeBase",
                "Properties": {"Name": kb_name, "KnowledgeBaseType": "CUSTOM"},
            },
            "Association": {
                "Type": "AWS::Wisdom::AssistantAssociation",
                "DependsOn": "KnowledgeBase",
                "Properties": {
                    "AssistantId": {"Fn::GetAtt": ["Assistant", "AssistantId"]},
                    "AssociationType": "KNOWLEDGE_BASE",
                    "Association": {"KnowledgeBaseId": kb_ref},
                },
            },
        },
        "Outputs": {
            "AssistantId": {"Value": {"Fn::GetAtt": ["Assistant", "AssistantId"]}},
            "KnowledgeBaseId": {"Value": {"Fn::GetAtt": ["KnowledgeBase", "KnowledgeBaseId"]}},
            "AssociationId": {"Value": {"Fn::GetAtt": ["Association", "AssistantAssociationId"]}},
        },
    })


def _physical_id(cfn, stack_id, logical_id):
    rows = [r.get("PhysicalResourceId") for r in paginate(
        cfn, "list_stack_resources", "StackResourceSummaries", StackName=stack_id)
        if r["LogicalResourceId"] == logical_id]
    assert len(rows) == 1 and rows[0], f"stack {stack_id!r} resource {logical_id!r}: {rows!r}"
    return rows[0]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AssistantAssociation targeting its template's own KnowledgeBase deploys and
    reads back, while the same template whose association names a KnowledgeBaseId that does not
    exist fails with Wisdom's own NotFound and rolls back its assistant and knowledge base."""
    wis = ctx.client("wisdom")
    cfn = ctx.client("cloudformation")
    good_stack = ctx.unique_name("sim2real-wisdomassocok-")
    bad_stack = ctx.unique_name("sim2real-wisdomassocbad-")
    missing_kb_id = str(uuid.uuid4())

    # Positive control: the association targets the template's own knowledge base.
    good_id = create_stack(ctx, cfn, good_stack,
                           _template(f"{good_stack}-a", f"{good_stack}-kb"))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    out = stack_outputs(cfn, good_id)
    assoc = wis.get_assistant_association(
        assistantId=out["AssistantId"], assistantAssociationId=out["AssociationId"]
    )["assistantAssociation"]
    assistant = wis.get_assistant(assistantId=out["AssistantId"])["assistant"]
    got = (assoc["associationType"],
           assoc["associationData"]["knowledgeBaseAssociation"]["knowledgeBaseId"],
           assistant["name"], assistant["type"])
    want = ("KNOWLEDGE_BASE", out["KnowledgeBaseId"], f"{good_stack}-a", "AGENT")
    assert got == want, f"control (association type, kb, assistant name, type) {got!r}"

    bad_id = create_stack(ctx, cfn, bad_stack,
                          _template(f"{bad_stack}-a", f"{bad_stack}-kb", missing_kb_id))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Association"), ctx.account,
                         missing_kb_id)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through Wisdom before any delete: the assistant and knowledge base it
    # created are gone.
    assistant_id = _physical_id(cfn, bad_id, "Assistant")
    kb_id = _physical_id(cfn, bad_id, "KnowledgeBase")
    gone = ("ResourceNotFoundException", "Assistant does not exist.")
    expect_error(lambda: wis.get_assistant(assistantId=assistant_id), *gone)
    gone = ("ResourceNotFoundException", "Knowledge Base does not exist.")
    expect_error(lambda: wis.get_knowledge_base(knowledgeBaseId=kb_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
