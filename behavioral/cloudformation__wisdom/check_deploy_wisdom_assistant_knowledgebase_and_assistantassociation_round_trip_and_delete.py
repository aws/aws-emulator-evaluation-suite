"""deploy-wisdom-assistant-knowledgebase-and-assistantassociation-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-wisdom-assistant-knowledgebase-and-assistantassociation-round-trip-and-delete"
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

def _template(name_prefix: str, *, with_association: bool) -> str:
    resources = {
        "Assistant": {
            "Type": "AWS::Wisdom::Assistant",
            "Properties": {"Name": {"Fn::Sub": f"{name_prefix}-a"}, "Type": "AGENT"},
        },
        "KnowledgeBase": {
            "Type": "AWS::Wisdom::KnowledgeBase",
            "Properties": {
                "Name": {"Fn::Sub": f"{name_prefix}-kb"},
                "KnowledgeBaseType": "CUSTOM",
            },
        },
    }
    outputs = {
        "AssistantId": {"Value": {"Fn::GetAtt": ["Assistant", "AssistantId"]}},
        "AssistantArn": {"Value": {"Fn::GetAtt": ["Assistant", "AssistantArn"]}},
        "AssistantRef": {"Value": {"Ref": "Assistant"}},
        "KnowledgeBaseId": {"Value": {"Fn::GetAtt": ["KnowledgeBase", "KnowledgeBaseId"]}},
        "KnowledgeBaseArn": {"Value": {"Fn::GetAtt": ["KnowledgeBase", "KnowledgeBaseArn"]}},
        "KnowledgeBaseRef": {"Value": {"Ref": "KnowledgeBase"}},
    }
    if with_association:
        resources["Association"] = {
            "Type": "AWS::Wisdom::AssistantAssociation",
            "Properties": {
                "AssistantId": {"Fn::GetAtt": ["Assistant", "AssistantId"]},
                "AssociationType": "KNOWLEDGE_BASE",
                "Association": {
                    "KnowledgeBaseId": {"Fn::GetAtt": ["KnowledgeBase", "KnowledgeBaseId"]}},
            },
        }
        outputs["AssociationId"] = {
            "Value": {"Fn::GetAtt": ["Association", "AssistantAssociationId"]}}
        outputs["AssociationRef"] = {"Value": {"Ref": "Association"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Assistant, KnowledgeBase and AssistantAssociation read back through Wisdom
    with the template's values and the ids Wisdom lists; removing the association alone leaves the
    assistant and knowledge base intact, and deleting the stack removes every one.
    """
    wis = ctx.client("wisdom")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-wisdomkb-")

    stack_id = create_stack(ctx, cfn, stack, _template(stack, with_association=True))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    assistant_id, kb_id = outputs["AssistantId"], outputs["KnowledgeBaseId"]
    assoc_id = outputs["AssociationId"]

    # Each Ref against an independent list entry by the declared name.
    listed = [(a["assistantId"], a["assistantArn"]) for a in paginate(
        wis, "list_assistants", "assistantSummaries") if a["name"] == f"{stack}-a"]
    got = (listed, outputs["AssistantRef"])
    assert got == ([(assistant_id, outputs["AssistantArn"])], assistant_id), (
        f"(ListAssistants, Ref) {got!r} for GetAtt {(assistant_id, outputs['AssistantArn'])!r}"
    )
    listed = [(k["knowledgeBaseId"], k["knowledgeBaseArn"]) for k in paginate(
        wis, "list_knowledge_bases", "knowledgeBaseSummaries") if k["name"] == f"{stack}-kb"]
    got = (listed, outputs["KnowledgeBaseRef"])
    assert got == ([(kb_id, outputs["KnowledgeBaseArn"])], kb_id), (
        f"(ListKnowledgeBases, Ref) {got!r} for GetAtt {(kb_id, outputs['KnowledgeBaseArn'])!r}"
    )
    listed = [a["assistantAssociationId"] for a in paginate(
        wis, "list_assistant_associations", "assistantAssociationSummaries",
        assistantId=assistant_id)]
    got = (listed, outputs["AssociationRef"])
    assert got == ([assoc_id], f"{assoc_id}|{assistant_id}"), (
        f"(ListAssistantAssociations, Ref) {got!r}"
    )

    assistant = wis.get_assistant(assistantId=assistant_id)["assistant"]
    got = (assistant["name"], assistant["type"])
    assert got == (f"{stack}-a", "AGENT"), f"GetAssistant (name, type) {got!r}"
    kb = wis.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]
    got = (kb["name"], kb["knowledgeBaseType"])
    assert got == (f"{stack}-kb", "CUSTOM"), f"GetKnowledgeBase (name, type) {got!r}"
    assoc = wis.get_assistant_association(
        assistantId=assistant_id, assistantAssociationId=assoc_id
    )["assistantAssociation"]
    got = (assoc["associationType"],
           assoc["associationData"]["knowledgeBaseAssociation"]["knowledgeBaseId"])
    assert got == ("KNOWLEDGE_BASE", kb_id), f"association (type, knowledge base) {got!r}"

    # Child first: the update drops only the association while its parents still answer.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack, with_association=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"association-dropping update ended {status!r}"
    gone = ("ResourceNotFoundException", "Assistant Association does not exist.")
    expect_error(lambda: wis.get_assistant_association(
        assistantId=assistant_id, assistantAssociationId=assoc_id), *gone)
    got = (wis.get_assistant(assistantId=assistant_id)["assistant"]["assistantId"],
           wis.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["knowledgeBaseId"])
    assert got == (assistant_id, kb_id), f"(assistant, knowledge base) after the update {got!r}"

    delete_stack(cfn, stack_id)
    gone = ("ResourceNotFoundException", "Assistant does not exist.")
    expect_error(lambda: wis.get_assistant(assistantId=assistant_id), *gone)
    gone = ("ResourceNotFoundException", "Knowledge Base does not exist.")
    expect_error(lambda: wis.get_knowledge_base(knowledgeBaseId=kb_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
