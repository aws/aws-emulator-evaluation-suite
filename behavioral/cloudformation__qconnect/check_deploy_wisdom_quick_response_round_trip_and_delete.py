"""deploy-wisdom-quick-response-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-wisdom-quick-response-round-trip-and-delete"
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


def _template(kb_name: str, qr_name: str | None, content: str, tag_value: str) -> str:
    resources = {
        "Kb": {
            "Type": "AWS::Wisdom::KnowledgeBase",
            "Properties": {
                "KnowledgeBaseType": "QUICK_RESPONSES",
                "Name": kb_name,
                "Tags": [{"Key": "sim2real-kb", "Value": tag_value}],
            },
        },
    }
    outputs = {
        "KbId": {"Value": {"Ref": "Kb"}},
        "KbArn": {"Value": {"Fn::GetAtt": ["Kb", "KnowledgeBaseArn"]}},
    }
    if qr_name is not None:
        resources["Qr"] = {
            "Type": "AWS::Wisdom::QuickResponse",
            "Properties": {
                "KnowledgeBaseArn": {"Fn::GetAtt": ["Kb", "KnowledgeBaseArn"]},
                "Name": qr_name,
                "Content": {"Content": content},
                "Tags": [{"Key": "sim2real-qr", "Value": qr_name}],
            },
        }
        outputs["QrRef"] = {"Value": {"Ref": "Qr"}}
        outputs["QrId"] = {"Value": {"Fn::GetAtt": ["Qr", "QuickResponseId"]}}
        outputs["QrStatus"] = {"Value": {"Fn::GetAtt": ["Qr", "Status"]}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                        "Outputs": outputs})


_QR_GONE = ("ResourceNotFoundException", "QuickResponse does not exist.")
_KB_GONE = ("ResourceNotFoundException", "Knowledge Base does not exist.")


def _own_tags(qc, arn):
    """A resource's tags without CloudFormation's aws:* system tags."""
    return {k: v for k, v in qc.list_tags_for_resource(resourceArn=arn)["tags"].items()
            if not k.startswith("aws:")}


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Wisdom::QuickResponse's Ref is its ARN, its Status, content and tags
    read back through Q in Connect; an update removing it clears the knowledge base, and deleting
    the stack removes the knowledge base too.
    """
    qc = ctx.client("qconnect")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-cfn-qr-")
    kb_name = ctx.unique_name("sim2real-cfn-qr-kb-")
    qr_name = ctx.unique_name("sim2real-cfn-qr-item-")
    content = "Thanks for reaching out, we will follow up shortly."

    stack_id = create_stack(ctx, cfn, stack, _template(kb_name, qr_name, content, kb_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outs = stack_outputs(cfn, stack_id)

    # The knowledge base: Ref and GetAtt Arn against the independent list entry by name.
    kbs = [k for k in paginate(qc, "list_knowledge_bases", "knowledgeBaseSummaries")
           if k["name"] == kb_name]
    got = [(k["knowledgeBaseId"], k["knowledgeBaseArn"], k["knowledgeBaseType"]) for k in kbs]
    assert got == [(outs["KbId"], outs["KbArn"], "QUICK_RESPONSES")], (
        f"ListKnowledgeBases entries named {kb_name!r}: {got!r}"
    )
    kb_id = kbs[0]["knowledgeBaseId"]

    # The quick response: listed by name under the knowledge base; Ref is its ARN.
    qr_rows = [q for q in paginate(qc, "list_quick_responses", "quickResponseSummaries",
                                   knowledgeBaseId=kb_id)
               if q["name"] == qr_name]
    got = [(q["quickResponseId"], q["quickResponseArn"], q["status"]) for q in qr_rows]
    assert got == [(outs["QrId"], outs["QrRef"], outs["QrStatus"])], (
        f"ListQuickResponses entries named {qr_name!r}: {got!r}"
    )
    qr_id = qr_rows[0]["quickResponseId"]
    got = qc.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id)["quickResponse"]
    assert (got["status"], got["contents"]["plainText"]["content"]) == ("CREATED", content), (
        f"(status, content) {(got['status'], got['contents']['plainText']['content'])!r}"
    )

    # Template tags, CloudFormation's aws:* tags dropped. The child also carries the propagated
    # stack tag; the knowledge base, whose tags are create-only, carries only its template tag.
    for arn, want in ((outs["KbArn"], {"sim2real-kb": kb_name}),
                      (qr_rows[0]["quickResponseArn"],
                       {"sim2real": stack, "sim2real-qr": qr_name})):
        got_tags = _own_tags(qc, arn)
        assert got_tags == want, f"tags of {arn!r}: {got_tags!r}, expected {want!r}"

    # Child first: the update drops the quick response, keeping the knowledge base.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(kb_name, None, content, kb_name))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"quick-response-removing update ended {status!r}"
    remaining = paginate(qc, "list_quick_responses", "quickResponseSummaries",
                         knowledgeBaseId=kb_id)
    assert remaining == [], f"quick responses left in {kb_id!r}: {remaining!r}"
    expect_error(lambda: qc.get_quick_response(knowledgeBaseId=kb_id, quickResponseId=qr_id),
                 *_QR_GONE)
    kb_after = qc.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]
    assert kb_after["status"] == "ACTIVE", f"the knowledge base reads {kb_after['status']!r}"

    delete_stack(cfn, stack_id)
    expect_error(lambda: qc.get_knowledge_base(knowledgeBaseId=kb_id), *_KB_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
