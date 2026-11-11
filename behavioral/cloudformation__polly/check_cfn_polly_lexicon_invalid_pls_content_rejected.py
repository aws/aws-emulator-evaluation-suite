"""cfn-polly-lexicon-invalid-pls-content-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-polly-lexicon-invalid-pls-content-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "polly"]

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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


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
    "Invalid PLS Lexicon (Service: Polly; Operation: PutLexicon; Status Code: 400; "
    "Error Code: InvalidLexiconException; Request ID: <id>)",
    "InvalidRequest",
)
_NOT_FOUND = ("LexiconNotFoundException", "Lexicon not found")

# A well-formed XML document that is not a PLS lexicon: Polly's PutLexicon rejects
# the content, not CloudFormation's own property validation, so the resource
# handler itself fails.
_INVALID_CONTENT = '<?xml version="1.0" encoding="UTF-8"?><notlexicon></notlexicon>'
_VALID_CONTENT = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<lexicon version="1.0" xmlns="http://www.w3.org/2005/01/pronunciation-lexicon" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
    'xsi:schemaLocation="http://www.w3.org/2005/01/pronunciation-lexicon '
    'http://www.w3.org/TR/2007/CR-pronunciation-lexicon-20071212/pls.xsd" '
    'alphabet="ipa" xml:lang="en-US">\n'
    "  <lexeme><grapheme>W3C</grapheme><alias>World Wide Web Consortium</alias></lexeme>\n"
    "</lexicon>"
)


def _template(lexicon_name: str, content: str) -> str:
    """One lexicon; the rejected and control stacks differ only in ``content``."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Lex": {
                "Type": "AWS::Polly::Lexicon",
                "Properties": {"Name": lexicon_name, "Content": content},
            },
        },
        "Outputs": {"LexRef": {"Value": {"Ref": "Lex"}}},
    })


def _delete_lexicon(polly, name: str) -> None:
    """Delete a lexicon the rollback unexpectedly left; only its own not-found means gone."""
    try:
        polly.delete_lexicon(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LexiconNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control",
      "resource:account-singleton:polly-lexicons")
def run(ctx) -> None:
    """A CloudFormation AWS::Polly::Lexicon whose Content is not a valid PLS document fails the
    resource handler with Polly's own InvalidLexiconException and never creates the lexicon; the
    same template with valid PLS Content deploys and reads back through Polly."""
    cf = ctx.client("cloudformation")
    polly = ctx.client("polly")
    stack_name = ctx.unique_name("sim2real-behav-cfn-pollylexneg-")
    lexicon_name = ctx.unique_name("sim2real")[:20]

    stack_id = create_stack(ctx, cf, stack_name, _template(lexicon_name, _INVALID_CONTENT))
    final = wait_stack(cf, stack_id)
    assert final == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {final!r}"

    got_reason = handler_reason(failed_reason(stack_events(cf, stack_id), "Lex"),
                                ctx.account, lexicon_name)
    assert got_reason == _REJECTED, f"expected {_REJECTED!r}, got {got_reason!r}"

    # The handler failed before any lexicon existed: Polly does not resolve the name the
    # template declared, a valid name it would otherwise answer for.
    expect_error(lambda: polly.get_lexicon(Name=lexicon_name), *_NOT_FOUND,
                 undo=lambda _: ctx.on_cleanup(lambda: _delete_lexicon(polly, lexicon_name)))

    # Positive control: the same template with valid PLS Content deploys.
    good_name = ctx.unique_name("sim2real")[:20]
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-behav-cfn-pollylexok-"),
                           _template(good_name, _VALID_CONTENT))
    good_final = wait_stack(cf, good_id)
    assert good_final == "CREATE_COMPLETE", (
        f"expected the control CREATE_COMPLETE, got {good_final!r}: "
        f"{decisive_rows(stack_events(cf, good_id))!r}"
    )

    good_ref = stack_outputs(cf, good_id)["LexRef"]
    lexicon = polly.get_lexicon(Name=good_name)
    assert lexicon["Lexicon"]["Content"] == _VALID_CONTENT, (
        "the PLS content Polly stored for the control differs from what the template declared"
    )
    assert lexicon["LexiconAttributes"]["LexiconArn"] == good_ref, (
        f"expected the control's Ref {good_ref!r} to equal Polly's LexiconArn "
        f"{lexicon['LexiconAttributes']['LexiconArn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
