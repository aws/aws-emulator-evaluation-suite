"""cfn-polly-lexicon-attributes-and-getatt-read-back-then-not-found-after-delete."""
from __future__ import annotations

import json
import time
from datetime import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-polly-lexicon-attributes-and-getatt-read-back-then-not-found-after-delete"
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

_NOT_FOUND = ("LexiconNotFoundException", "Lexicon not found")
_LEXICON_CONTENT = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<lexicon version="1.0" xmlns="http://www.w3.org/2005/01/pronunciation-lexicon" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
    'xsi:schemaLocation="http://www.w3.org/2005/01/pronunciation-lexicon '
    'http://www.w3.org/TR/2007/CR-pronunciation-lexicon-20071212/pls.xsd" '
    'alphabet="ipa" xml:lang="en-US">\n'
    "  <lexeme><grapheme>W3C</grapheme><alias>World Wide Web Consortium</alias></lexeme>\n"
    "</lexicon>"
)


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Polly::Lexicon is real at Polly: Ref and every
    Fn::GetAtt attribute match Polly's own answer and its Content round-trips.
    Deleting the stack removes the lexicon from Polly, not just from CFN."""
    cf = ctx.client("cloudformation")
    polly = ctx.client("polly")
    stack_name = ctx.unique_name("sim2real-behav-cfn-pollylex-")
    lexicon_name = ctx.unique_name("sim2real")[:20]

    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Lex": {
                "Type": "AWS::Polly::Lexicon",
                "Properties": {"Name": lexicon_name, "Content": _LEXICON_CONTENT},
            },
        },
        "Outputs": {
            "LexRef": {"Value": {"Ref": "Lex"}},
            "LexArn": {"Value": {"Fn::GetAtt": ["Lex", "Arn"]}},
            "LexAlphabet": {"Value": {"Fn::GetAtt": ["Lex", "Alphabet"]}},
            "LexLanguageCode": {"Value": {"Fn::GetAtt": ["Lex", "LanguageCode"]}},
            "LexLastModified": {"Value": {"Fn::GetAtt": ["Lex", "LastModified"]}},
        },
    })

    stack_id = create_stack(ctx, cf, stack_name, template)
    created = wait_stack(cf, stack_id)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )

    # Ref against an independent read: ListLexicons' entry for the declared name.
    listed = [lx["Attributes"]["LexiconArn"] for lx in paginate(polly, "list_lexicons", "Lexicons")
              if lx["Name"] == lexicon_name]
    outputs = stack_outputs(cf, stack_id)
    assert listed == [outputs["LexRef"]], (
        f"Ref Lex was {outputs['LexRef']!r}, ListLexicons lists {listed!r} under {lexicon_name!r}"
    )
    physical_id = listed[0]
    assert outputs["LexArn"] == physical_id, (
        f"GetAtt Lex.Arn was {outputs['LexArn']!r}, expected the listed arn {physical_id!r}"
    )

    # Independent read at the destination: Polly's own attributes must carry the
    # properties the template declared, including the two CloudFormation cannot
    # export as an Output at all (LexemesCount and Size are typed integer, and a
    # stack Output must resolve to a string).
    lexicon = polly.get_lexicon(Name=lexicon_name)
    attrs = lexicon["LexiconAttributes"]
    assert lexicon["Lexicon"]["Name"] == lexicon_name, (
        f"expected lexicon name {lexicon_name!r}, Polly reports {lexicon['Lexicon']['Name']!r}"
    )
    assert lexicon["Lexicon"]["Content"] == _LEXICON_CONTENT, (
        "the PLS content Polly stored differs from what the template declared"
    )
    assert attrs["LexiconArn"] == physical_id, (
        f"Polly's LexiconArn was {attrs['LexiconArn']!r}, expected {physical_id!r}"
    )
    assert outputs["LexAlphabet"] == attrs["Alphabet"] == "ipa", (
        f"GetAtt Lex.Alphabet was {outputs['LexAlphabet']!r}, Polly reports {attrs['Alphabet']!r}"
    )
    assert outputs["LexLanguageCode"] == attrs["LanguageCode"] == "en-US", (
        f"GetAtt Lex.LanguageCode was {outputs['LexLanguageCode']!r}, "
        f"Polly reports {attrs['LanguageCode']!r}"
    )
    assert attrs["LexemesCount"] == 1, f"expected 1 lexeme, Polly reports {attrs['LexemesCount']!r}"
    assert attrs["Size"] == len(_LEXICON_CONTENT), (
        f"expected Size {len(_LEXICON_CONTENT)!r}, Polly reports {attrs['Size']!r}"
    )

    reported_modified = datetime.fromisoformat(outputs["LexLastModified"].replace("Z", "+00:00"))
    assert reported_modified == attrs["LastModified"], (
        f"GetAtt Lex.LastModified was {outputs['LexLastModified']!r} ({reported_modified!r}), "
        f"Polly reports {attrs['LastModified']!r}"
    )

    delete_stack(cf, stack_id)

    # The physical delete may lag DELETE_COMPLETE.
    until_raises(lambda: polly.get_lexicon(Name=lexicon_name), timeout_s=60.0)
    expect_error(lambda: polly.get_lexicon(Name=lexicon_name), *_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
