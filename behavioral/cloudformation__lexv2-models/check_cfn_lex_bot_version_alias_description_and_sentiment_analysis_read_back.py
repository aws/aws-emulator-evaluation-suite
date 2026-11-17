"""cfn-lex-bot-version-alias-description-and-sentiment-analysis-read-back."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lex-bot-version-alias-description-and-sentiment-analysis-read-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "lexv2-models"]

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

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lexv2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}
_LOCALE = "en_US"
_ALIAS_NAME = "live"
_BOT_DESCRIPTION = "Helps customers order a pizza and track its delivery status."
_VERSION_DESCRIPTION = "A snapshot taken after the pizza-ordering locale was built."
_GONE = ("ResourceNotFoundException", "Failed to retrieve resource since it does not exist")


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    for r in resources:
        if r["LogicalResourceId"] == logical_id:
            return r["PhysicalResourceId"]
    raise AssertionError(f"no resource {logical_id!r} in stack {stack_id!r}: {resources!r}")


def _template(bot_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {"AssumeRolePolicyDocument": _TRUST},
            },
            "Bot": {
                "Type": "AWS::Lex::Bot",
                "Properties": {
                    "Name": bot_name,
                    "Description": _BOT_DESCRIPTION,
                    "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                    "DataPrivacy": {"ChildDirected": False},
                    "IdleSessionTTLInSeconds": 300,
                    "AutoBuildBotLocales": True,
                    "BotLocales": [{
                        "LocaleId": _LOCALE,
                        "NluConfidenceThreshold": 0.40,
                        "Intents": [
                            {
                                "Name": "OrderPizza",
                                "SampleUtterances": [{"Utterance": "I want to order a pizza"}],
                            },
                            {
                                "Name": "FallbackIntent",
                                "ParentIntentSignature": "AMAZON.FallbackIntent",
                            },
                        ],
                    }],
                },
            },
            "BotVersion": {
                "Type": "AWS::Lex::BotVersion",
                "Properties": {
                    "BotId": {"Ref": "Bot"},
                    "Description": _VERSION_DESCRIPTION,
                    "BotVersionLocaleSpecification": [{
                        "LocaleId": _LOCALE,
                        "BotVersionLocaleDetails": {"SourceBotVersion": "DRAFT"},
                    }],
                },
            },
            "BotAlias": {
                "Type": "AWS::Lex::BotAlias",
                "Properties": {
                    "BotId": {"Ref": "Bot"},
                    "BotAliasName": _ALIAS_NAME,
                    "BotVersion": {"Fn::GetAtt": ["BotVersion", "BotVersion"]},
                    "SentimentAnalysisSettings": {"DetectSentiment": True},
                },
            },
        },
        "Outputs": {
            "BotId": {"Value": {"Ref": "Bot"}},
            "BotVersionNumber": {"Value": {"Fn::GetAtt": ["BotVersion", "BotVersion"]}},
            "BotAliasId": {"Value": {"Ref": "BotAlias"}},
        },
    })


@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Lex::Bot and AWS::Lex::BotVersion each read back the exact
    Description they declared, and AWS::Lex::BotAlias reads back its SentimentAnalysisSettings,
    all through Lex's own Describe calls.
    """
    cfn = ctx.client("cloudformation")
    lex = ctx.client("lexv2-models")
    stack_name = ctx.unique_name("sim2real-behav-cfn-lexdesc-")
    bot_name = ctx.unique_name("sim2real-behav-lexdescbot-")

    # The locale build AutoBuildBotLocales triggers during create takes a few minutes.
    stack_id = create_stack(ctx, cfn, stack_name, _template(bot_name),
                            Capabilities=["CAPABILITY_IAM"])
    created = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    bot_id = _physical_id(cfn, stack_id, "Bot")
    outputs = stack_outputs(cfn, stack_id)
    version_number = outputs["BotVersionNumber"]
    alias_id = outputs["BotAliasId"].split("|")[0]

    bot = lex.describe_bot(botId=bot_id)
    assert bot["description"] == _BOT_DESCRIPTION, (
        f"DescribeBot description was {bot['description']!r}, expected {_BOT_DESCRIPTION!r}"
    )

    version = lex.describe_bot_version(botId=bot_id, botVersion=version_number)
    assert version["description"] == _VERSION_DESCRIPTION, (
        f"DescribeBotVersion description was {version['description']!r}, expected "
        f"{_VERSION_DESCRIPTION!r}"
    )

    alias = lex.describe_bot_alias(botAliasId=alias_id, botId=bot_id)
    assert alias["sentimentAnalysisSettings"] == {"detectSentiment": True}, (
        f"DescribeBotAlias sentimentAnalysisSettings was {alias['sentimentAnalysisSettings']!r}, "
        f"expected {{'detectSentiment': True}}"
    )

    delete_stack(cfn, stack_id)
    until_raises(lambda: lex.describe_bot(botId=bot_id), timeout_s=60.0)
    expect_error(lambda: lex.describe_bot(botId=bot_id), *_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
