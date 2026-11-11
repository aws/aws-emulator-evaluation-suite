"""cfn-lex-bot-version-and-alias-read-back-then-resource-not-found-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lex-bot-version-and-alias-read-back-then-resource-not-found-after-delete"
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
_GONE = ("ResourceNotFoundException", "Failed to retrieve resource since it does not exist")


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    for r in resources:
        if r["LogicalResourceId"] == logical_id:
            return r["PhysicalResourceId"]
    raise AssertionError(f"no resource {logical_id!r} in stack {stack_id!r}: {resources!r}")


def _intent_names(lex, bot_id: str) -> list[str]:
    """Every intent name of the bot's DRAFT locale, following nextToken (botocore has no
    ListIntents paginator), sorted."""
    names: list[str] = []
    kwargs = {"botId": bot_id, "botVersion": "DRAFT", "localeId": _LOCALE}
    while True:
        page = lex.list_intents(**kwargs)
        names.extend(i["intentName"] for i in page["intentSummaries"])
        if not page.get("nextToken"):
            return sorted(names)
        kwargs["nextToken"] = page["nextToken"]


def _alias_ids_named(lex, bot_id: str, alias_name: str) -> list[str]:
    """The ids of every alias of the bot Lex lists under ``alias_name``, following nextToken
    (botocore has no ListBotAliases paginator)."""
    ids: list[str] = []
    kwargs = {"botId": bot_id}
    while True:
        page = lex.list_bot_aliases(**kwargs)
        ids.extend(a["botAliasId"] for a in page["botAliasSummaries"]
                   if a["botAliasName"] == alias_name)
        if not page.get("nextToken"):
            return ids
        kwargs["nextToken"] = page["nextToken"]


def _template(bot_name: str, *, with_version_and_alias: bool = True) -> str:
    """The bot stack; without its version and alias, the stack the update leaves."""
    children = {
        "BotVersion": {
            "Type": "AWS::Lex::BotVersion",
            "Properties": {
                "BotId": {"Ref": "Bot"},
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
            },
        },
    }
    child_outputs = {
        "BotVersionNumber": {"Value": {"Fn::GetAtt": ["BotVersion", "BotVersion"]}},
        "BotAliasId": {"Value": {"Ref": "BotAlias"}},
        "BotAliasArn": {"Value": {"Fn::GetAtt": ["BotAlias", "Arn"]}},
    }
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
            **(children if with_version_and_alias else {}),
        },
        "Outputs": {
            "BotId": {"Value": {"Ref": "Bot"}},
            **(child_outputs if with_version_and_alias else {}),
        },
    })


@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Lex::BotVersion and AWS::Lex::BotAlias are real at Lex:
    Ref is each composite primary identifier, the locale and alias read back as declared, and an
    update removing them deletes both from Lex while the bot stays; the stack delete removes the bot.
    """
    cfn = ctx.client("cloudformation")
    lex = ctx.client("lexv2-models")
    stack_name = ctx.unique_name("sim2real-behav-cfn-lexver-")
    bot_name = ctx.unique_name("sim2real-behav-lexverbot-")

    # The locale build AutoBuildBotLocales triggers during create takes a few minutes.
    stack_id = create_stack(ctx, cfn, stack_name, _template(bot_name),
                            Capabilities=["CAPABILITY_IAM"])
    created = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    partition = stack_id.split(":")[1]

    bot_id = _physical_id(cfn, stack_id, "Bot")
    version_physical = _physical_id(cfn, stack_id, "BotVersion")
    alias_physical = _physical_id(cfn, stack_id, "BotAlias")
    outputs = stack_outputs(cfn, stack_id)
    version_number = outputs["BotVersionNumber"]
    alias_id = outputs["BotAliasId"].split("|")[0]

    assert version_physical == f"{bot_id}|{version_number}", (
        f"BotVersion's PhysicalResourceId {version_physical!r} != composite "
        f"{bot_id}|{version_number}"
    )
    assert alias_physical == f"{alias_id}|{bot_id}", (
        f"BotAlias's PhysicalResourceId {alias_physical!r} != composite {alias_id}|{bot_id}"
    )
    assert outputs["BotAliasId"] == alias_physical, (
        f"Ref BotAlias {outputs['BotAliasId']!r} != PhysicalResourceId {alias_physical!r}"
    )

    # Independent reads at the destination: Lex's own version and alias records carry the
    # properties the template declared.
    version = lex.describe_bot_version(botId=bot_id, botVersion=version_number)
    assert version["botId"] == bot_id, f"DescribeBotVersion botId {version['botId']!r} != {bot_id!r}"
    assert version["botVersion"] == version_number, (
        f"DescribeBotVersion botVersion {version['botVersion']!r} != {version_number!r}"
    )
    assert version["botStatus"] == "Available", (
        f"expected BotVersion status 'Available', got {version['botStatus']!r}"
    )

    expected_alias_arn = f"arn:{partition}:lex:{ctx.region}:{ctx.account}:bot-alias/{bot_id}/{alias_id}"
    assert outputs["BotAliasArn"] == expected_alias_arn, (
        f"GetAtt BotAlias.Arn was {outputs['BotAliasArn']!r}, expected {expected_alias_arn!r}"
    )

    locale = lex.describe_bot_locale(botId=bot_id, botVersion="DRAFT", localeId=_LOCALE)
    assert locale["nluIntentConfidenceThreshold"] == 0.4, (
        f"expected nluIntentConfidenceThreshold 0.4, got {locale['nluIntentConfidenceThreshold']!r}"
    )
    intents = _intent_names(lex, bot_id)
    assert intents == ["FallbackIntent", "OrderPizza"], (
        f"expected the locale's intents ['FallbackIntent', 'OrderPizza'], got {intents!r}"
    )

    # The alias Ref against an independent read: ListBotAliases by the declared alias name.
    listed_aliases = _alias_ids_named(lex, bot_id, _ALIAS_NAME)
    assert listed_aliases == [alias_id], (
        f"ListBotAliases under {_ALIAS_NAME!r} gave {listed_aliases!r}, expected the Ref's alias "
        f"id {alias_id!r}"
    )
    alias = lex.describe_bot_alias(botAliasId=alias_id, botId=bot_id)
    assert alias["botAliasName"] == _ALIAS_NAME, (
        f"expected botAliasName {_ALIAS_NAME!r}, got {alias['botAliasName']!r}"
    )
    assert alias["botVersion"] == version_number, (
        f"BotAlias is bound to version {alias['botVersion']!r}, expected GetAtt's {version_number!r}"
    )
    assert alias["botAliasStatus"] == "Available", (
        f"expected botAliasStatus 'Available', got {alias['botAliasStatus']!r}"
    )

    # Each child's own delete, proven while its bot still exists.
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(bot_name, with_version_and_alias=False),
        Capabilities=["CAPABILITY_IAM"],
    )
    updated = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert updated == "UPDATE_COMPLETE", f"expected UPDATE_COMPLETE, got {updated!r}"

    until_raises(lambda: lex.describe_bot_version(botId=bot_id, botVersion=version_number),
                 timeout_s=60.0)
    expect_error(lambda: lex.describe_bot_version(botId=bot_id, botVersion=version_number), *_GONE)
    until_raises(lambda: lex.describe_bot_alias(botAliasId=alias_id, botId=bot_id), timeout_s=60.0)
    expect_error(lambda: lex.describe_bot_alias(botAliasId=alias_id, botId=bot_id), *_GONE)
    kept = lex.describe_bot(botId=bot_id)["botName"]
    assert kept == bot_name, f"expected the bot {bot_name!r} to survive the update, Lex reports {kept!r}"

    delete_stack(cfn, stack_id)
    until_raises(lambda: lex.describe_bot(botId=bot_id), timeout_s=60.0)
    expect_error(lambda: lex.describe_bot(botId=bot_id), *_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
