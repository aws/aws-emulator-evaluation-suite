"""cfn-lex-resource-policy-read-back-then-resource-not-found-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lex-resource-policy-read-back-then-resource-not-found-after-delete"
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


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    for r in resources:
        if r["LogicalResourceId"] == logical_id:
            return r["PhysicalResourceId"]
    raise AssertionError(f"no resource {logical_id!r} in stack {stack_id!r}: {resources!r}")


def _bot_ids_named(lex, bot_name: str) -> list[str]:
    """The ids of every bot Lex lists under exactly ``bot_name``, following nextToken (botocore
    has no ListBots paginator)."""
    ids: list[str] = []
    kwargs = {"filters": [{"name": "BotName", "values": [bot_name], "operator": "EQ"}]}
    while True:
        page = lex.list_bots(**kwargs)
        ids.extend(b["botId"] for b in page["botSummaries"] if b["botName"] == bot_name)
        if not page.get("nextToken"):
            return ids
        kwargs["nextToken"] = page["nextToken"]


def _template(bot_name: str, *, with_policy: bool = True) -> str:
    """The bot stack; without its resource policy, the stack the update leaves."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowSameAccountDescribe",
            "Effect": "Allow",
            "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
            "Action": "lex:DescribeBot",
            "Resource": {"Fn::GetAtt": ["Bot", "Arn"]},
        }],
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
                },
            },
            **({"ResourcePolicy": {
                "Type": "AWS::Lex::ResourcePolicy",
                "Properties": {
                    "ResourceArn": {"Fn::GetAtt": ["Bot", "Arn"]},
                    "Policy": policy,
                },
            }} if with_policy else {}),
        },
        "Outputs": {
            "BotArn": {"Value": {"Fn::GetAtt": ["Bot", "Arn"]}},
            **({
                "PolicyId": {"Value": {"Ref": "ResourcePolicy"}},
                "PolicyRevisionId": {"Value": {"Fn::GetAtt": ["ResourcePolicy", "RevisionId"]}},
            } if with_policy else {}),
        },
    })


@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Lex::ResourcePolicy is real at Lex: Ref is the policy's
    primary identifier built from the bot's Arn, the statement and RevisionId read back unchanged,
    and an update removing it deletes the policy from Lex while the bot stays.
    """
    cfn = ctx.client("cloudformation")
    lex = ctx.client("lexv2-models")
    stack_name = ctx.unique_name("sim2real-behav-cfn-lexrp-")
    bot_name = ctx.unique_name("sim2real-behav-lexrpbot-")

    stack_id = create_stack(ctx, cfn, stack_name, _template(bot_name),
                            Capabilities=["CAPABILITY_IAM"])
    created = wait_stack(cfn, stack_id)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    partition = stack_id.split(":")[1]

    bot_id = _physical_id(cfn, stack_id, "Bot")
    policy_physical = _physical_id(cfn, stack_id, "ResourcePolicy")
    outputs = stack_outputs(cfn, stack_id)
    bot_arn = outputs["BotArn"]
    # The bot the policy names, against an independent read: ListBots by the declared name, and
    # GetAtt Arn in the documented format over that listed id.
    listed = _bot_ids_named(lex, bot_name)
    assert listed == [bot_id], f"ListBots under {bot_name!r} gave {listed!r}, expected {bot_id!r}"
    want_bot_arn = f"arn:{partition}:lex:{ctx.region}:{ctx.account}:bot/{bot_id}"
    assert bot_arn == want_bot_arn, f"GetAtt Bot.Arn {bot_arn!r}, expected {want_bot_arn!r}"
    expected_id = f"{bot_arn}/ResourcePolicy"
    assert policy_physical == expected_id, (
        f"ResourcePolicy's PhysicalResourceId {policy_physical!r} != {expected_id!r}"
    )
    assert outputs["PolicyId"] == policy_physical, (
        f"Ref ResourcePolicy {outputs['PolicyId']!r} != PhysicalResourceId {policy_physical!r}"
    )

    # Independent read at the destination: Lex's own resource-policy record carries the
    # statement the template declared.
    described = lex.describe_resource_policy(resourceArn=bot_arn)
    assert described["resourceArn"] == bot_arn, (
        f"DescribeResourcePolicy resourceArn {described['resourceArn']!r} != {bot_arn!r}"
    )
    statements = json.loads(described["policy"])["Statement"]
    assert len(statements) == 1, f"expected exactly one statement, got {statements!r}"
    statement = statements[0]
    assert statement["Sid"] == "AllowSameAccountDescribe", (
        f"expected Sid 'AllowSameAccountDescribe', got {statement.get('Sid')!r}"
    )
    assert statement["Effect"] == "Allow", f"expected Effect 'Allow', got {statement.get('Effect')!r}"
    expected_principal = {"AWS": f"arn:{partition}:iam::{ctx.account}:root"}
    assert statement["Principal"] == expected_principal, (
        f"expected Principal {expected_principal!r}, got {statement.get('Principal')!r}"
    )
    assert described["revisionId"] == outputs["PolicyRevisionId"], (
        f"DescribeResourcePolicy revisionId {described['revisionId']!r} != GetAtt RevisionId "
        f"{outputs['PolicyRevisionId']!r}"
    )
    assert statement["Action"] == "lex:DescribeBot", (
        f"expected Action 'lex:DescribeBot', got {statement.get('Action')!r}"
    )
    assert statement["Resource"] == bot_arn, (
        f"expected Resource {bot_arn!r}, got {statement.get('Resource')!r}"
    )

    # The policy's own delete, proven while its bot still exists.
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(bot_name, with_policy=False),
        Capabilities=["CAPABILITY_IAM"],
    )
    updated = wait_stack(cfn, stack_id)
    assert updated == "UPDATE_COMPLETE", f"expected UPDATE_COMPLETE, got {updated!r}"
    policy_gone = (
        "ResourceNotFoundException",
        f"There is no policy for resourceArn {bot_arn}. Create a resource-based policy and try "
        "your request again.",
    )
    until_raises(lambda: lex.describe_resource_policy(resourceArn=bot_arn), timeout_s=60.0)
    expect_error(lambda: lex.describe_resource_policy(resourceArn=bot_arn), *policy_gone)
    kept = lex.describe_bot(botId=bot_id)["botName"]
    assert kept == bot_name, f"expected the bot {bot_name!r} to survive the update, Lex reports {kept!r}"

    delete_stack(cfn, stack_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
