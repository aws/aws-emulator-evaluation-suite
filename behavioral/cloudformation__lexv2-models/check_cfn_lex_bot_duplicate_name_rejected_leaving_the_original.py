"""cfn-lex-bot-duplicate-name-rejected-leaving-the-original."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "cfn-lex-bot-duplicate-name-rejected-leaving-the-original"
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


# ---- Check-specific: the template, then run(). ----

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lexv2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}

_DUPLICATE = (
    "Couldn't create the bot. A bot with the same name already exists. Use a different name "
    "and try your request again.",
    "AlreadyExists",
)


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
                    "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                    "DataPrivacy": {"ChildDirected": False},
                    "IdleSessionTTLInSeconds": 300,
                },
            },
        },
        "Outputs": {
            "BotId": {"Value": {"Ref": "Bot"}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
        },
    })


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second stack creating an AWS::Lex::Bot with a name Lex already holds is refused by
    Lex's own CreateBot call and rolls back; Lex still lists only the first stack's bot, the same
    bot (creation time) with its template properties.
    """
    cfn = ctx.client("cloudformation")
    lex = ctx.client("lexv2-models")
    bot_name = ctx.unique_name("sim2real-behav-lexdup-")
    stack_a = ctx.unique_name("sim2real-behav-cfn-lexdup-a-")
    stack_b = ctx.unique_name("sim2real-behav-cfn-lexdup-b-")

    stack_a_id = create_stack(ctx, cfn, stack_a, _template(bot_name),
                              Capabilities=["CAPABILITY_IAM"])
    status_a = wait_stack(cfn, stack_a_id)
    assert status_a == "CREATE_COMPLETE", (
        f"stack A create ended {status_a!r}: {decisive_rows(stack_events(cfn, stack_a_id))!r}"
    )
    outputs_a = stack_outputs(cfn, stack_a_id)
    bot_id_a, role_arn_a = outputs_a["BotId"], outputs_a["RoleArn"]

    before = lex.describe_bot(botId=bot_id_a)
    got = (before["botName"], before["roleArn"], before["dataPrivacy"], before["idleSessionTTLInSeconds"])
    want = (bot_name, role_arn_a, {"childDirected": False}, 300)
    assert got == want, f"stack A's bot reads back {got!r}, expected {want!r}"
    assert _bot_ids_named(lex, bot_name) == [bot_id_a], (
        f"expected Lex to list stack A's bot {bot_id_a!r} alone under {bot_name!r}"
    )

    stack_b_id = create_stack(ctx, cfn, stack_b, _template(bot_name),
                              Capabilities=["CAPABILITY_IAM"])
    status_b = wait_stack(cfn, stack_b_id)
    assert status_b == "ROLLBACK_COMPLETE", (
        f"stack B create ended {status_b!r}, expected ROLLBACK_COMPLETE"
    )

    reason = failed_reason(stack_events(cfn, stack_b_id), "Bot")
    got = handler_reason(reason, ctx.account, bot_name)
    assert got == _DUPLICATE, f"reason {got!r} != {_DUPLICATE!r}"

    # Stack B's rejection created no second bot: Lex lists stack A's bot alone under the name,
    # and it is the same bot (creation time), unharmed.
    listed = _bot_ids_named(lex, bot_name)
    assert listed == [bot_id_a], f"expected only stack A's bot {bot_id_a!r} under {bot_name!r}, got {listed!r}"
    bot = lex.describe_bot(botId=bot_id_a)
    assert bot["creationDateTime"] == before["creationDateTime"], (
        f"stack A's bot creationDateTime changed from {before['creationDateTime']!r} to "
        f"{bot['creationDateTime']!r}"
    )
    assert bot["botName"] == bot_name, (
        f"stack A's bot name changed to {bot['botName']!r}, expected {bot_name!r}"
    )
    assert bot["botStatus"] == "Available", (
        f"stack A's bot status is {bot['botStatus']!r}, expected 'Available'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
