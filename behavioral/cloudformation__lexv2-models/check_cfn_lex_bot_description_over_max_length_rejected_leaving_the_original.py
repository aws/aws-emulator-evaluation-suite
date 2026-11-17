"""cfn-lex-bot-description-over-max-length-rejected-leaving-the-original."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cfn-lex-bot-description-over-max-length-rejected-leaving-the-original"
GROUP = "deploy"
SERVICES = ["cloudformation", "lexv2-models"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "IMPORT_ROLLBACK_FAILED",
    }
)
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def wait_stack(ctx, cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"stack {stack_id} still {status!r}: the run budget ended first; not graded"
                )
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(ctx, cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in (
        "DELETE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
    ):
        wait_stack(ctx, cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        ctx, cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic()
    )
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [
            i
            for i, e in enumerate(events)
            if e.get("PhysicalResourceId") == stack_id
            and e["ResourceStatus"] == "DELETE_IN_PROGRESS"
        ]
        failed = [
            (e["LogicalResourceId"], e.get("ResourceStatusReason"))
            for e in events[starts[-1] if starts else 0 :]
            if e["ResourceStatus"] == "DELETE_FAILED"
        ]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(ctx, cf, name, stack_id=None):
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
                "ValidationError",
                f"Stack with id {name} does not exist",
            ):
                return
            raise
    delete_stack(ctx, cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(ctx, cf, name, created.get("StackId")))
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


def validation_errors(cf, stack_id):
    """(logical id, type, name, status, mode, reason, path) of each VALIDATION_ERROR operation event."""
    return [
        (
            e.get("LogicalResourceId"),
            e.get("ResourceType"),
            e.get("ValidationName"),
            e.get("ValidationStatus"),
            e.get("ValidationFailureMode"),
            e.get("ValidationStatusReason"),
            e.get("ValidationPath"),
        )
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    ]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


# ---- Check-specific: the template, then run(). ----

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lexv2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_MAX_LEN = 2000
_AT_MAX = "A" * _MAX_LEN
_OVER_MAX = "A" * (_MAX_LEN + 1)


def _template(bot_name: str, description: str) -> str:
    return json.dumps(
        {
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
                        "Description": description,
                        "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                        "DataPrivacy": {"ChildDirected": False},
                        "IdleSessionTTLInSeconds": 300,
                    },
                },
            },
            "Outputs": {
                "BotId": {"Value": {"Ref": "Bot"}},
            },
        }
    )


_OVER_MAX_VALIDATION = [
    (
        "Bot",
        "AWS::Lex::Bot",
        "PROPERTY_VALIDATION",
        "FAILED",
        "FAIL",
        f"#/Description: expected maxLength: {_MAX_LEN}, actual: {_MAX_LEN + 1}",
        "/Resources/Bot/Properties/Description",
    )
]
_OVER_MAX_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues "
    "with resource and property details, resolve each error, then retry the operation."
)


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::Lex::Bot Description of 2000 characters is created and read back unchanged; one
    character longer fails the Description maxLength property validation, the stack rolls back with
    no resource and no bot of its name, and the first stack's bot is untouched.
    """
    cfn = ctx.client("cloudformation")
    lex = ctx.client("lexv2-models")
    bot_name_ok = ctx.unique_name("sim2real-behav-lexdesclen-ok-")
    bot_name_bad = ctx.unique_name("sim2real-behav-lexdesclen-bad-")
    stack_ok = ctx.unique_name("sim2real-behav-cfn-lexdesclen-ok-")
    stack_bad = ctx.unique_name("sim2real-behav-cfn-lexdesclen-bad-")

    stack_ok_id = create_stack(
        ctx, cfn, stack_ok, _template(bot_name_ok, _AT_MAX), Capabilities=["CAPABILITY_IAM"]
    )
    status_ok = wait_stack(ctx, cfn, stack_ok_id)
    assert status_ok == "CREATE_COMPLETE", (
        f"stack at the boundary ended {status_ok!r}: {decisive_rows(stack_events(cfn, stack_ok_id))!r}"
    )
    outputs_ok = stack_outputs(cfn, stack_ok_id)
    bot_id_ok = outputs_ok["BotId"]

    before = lex.describe_bot(botId=bot_id_ok)
    assert before["description"] == _AT_MAX, (
        f"boundary bot's description has length {len(before['description'])}, expected "
        f"{_MAX_LEN} characters unchanged"
    )

    stack_bad_id = create_stack(
        ctx, cfn, stack_bad, _template(bot_name_bad, _OVER_MAX), Capabilities=["CAPABILITY_IAM"]
    )
    status_bad = wait_stack(ctx, cfn, stack_bad_id)
    assert status_bad == "ROLLBACK_COMPLETE", (
        f"stack one character past the boundary ended {status_bad!r}, expected ROLLBACK_COMPLETE"
    )

    reason = failed_reason(stack_events(cfn, stack_bad_id), stack_bad, status="CREATE_FAILED")
    assert reason == _OVER_MAX_REASON, f"reason {reason!r} != {_OVER_MAX_REASON!r}"
    found = validation_errors(cfn, stack_bad_id)
    assert found == _OVER_MAX_VALIDATION, (
        f"validation errors of the create: expected {_OVER_MAX_VALIDATION!r}, got {found!r}"
    )
    resources_bad = cfn.describe_stack_resources(StackName=stack_bad_id)["StackResources"]
    assert resources_bad == [], (
        f"expected no resource ever created in the rejected stack, got {resources_bad!r}"
    )

    # The rejected stack created no bot of its name, and the boundary bot is unharmed.
    name_filter = [{"name": "BotName", "values": [bot_name_bad], "operator": "EQ"}]
    named_bad, kwargs = [], {"filters": name_filter}
    while True:
        page = lex.list_bots(**kwargs)
        named_bad += [b["botName"] for b in page["botSummaries"]]
        if not page.get("nextToken"):
            break
        kwargs["nextToken"] = page["nextToken"]
    assert named_bad == [], f"ListBots names {bot_name_bad!r}: {named_bad!r}"
    after = lex.describe_bot(botId=bot_id_ok)
    assert after["creationDateTime"] == before["creationDateTime"], (
        f"boundary bot's creationDateTime changed from {before['creationDateTime']!r} to "
        f"{after['creationDateTime']!r}"
    )
    assert after["description"] == _AT_MAX, (
        f"boundary bot's description changed, got length {len(after['description'])}"
    )
    assert after["botStatus"] == "Available", (
        f"boundary bot's status is {after['botStatus']!r}, expected 'Available'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
