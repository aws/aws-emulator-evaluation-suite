"""cfn-lambda-permission-retained-replacement-keeps-both-grants-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-permission-retained-replacement-keeps-both-grants-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "events", "lambda", "sqs"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_RECEIVE_CAP_S = 120.0
#: A new rule, grant or role policy can lag for a short while, so a fresh probe follows this often.
_RESEND_S = 10.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_HANDLER = (
    "import json\n"
    "import os\n"
    "\n"
    "import boto3\n"
    "\n"
    "_SQS = boto3.client('sqs')\n"
    "\n"
    "\n"
    "def handler(event, context):\n"
    "    body = json.dumps({'source': event['source'], 'detail': event['detail']})\n"
    "    _SQS.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=body)\n"
    "    return {'ok': True}\n"
)

#: Lambda's refusal of a policy read on a function that no longer exists.
_NOT_FOUND = ("ResourceNotFoundException", "The resource you requested does not exist.")


def _rule(source: str) -> dict:
    return {
        "Type": "AWS::Events::Rule",
        "Properties": {
            "EventPattern": {"source": [source]},
            "State": "ENABLED",
            "Targets": [{"Arn": {"Fn::GetAtt": ["Fn", "Arn"]}, "Id": "fn"}],
        },
    }


def _template(function_name: str, source_a: str, source_b: str, granted_rule: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": _TAGS}},
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "send-to-queue",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "sqs:SendMessage",
                                            "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Fn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "FunctionName": function_name,
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                        "Code": {"ZipFile": _HANDLER},
                        "Timeout": 30,
                        "Environment": {"Variables": {"QUEUE_URL": {"Ref": "Queue"}}},
                        "Tags": _TAGS,
                    },
                },
                "RuleA": _rule(source_a),
                "RuleB": _rule(source_b),
                "Perm": {
                    "Type": "AWS::Lambda::Permission",
                    # Every Permission property is create-only, so a new SourceArn replaces it.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "FunctionName": {"Ref": "Fn"},
                        "Action": "lambda:InvokeFunction",
                        "Principal": "events.amazonaws.com",
                        "SourceArn": {"Fn::GetAtt": [granted_rule, "Arn"]},
                    },
                },
            },
            "Outputs": {
                "FnArn": {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}},
                "RuleAArn": {"Value": {"Fn::GetAtt": ["RuleA", "Arn"]}},
                "RuleBArn": {"Value": {"Fn::GetAtt": ["RuleB", "Arn"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c7",
    "concern:deploy",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation Lambda permission reads back through GetPolicy and survives replacement.

    Its rule's events invoke the function; a SourceArn change under UpdateReplacePolicy Retain adds
    a grant and keeps the old one serving; delete: GetPolicy ResourceNotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-permission.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    fn_name = ctx.unique_name("sim2real-cfnperm-")
    stack_name = ctx.unique_name("sim2real-cfnperm-stack-")
    source_a = ctx.unique_name("sim2real.perm.a.")
    source_b = ctx.unique_name("sim2real.perm.b.")
    ref = {"stack": stack_name}
    retained = {}

    # The replaced statement is retained on the function; teardown removes it if the function lives.
    ctx.on_cleanup(lambda: _remove_statement(lam, fn_name, retained.get("sid")))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref))

    # ---- 1. create: CloudFormation's view, Lambda's policy, and the rule invoking the function
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(fn_name, source_a, source_b, "RuleA"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    outputs = _outputs(stack)
    ids = _physical_ids(cfn, ref["stack"])
    first_sid, queue_url = ids["Perm"], ids["Queue"]
    retained["sid"] = first_sid
    fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_name}"
    assert outputs["FnArn"] == fn_arn, f"GetAtt Fn.Arn {outputs['FnArn']!r}, expected {fn_arn!r}"
    statements = _statements(lam, fn_name)
    assert set(statements) == {first_sid}, (
        f"GetPolicy must hold exactly the stack's statement {first_sid!r}: {sorted(statements)!r}"
    )
    _assert_statement(statements[first_sid], fn_arn, outputs["RuleAArn"])
    _assert_delivered(ctx, events, sqs, queue_url, source_a)

    # ---- 2. replacement under UpdateReplacePolicy Retain: a new grant, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(fn_name, source_a, source_b, "RuleB"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    second_sid = _physical_ids(cfn, ref["stack"])["Perm"]
    assert second_sid != first_sid, f"the replacement must be a new statement, still {first_sid!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Perm"), first_sid, second_sid, "Perm"
    )
    statements = _statements(lam, fn_name)
    assert set(statements) == {first_sid, second_sid}, (
        f"GetPolicy must hold the retained {first_sid!r} and the new {second_sid!r}: "
        f"{sorted(statements)!r}"
    )
    _assert_statement(statements[second_sid], fn_arn, outputs["RuleBArn"])
    _assert_statement(statements[first_sid], fn_arn, outputs["RuleAArn"])
    _assert_delivered(ctx, events, sqs, queue_url, source_b)
    _assert_delivered(ctx, events, sqs, queue_url, source_a)

    # ---- 3. delete: the function, and with it its policy, is gone
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx, lambda: lam.get_policy(FunctionName=fn_name), _NOT_FOUND[0], f"policy of {fn_name}"
    )
    assert got == _NOT_FOUND, f"GetPolicy after the stack delete answered {got!r}"


def _statements(lam, fn_name: str) -> dict[str, dict]:
    policy = json.loads(lam.get_policy(FunctionName=fn_name)["Policy"])
    return {s["Sid"]: s for s in policy["Statement"]}


def _assert_statement(statement: dict, fn_arn: str, rule_arn: str) -> None:
    """The statement grants exactly what the template declares."""
    got = {k: statement.get(k) for k in ("Effect", "Principal", "Action", "Resource", "Condition")}
    want = {
        "Effect": "Allow",
        "Principal": {"Service": "events.amazonaws.com"},
        "Action": "lambda:InvokeFunction",
        "Resource": fn_arn,
        "Condition": {"ArnLike": {"AWS:SourceArn": rule_arn}},
    }
    assert got == want, f"statement {statement.get('Sid')!r}: {got!r}, expected {want!r}"


def _assert_delivered(ctx, events, sqs, queue_url: str, source: str) -> None:
    """An event matching the rule reaches the function, which writes it to the queue.

    A fresh probe is put every _RESEND_S until one arrives; the first one received is asserted.
    """
    sent: list[str] = []
    timeout = _budget_s(ctx, _RECEIVE_CAP_S)
    deadline = time.monotonic() + timeout
    resend_at = 0.0
    got: list = []
    while True:
        if time.monotonic() >= resend_at:
            probe = ctx.unique_name("probe-")
            put = events.put_events(
                Entries=[
                    {
                        "Source": source,
                        "DetailType": "sim2real-probe",
                        "Detail": json.dumps({"probe": probe}),
                    }
                ]
            )
            assert put["FailedEntryCount"] == 0, f"PutEvents refused the probe: {put['Entries']!r}"
            sent.append(probe)
            resend_at = time.monotonic() + _RESEND_S
        for m in sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            got.append(json.loads(m["Body"]))
        mine = [b for b in got if (b.get("detail") or {}).get("probe") in sent]
        if mine:
            want = {"source": source, "detail": {"probe": mine[0]["detail"]["probe"]}}
            assert mine[0] == want, f"the handled {source} event: {mine[0]!r}, expected {want!r}"
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before the {source} event was handled")
            raise AssertionError(
                f"the {source} rule's invocation never reached the queue within {timeout:.0f}s; "
                f"received {got!r}"
            )


def _remove_statement(lam, fn_name: str, sid: str | None) -> None:
    if sid is None:
        return
    try:
        lam.remove_permission(FunctionName=fn_name, StatementId=sid)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _NOT_FOUND[0]:
            raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message.
    """
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done."""
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"])
    _delete_stack(ctx, cfn, stack["StackId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
