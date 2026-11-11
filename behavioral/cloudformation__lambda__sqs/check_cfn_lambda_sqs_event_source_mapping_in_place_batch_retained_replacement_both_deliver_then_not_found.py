"""cfn-lambda-sqs-event-source-mapping-in-place-batch-retained-replacement-both-deliver-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "cfn-lambda-sqs-event-source-mapping-in-place-batch-retained-replacement-both-deliver-then-"
    "not-found"
)
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "sqs"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: A new or updated mapping starts polling its queue after a short while.
_STATE_CAP_S = 120.0
_DELIVER_CAP_S = 120.0
#: A message sent before the mapping polls is still consumed, but a fresh one follows this often.
_RESEND_S = 10.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
#: Forwards every record it receives to the sink queue, naming the queue it came from.
_HANDLER = (
    "import json\n"
    "import os\n"
    "\n"
    "import boto3\n"
    "\n"
    "sqs = boto3.client('sqs')\n"
    "\n"
    "\n"
    "def handler(event, context):\n"
    "    for record in event['Records']:\n"
    "        sqs.send_message(\n"
    "            QueueUrl=os.environ['SINK_URL'],\n"
    "            MessageBody=json.dumps(\n"
    "                {'source': record['eventSourceARN'], 'body': record['body']}\n"
    "            ),\n"
    "        )\n"
)

#: Lambda's refusal of a mapping that no longer exists.
_NOT_FOUND = ("ResourceNotFoundException", "The resource you requested does not exist.")


def _template(function_name: str, source: str, batch_size: int) -> str:
    sources = [{"Fn::GetAtt": [q, "Arn"]} for q in ("SourceA", "SourceB")]
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "SourceA": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": _TAGS}},
                "SourceB": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": _TAGS}},
                "Sink": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": _TAGS}},
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
                                "PolicyName": "consume-and-forward",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "sqs:ReceiveMessage",
                                                "sqs:DeleteMessage",
                                                "sqs:GetQueueAttributes",
                                                "sqs:ChangeMessageVisibility",
                                            ],
                                            "Resource": sources,
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": "sqs:SendMessage",
                                            "Resource": {"Fn::GetAtt": ["Sink", "Arn"]},
                                        },
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
                        "MemorySize": 128,
                        "Timeout": 10,
                        "Environment": {"Variables": {"SINK_URL": {"Ref": "Sink"}}},
                        "Tags": _TAGS,
                    },
                },
                "Mapping": {
                    "Type": "AWS::Lambda::EventSourceMapping",
                    # EventSourceArn is create-only, so another queue replaces the mapping.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "EventSourceArn": {"Fn::GetAtt": [source, "Arn"]},
                        "FunctionName": {"Ref": "Fn"},
                        "BatchSize": batch_size,
                        "Enabled": True,
                    },
                },
            },
            "Outputs": {
                "FnArn": {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}},
                "SourceAArn": {"Value": {"Fn::GetAtt": ["SourceA", "Arn"]}},
                "SourceBArn": {"Value": {"Fn::GetAtt": ["SourceB", "Arn"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation SQS mapping reads back, invokes its function and survives replacement.

    A BatchSize change keeps the mapping; an EventSourceArn change under UpdateReplacePolicy
    Retain leaves both mappings forwarding their queue's messages; delete: not found.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-cfnesm-")
    stack_name = ctx.unique_name("sim2real-cfnesm-stack-")
    ref = {"stack": stack_name}
    retained = {}

    # The replaced mapping is retained, so it outlives the stack and needs its own teardown.
    # Teardowns run last-registered first: the retained mapping goes before the stack's function.
    ctx.on_cleanup(lambda: _teardown_stack(None, cfn, ref))
    ctx.on_cleanup(lambda: _delete_mapping(None, lam, retained.get("uuid")))

    # ---- 1. create: CloudFormation's view, Lambda's view, and a message forwarded
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(name, "SourceA", 1),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    out = _outputs(stack)
    ids = _physical_ids(cfn, ref["stack"])
    first = ids["Mapping"]
    retained["uuid"] = first
    _assert_mapping(ctx, lam, first, out["SourceAArn"], out["FnArn"], 1)
    _deliver(ctx, sqs, ids["SourceA"], ids["Sink"], out["SourceAArn"])

    # ---- 2. in-place: a new BatchSize, the same mapping
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(name, "SourceA", 5),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Mapping"] == first, "an in-place update keeps it"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Mapping"), first, "Mapping")
    _assert_mapping(ctx, lam, first, out["SourceAArn"], out["FnArn"], 5)
    _deliver(ctx, sqs, ids["SourceA"], ids["Sink"], out["SourceAArn"])

    # ---- 3. replacement under UpdateReplacePolicy Retain: a mapping on queue B, A's kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(name, "SourceB", 5),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    second = _physical_ids(cfn, ref["stack"])["Mapping"]
    assert second != first, f"the replacement must be a new mapping, still {first!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Mapping"), first, second, "Mapping"
    )
    _assert_mapping(ctx, lam, second, out["SourceBArn"], out["FnArn"], 5)
    _assert_mapping(ctx, lam, first, out["SourceAArn"], out["FnArn"], 5)
    listed = {
        (m["UUID"], m["EventSourceArn"])
        for m in lam.list_event_source_mappings(FunctionName=name)["EventSourceMappings"]
    }
    assert listed == {(first, out["SourceAArn"]), (second, out["SourceBArn"])}, (
        f"ListEventSourceMappings of {name}: {listed!r}"
    )
    _deliver(ctx, sqs, ids["SourceB"], ids["Sink"], out["SourceBArn"])
    _deliver(ctx, sqs, ids["SourceA"], ids["Sink"], out["SourceAArn"])

    # ---- 4. delete: Lambda no longer knows either mapping
    # The retained mapping is no longer the stack's; it is deleted before the stack's function.
    lam.delete_event_source_mapping(UUID=first)
    got = _wait_error(
        ctx, lambda: lam.get_event_source_mapping(UUID=first), _NOT_FOUND[0], f"mapping {first}"
    )
    assert got == _NOT_FOUND, f"GetEventSourceMapping of the deleted {first} answered {got!r}"
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: lam.get_event_source_mapping(UUID=second),
        _NOT_FOUND[0],
        f"mapping {second}",
    )
    assert got == _NOT_FOUND, f"GetEventSourceMapping after the stack delete answered {got!r}"


def _assert_mapping(ctx, lam, uuid: str, source_arn: str, fn_arn: str, batch_size: int) -> None:
    """GetEventSourceMapping reports the template's mapping exactly, once it is Enabled."""
    mapping = _poll(
        ctx,
        lambda: lam.get_event_source_mapping(UUID=uuid),
        lambda m: m.get("State") not in ("Creating", "Enabling", "Updating"),
        f"mapping {uuid} to settle",
        _STATE_CAP_S,
    )
    got = {
        k: mapping.get(k) for k in ("UUID", "EventSourceArn", "FunctionArn", "BatchSize", "State")
    }
    want = {
        "UUID": uuid,
        "EventSourceArn": source_arn,
        "FunctionArn": fn_arn,
        "BatchSize": batch_size,
        "State": "Enabled",
    }
    assert got == want, f"GetEventSourceMapping {uuid}: {got!r}, expected {want!r}"


def _deliver(ctx, sqs, source_url: str, sink_url: str, source_arn: str) -> None:
    """Send to the source until the function forwards one of the probes to the sink."""
    sent: list[str] = []
    timeout = _budget_s(ctx, _DELIVER_CAP_S)
    deadline = time.monotonic() + timeout
    resend_at = 0.0
    got: list[str] = []
    while True:
        if time.monotonic() >= resend_at:
            sent.append(ctx.unique_name("probe-"))
            sqs.send_message(QueueUrl=source_url, MessageBody=sent[-1])
            resend_at = time.monotonic() + _RESEND_S
        for m in sqs.receive_message(
            QueueUrl=sink_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=sink_url, ReceiptHandle=m["ReceiptHandle"])
            got.append(m["Body"])
            forwarded = json.loads(m["Body"])
            if forwarded.get("body") in sent:
                assert forwarded == {"source": source_arn, "body": forwarded["body"]}, (
                    f"the function must forward {source_arn}'s record, got {forwarded!r}"
                )
                return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {source_arn} reached the sink")
            raise AssertionError(
                f"none of {sent!r} sent to {source_arn} reached the sink within {timeout:.0f}s; "
                f"the sink received {got!r}"
            )


def _delete_mapping(ctx, lam, uuid: str | None) -> None:
    """Delete the mapping and wait until Lambda no longer knows it."""
    if uuid is None:
        return
    try:
        lam.delete_event_source_mapping(UUID=uuid)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == _NOT_FOUND[0]:
            return
        raise
    _wait_error(ctx, lambda: lam.get_event_source_mapping(UUID=uuid), _NOT_FOUND[0], uuid)


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. A teardown passes ``ctx=None`` and waits the full
    cap_s; in a teardown, ctx.time_left() counts down the runner's cleanup timeout.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
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


def _poll(ctx, read, ok, what: str, cap_s: float):
    """Re-read until ``ok(value)`` holds, for an eventually consistent read; the last value."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        value = read()
        if ok(value):
            return value
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while waiting for {what}")
            raise AssertionError(f"{what} not reached after {timeout:.0f}s; last read {value!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
