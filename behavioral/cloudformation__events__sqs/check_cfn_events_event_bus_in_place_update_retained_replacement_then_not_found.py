"""cfn-events-event-bus-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-events-event-bus-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "events", "sqs"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_RECEIVE_CAP_S = 60.0
#: A new or updated rule can miss events for a short while, so a fresh probe follows this often.
_RESEND_S = 8.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: EventBridge's refusal of an event bus that no longer exists, naming the bus.
_NOT_FOUND_CODE = "ResourceNotFoundException"
_NOT_FOUND_MESSAGE = "Event bus {name} does not exist."


def _template(bus_name: str, description: str, source: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bus": {
                    "Type": "AWS::Events::EventBus",
                    # Name is create-only, so changing it replaces the bus.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {"Name": bus_name, "Description": description, "Tags": _TAGS},
                },
                "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"Tags": _TAGS}},
                "Rule": {
                    "Type": "AWS::Events::Rule",
                    "Properties": {
                        "EventBusName": {"Ref": "Bus"},
                        "EventPattern": {"source": [source]},
                        "State": "ENABLED",
                        "Targets": [{"Arn": {"Fn::GetAtt": ["Queue", "Arn"]}, "Id": "queue"}],
                    },
                },
                "QueuePolicy": {
                    "Type": "AWS::SQS::QueuePolicy",
                    "Properties": {
                        "Queues": [{"Ref": "Queue"}],
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "events.amazonaws.com"},
                                    "Action": "sqs:SendMessage",
                                    "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                                    "Condition": {
                                        "ArnEquals": {
                                            "aws:SourceArn": {"Fn::GetAtt": ["Rule", "Arn"]}
                                        },
                                    },
                                }
                            ],
                        },
                    },
                },
            },
            "Outputs": {
                "BusName": {"Value": {"Ref": "Bus"}},
                "BusArn": {"Value": {"Fn::GetAtt": ["Bus", "Arn"]}},
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
    """A CloudFormation event bus reads back, updates in place and survives replacement.

    Its rule routes an event to a queue; a Description change keeps the bus, a Name change under
    UpdateReplacePolicy Retain keeps the old bus; delete: ResourceNotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-events-eventbus.html
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    first = ctx.unique_name("sim2real-cfnbus-a-")
    second = ctx.unique_name("sim2real-cfnbus-b-")
    stack_name = ctx.unique_name("sim2real-cfnbus-stack-")
    source = ctx.unique_name("sim2real.bus.")
    ref = {"stack": stack_name}
    first_arn = f"arn:aws:events:{ctx.region}:{ctx.account}:event-bus/{first}"
    second_arn = f"arn:aws:events:{ctx.region}:{ctx.account}:event-bus/{second}"

    # The replaced bus is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_bus(events, first))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref))

    # ---- 1. create: CloudFormation's view, EventBridge's view, and an event routed
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(first, "first", source),
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    queue_url = ids["Queue"]
    assert ids["Bus"] == first, f"the bus's physical id must be its Name {first!r}"
    assert _outputs(stack) == {"BusName": first, "BusArn": first_arn}, (
        f"Ref and GetAtt Arn: {_outputs(stack)!r}"
    )
    _assert_bus(events, first, first_arn, "first")
    _assert_routed(ctx, events, sqs, first, source, queue_url)

    # ---- 2. in-place: a new Description, the same bus
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(first, "second", source), Tags=_TAGS
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Bus"] == first, "an in-place update keeps the bus"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Bus"), first, "Bus")
    _assert_bus(events, first, first_arn, "second")
    _assert_routed(ctx, events, sqs, first, source, queue_url)

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new bus, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(second, "second", source), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Bus"] == second, (
        f"the stack must track the replacement {second!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Bus"), first, second, "Bus"
    )
    assert _outputs(stack) == {"BusName": second, "BusArn": second_arn}, (
        f"Ref and GetAtt Arn after replacement: {_outputs(stack)!r}"
    )
    _assert_bus(events, second, second_arn, "second")
    _assert_routed(ctx, events, sqs, second, source, queue_url)
    _assert_bus(events, first, first_arn, "second")

    # ---- 4. delete: EventBridge no longer knows the stack's bus
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx, lambda: events.describe_event_bus(Name=second), _NOT_FOUND_CODE, f"event bus {second}"
    )
    want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(name=second))
    assert got == want, f"DescribeEventBus after the stack delete answered {got!r}"


def _assert_bus(events, name: str, arn: str, description: str) -> None:
    """DescribeEventBus reports the template's bus exactly."""
    described = events.describe_event_bus(Name=name)
    got = {k: described.get(k) for k in ("Name", "Arn", "Description")}
    want = {"Name": name, "Arn": arn, "Description": description}
    assert got == want, f"DescribeEventBus {name}: {got!r}, expected {want!r}"


def _assert_routed(ctx, events, sqs, bus: str, source: str, queue_url: str) -> None:
    """An event put on the bus matches the stack's rule and arrives on its queue.

    A fresh probe is put every _RESEND_S until one arrives; the first one received is asserted.
    """
    sent: dict[str, str] = {}
    timeout = _budget_s(ctx, _RECEIVE_CAP_S)
    deadline = time.monotonic() + timeout
    resend_at = 0.0
    got: list[dict] = []
    while True:
        if time.monotonic() >= resend_at:
            probe = ctx.unique_name("probe-")
            put = events.put_events(
                Entries=[
                    {
                        "EventBusName": bus,
                        "Source": source,
                        "DetailType": "sim2real-probe",
                        "Detail": json.dumps({"probe": probe}),
                    }
                ]
            )
            assert put["FailedEntryCount"] == 0, f"PutEvents refused the probe: {put['Entries']!r}"
            sent[put["Entries"][0]["EventId"]] = probe
            resend_at = time.monotonic() + _RESEND_S
        for m in sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
        ).get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            got.append(json.loads(m["Body"]))
        mine = [e for e in got if e.get("id") in sent]
        if mine:
            shape = {
                k: mine[0].get(k) for k in ("source", "detail-type", "detail", "account", "region")
            }
            want = {
                "source": source,
                "detail-type": "sim2real-probe",
                "detail": {"probe": sent[mine[0]["id"]]},
                "account": ctx.account,
                "region": ctx.region,
            }
            assert shape == want, f"the routed event on {bus}: {mine[0]!r}, expected {want!r}"
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {bus} routed the event")
            raise AssertionError(
                f"none of the events {sorted(sent)!r} on {bus} reached the queue within "
                f"{timeout:.0f}s; received {got!r}"
            )


def _delete_bus(events, name: str) -> None:
    try:
        events.delete_event_bus(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _NOT_FOUND_CODE:
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
