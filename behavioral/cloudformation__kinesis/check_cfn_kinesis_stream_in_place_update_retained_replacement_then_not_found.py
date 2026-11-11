"""cfn-kinesis-stream-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-kinesis-stream-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "kinesis"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: A put record is readable within seconds; the cap only stops a hung poll.
_READ_CAP_S = 60.0
#: Every teardown waits to one deadline, set by the first to run, inside the cleanup budget.
_TEARDOWN_S = 1700.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: Kinesis' refusal of a stream that no longer exists.
_NOT_FOUND_CODE = "ResourceNotFoundException"
_NOT_FOUND_MESSAGE = "Stream {name} under account {account} not found."


def _template(stream_name: str, retention_hours: int) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Stream": {
                    "Type": "AWS::Kinesis::Stream",
                    # Name is create-only, so changing it replaces the stream.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Name": stream_name,
                        "ShardCount": 1,
                        "StreamModeDetails": {"StreamMode": "PROVISIONED"},
                        "RetentionPeriodHours": retention_hours,
                        "Tags": _TAGS,
                    },
                },
            },
            "Outputs": {
                "StreamArn": {"Value": {"Fn::GetAtt": ["Stream", "Arn"]}},
                "Partition": {"Value": {"Ref": "AWS::Partition"}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation stream reads back as templated, updates in place and survives replacement.

    Records round-trip; a RetentionPeriodHours change keeps the stream, a Name change under
    UpdateReplacePolicy Retain keeps the old stream and its record; delete: ResourceNotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kinesis-stream.html
    """
    cfn = ctx.client("cloudformation")
    kinesis = ctx.client("kinesis")
    first = ctx.unique_name("sim2real-cfnkin-a-")
    second = ctx.unique_name("sim2real-cfnkin-b-")
    stack_name = ctx.unique_name("sim2real-cfnkin-stack-")
    ref = {"stack": stack_name}
    teardown: dict = {}

    # The replaced stream is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_stream(kinesis, first))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref, teardown))

    # ---- 1. create: CloudFormation's view, Kinesis' view, and a record round trip
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(first, 24), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    partition = _outputs(stack)["Partition"]
    assert _physical_ids(cfn, ref["stack"])["Stream"] == first, (
        f"the stream's physical id must be its Name {first!r}"
    )
    first_arn = f"arn:{partition}:kinesis:{ctx.region}:{ctx.account}:stream/{first}"
    assert _outputs(stack)["StreamArn"] == first_arn, f"GetAtt Stream.Arn {_outputs(stack)!r}"
    _eventually(ctx, _READ_CAP_S, lambda: _assert_stream(kinesis, first, first_arn, 24))
    kept = _assert_round_trip(ctx, kinesis, first)

    # ---- 2. in-place: a longer RetentionPeriodHours, the same stream
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(first, 48), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Stream"] == first, (
        "an in-place update keeps the stream"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Stream"), first, "Stream")
    _eventually(ctx, _READ_CAP_S, lambda: _assert_stream(kinesis, first, first_arn, 48))
    assert _records(ctx, kinesis, first) == [kept], "an in-place update keeps the stream's record"

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new stream, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(second, 48), Tags=_TAGS)
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Stream"] == second, (
        f"the replacement's physical id must be its Name {second!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Stream"), first, second, "Stream"
    )
    second_arn = f"arn:{partition}:kinesis:{ctx.region}:{ctx.account}:stream/{second}"
    assert _outputs(stack)["StreamArn"] == second_arn, (
        f"GetAtt Stream.Arn after replacement {_outputs(stack)!r}"
    )
    _eventually(ctx, _READ_CAP_S, lambda: _assert_stream(kinesis, second, second_arn, 48))
    _assert_round_trip(ctx, kinesis, second)
    _assert_stream(kinesis, first, first_arn, 48)
    assert _records(ctx, kinesis, first) == [kept], (
        "the retained stream must still hold the record put before the replacement"
    )

    # ---- 4. delete: Kinesis no longer knows the stack's stream
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: kinesis.describe_stream_summary(StreamName=second),
        _NOT_FOUND_CODE,
        f"stream {second}",
    )
    want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(name=second, account=ctx.account))
    assert got == want, f"DescribeStreamSummary after the stack delete answered {got!r}"


def _assert_stream(kinesis, name: str, arn: str, retention_hours: int) -> None:
    """DescribeStreamSummary reports an ACTIVE stream with the template's settings exactly."""
    summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    keys = (
        "StreamName",
        "StreamARN",
        "StreamStatus",
        "StreamModeDetails",
        "RetentionPeriodHours",
        "OpenShardCount",
        "EncryptionType",
    )
    got = {k: summary.get(k) for k in keys}
    want = {
        "StreamName": name,
        "StreamARN": arn,
        "StreamStatus": "ACTIVE",
        "StreamModeDetails": {"StreamMode": "PROVISIONED"},
        "RetentionPeriodHours": retention_hours,
        "OpenShardCount": 1,
        "EncryptionType": "NONE",
    }
    assert got == want, f"DescribeStreamSummary {name!r}: {got!r}, expected {want!r}"


def _assert_round_trip(ctx, kinesis, name: str) -> bytes:
    data = ctx.unique_name("record-").encode()
    kinesis.put_record(StreamName=name, Data=data, PartitionKey="probe")
    got = _records(ctx, kinesis, name)
    assert got == [data], f"GetRecords on {name} returned {got!r}, expected [{data!r}]"
    return data


def _records(ctx, kinesis, name: str) -> list[bytes]:
    """The data of the first non-empty GetRecords read from the stream's only shard's start."""
    (shard,) = kinesis.list_shards(StreamName=name)["Shards"]
    iterator = kinesis.get_shard_iterator(
        StreamName=name, ShardId=shard["ShardId"], ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    timeout = _budget_s(ctx, _READ_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        page = kinesis.get_records(ShardIterator=iterator, Limit=100)
        if page["Records"]:
            return [r["Data"] for r in page["Records"]]
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {name} served a record")
            raise AssertionError(f"no record was readable from {name} within {timeout:.0f}s")
        iterator = page["NextShardIterator"]
        time.sleep(1.0)


def _delete_stream(kinesis, name: str) -> None:
    try:
        kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _NOT_FOUND_CODE:
            raise


def _eventually(ctx, cap_s, probe):
    """Run *probe* until it stops failing an assert; past the cap its last assert fails."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        try:
            return probe()
        except AssertionError as exc:
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"run budget ended before a read converged: {exc}") from None
                raise
        time.sleep(_POLL_S)


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


def _settle(ctx, cfn, stack_id: str, *, teardown: dict | None = None) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status.

    A teardown wait ends at the deadline every teardown shares.
    """
    timeout = _budget_s(ctx, _STACK_CAP_S) if teardown is None else _teardown_left(teardown)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if teardown is None and _budget_spent(ctx):
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


def _delete_stack(ctx, cfn, stack_id: str, *, teardown: dict | None = None) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id, teardown=teardown), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict, teardown: dict) -> None:
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
        stack = _settle(ctx, cfn, stack["StackId"], teardown=teardown)
    _delete_stack(ctx, cfn, stack["StackId"], teardown=teardown)


def _teardown_left(teardown: dict) -> float:
    """Seconds, at least 1, to the deadline every teardown shares; the first to ask fixes it."""
    deadline = teardown.setdefault("deadline", time.monotonic() + _TEARDOWN_S)
    return max(1.0, deadline - time.monotonic())


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
