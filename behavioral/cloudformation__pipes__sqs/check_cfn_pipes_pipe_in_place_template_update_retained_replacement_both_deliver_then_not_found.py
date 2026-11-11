"""cfn-pipes-pipe-in-place-template-update-retained-replacement-both-deliver-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-pipes-pipe-in-place-template-update-retained-replacement-both-deliver-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "pipes", "sqs"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 300.0
_READ_CAP_S = 120.0
#: A pipe moves a message in seconds; the cap only stops a hung poll.
_DELIVERY_CAP_S = 180.0
#: A pipe change reaches its pollers within moments; a fresh probe is sent this often.
_RESEND_S = 10.0
#: Every teardown waits to one deadline, set by the first to run, inside the cleanup budget.
_TEARDOWN_S = 1700.0
_POLL_S = 2.0

_TAGS = {"sim2real": CHECK}

#: Pipes' refusal of a pipe that no longer exists, keyed by its name.
_NOT_FOUND_CODE = "NotFoundException"
_NOT_FOUND_MESSAGE = "Pipe {name} does not exist."


def _input_template(rev: str) -> str:
    return json.dumps({"probe": "<$.body.probe>", "rev": rev})


def _template(name: str, source: str, rev: str) -> str:
    source_arns = [{"Fn::GetAtt": [q, "Arn"]} for q in ("SourceA", "SourceB")]
    queue = {
        "Type": "AWS::SQS::Queue",
        "Properties": {"Tags": [{"Key": "sim2real", "Value": CHECK}]},
    }
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "SourceA": queue,
                "SourceB": queue,
                "Target": queue,
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "pipes.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "pipe-sqs-access",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "sqs:ReceiveMessage",
                                                "sqs:DeleteMessage",
                                                "sqs:GetQueueAttributes",
                                            ],
                                            "Resource": source_arns,
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": "sqs:SendMessage",
                                            "Resource": {"Fn::GetAtt": ["Target", "Arn"]},
                                        },
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Pipe": {
                    "Type": "AWS::Pipes::Pipe",
                    # Name and Source are create-only, so changing them replaces the pipe.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Name": name,
                        "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                        "Source": {"Fn::GetAtt": [source, "Arn"]},
                        "SourceParameters": {"SqsQueueParameters": {"BatchSize": 1}},
                        "Target": {"Fn::GetAtt": ["Target", "Arn"]},
                        "TargetParameters": {"InputTemplate": _input_template(rev)},
                        "DesiredState": "RUNNING",
                        "Tags": _TAGS,
                    },
                },
            },
            "Outputs": {
                "PipeArn": {"Value": {"Fn::GetAtt": ["Pipe", "Arn"]}},
                "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
                "SourceAArn": {"Value": {"Fn::GetAtt": ["SourceA", "Arn"]}},
                "SourceBArn": {"Value": {"Fn::GetAtt": ["SourceB", "Arn"]}},
                "TargetArn": {"Value": {"Fn::GetAtt": ["Target", "Arn"]}},
                "SourceAUrl": {"Value": {"Ref": "SourceA"}},
                "SourceBUrl": {"Value": {"Ref": "SourceB"}},
                "TargetUrl": {"Value": {"Ref": "Target"}},
                "Partition": {"Value": {"Ref": "AWS::Partition"}},
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
    """A CloudFormation pipe reads back as templated, updates in place and survives replacement.

    It renders its InputTemplate into the target; a template change keeps the pipe, a Name and
    Source change under Retain keeps the old pipe moving its own source; delete: NotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-pipes-pipe.html
    """
    cfn = ctx.client("cloudformation")
    pipes = ctx.client("pipes")
    sqs = ctx.client("sqs")
    first = ctx.unique_name("sim2real-cfnpipe-a-")
    second = ctx.unique_name("sim2real-cfnpipe-b-")
    stack_name = ctx.unique_name("sim2real-cfnpipe-stack-")
    ref = {"stack": stack_name}
    teardown: dict = {}

    # The replaced pipe is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_pipe(teardown, pipes, first))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref, teardown))

    # ---- 1. create: CloudFormation's view, Pipes' view, and a message moved and rendered
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(first, "SourceA", "one"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    out = _outputs(stack)
    assert _physical_ids(cfn, ref["stack"])["Pipe"] == first, (
        f"the pipe's physical id must be its Name {first!r}"
    )
    first_arn = f"arn:{out['Partition']}:pipes:{ctx.region}:{ctx.account}:pipe/{first}"
    assert out["PipeArn"] == first_arn, f"GetAtt Pipe.Arn {out!r}"
    want_a = {"Source": out["SourceAArn"], "Target": out["TargetArn"], "RoleArn": out["RoleArn"]}
    _eventually(ctx, _READ_CAP_S, lambda: _assert_pipe(pipes, first, first_arn, "one", want_a))
    _assert_delivers(ctx, sqs, out["SourceAUrl"], out["TargetUrl"], "one")

    # ---- 2. in-place: a new InputTemplate, the same pipe, rendering the new template
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(first, "SourceA", "two"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Pipe"] == first, "an in-place update keeps the pipe"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Pipe"), first, "Pipe")
    _eventually(ctx, _READ_CAP_S, lambda: _assert_pipe(pipes, first, first_arn, "two", want_a))
    _assert_delivers(ctx, sqs, out["SourceAUrl"], out["TargetUrl"], "two")

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new pipe on SourceB, the old kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(second, "SourceB", "three"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Pipe"] == second, (
        f"the replacement's physical id must be its Name {second!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Pipe"), first, second, "Pipe"
    )
    second_arn = f"arn:{out['Partition']}:pipes:{ctx.region}:{ctx.account}:pipe/{second}"
    assert _outputs(stack)["PipeArn"] == second_arn, (
        f"GetAtt Pipe.Arn after replacement {_outputs(stack)!r}"
    )
    want_b = {**want_a, "Source": out["SourceBArn"]}
    _eventually(ctx, _READ_CAP_S, lambda: _assert_pipe(pipes, second, second_arn, "three", want_b))
    _assert_delivers(ctx, sqs, out["SourceBUrl"], out["TargetUrl"], "three")
    _assert_pipe(pipes, first, first_arn, "two", want_a)
    _assert_delivers(ctx, sqs, out["SourceAUrl"], out["TargetUrl"], "two")

    # ---- 4. delete: Pipes no longer knows the stack's pipe
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx, lambda: pipes.describe_pipe(Name=second), _NOT_FOUND_CODE, f"pipe {second}"
    )
    want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(name=second))
    assert got == want, f"DescribePipe after the stack delete answered {got!r}"


def _assert_pipe(pipes, name: str, arn: str, rev: str, want: dict) -> None:
    """DescribePipe reports a RUNNING pipe with the template's source, target and template."""
    pipe = pipes.describe_pipe(Name=name)
    got = {
        k: pipe.get(k)
        for k in ("Name", "Arn", "DesiredState", "CurrentState", "Source", "Target", "RoleArn")
    }
    got["BatchSize"] = (
        pipe.get("SourceParameters", {}).get("SqsQueueParameters", {}).get("BatchSize")
    )
    got["InputTemplate"] = pipe.get("TargetParameters", {}).get("InputTemplate")
    expected = {
        "Name": name,
        "Arn": arn,
        "DesiredState": "RUNNING",
        "CurrentState": "RUNNING",
        **want,
        "BatchSize": 1,
        "InputTemplate": _input_template(rev),
    }
    assert got == expected, f"DescribePipe {name!r}: {got!r}, expected {expected!r}"


def _assert_delivers(ctx, sqs, source_url: str, target_url: str, rev: str) -> None:
    """Fresh probes go to the source until the target holds one rendered exactly with *rev*.

    A probe is re-sent every few seconds, since a probe sent before a pipe change reaches its
    pollers may still render with the earlier template; those and earlier probes are skipped.
    """
    rendered: list[dict] = []
    seen: list[str] = []
    timeout = _budget_s(ctx, _DELIVERY_CAP_S)
    deadline = time.monotonic() + timeout
    next_send = 0.0
    while True:
        if time.monotonic() >= next_send:
            probe = ctx.unique_name("probe-")
            sqs.send_message(QueueUrl=source_url, MessageBody=json.dumps({"probe": probe}))
            rendered.append({"probe": probe, "rev": rev})
            next_send = time.monotonic() + _RESEND_S
        messages = sqs.receive_message(
            QueueUrl=target_url, MaxNumberOfMessages=10, WaitTimeSeconds=2
        ).get("Messages", [])
        for m in messages:
            sqs.delete_message(QueueUrl=target_url, ReceiptHandle=m["ReceiptHandle"])
            seen.append(m["Body"])
        for body in seen[len(seen) - len(messages) :]:
            if _parsed(body) in rendered:
                return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before the pipe rendered rev {rev!r}")
            raise AssertionError(
                f"no probe rendered as {rendered!r} reached the target within "
                f"{timeout:.0f}s; it received {seen!r}"
            )


def _parsed(body: str):
    try:
        return json.loads(body)
    except ValueError:
        return body


def _delete_pipe(teardown: dict, pipes, name: str) -> None:
    """Delete the pipe and wait until Pipes no longer knows it."""
    try:
        pipes.delete_pipe(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == _NOT_FOUND_CODE:
            return
        raise
    _wait_error(
        None,
        lambda: pipes.describe_pipe(Name=name),
        _NOT_FOUND_CODE,
        f"pipe {name}",
        teardown=teardown,
    )


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

    A teardown wait ends _GONE_CAP_S before the deadline every teardown shares, which the
    retained pipe's delete, run last, keeps for its own wait.
    """
    timeout = (
        _budget_s(ctx, _STACK_CAP_S) if teardown is None else _teardown_left(teardown, _GONE_CAP_S)
    )
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


def _wait_error(ctx, fn, code: str, what: str, *, teardown: dict | None = None):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message).

    A teardown wait ends at the deadline every teardown shares.
    """
    timeout = _budget_s(ctx, _GONE_CAP_S) if teardown is None else _teardown_left(teardown)
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
            if teardown is None and _budget_spent(ctx):
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


def _teardown_left(teardown: dict, reserve_s: float = 0.0) -> float:
    """Seconds, at least 1, to the deadline every teardown shares, less *reserve_s*.

    The first teardown to ask fixes the deadline.
    """
    deadline = teardown.setdefault("deadline", time.monotonic() + _TEARDOWN_S)
    return max(1.0, deadline - reserve_s - time.monotonic())


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
