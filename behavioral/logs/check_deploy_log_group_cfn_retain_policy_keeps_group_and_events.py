"""deploy-log-group-cfn-retain-policy-keeps-group-and-events."""
from __future__ import annotations

import json
import sys
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-log-group-cfn-retain-policy-keeps-group-and-events"
GROUP = "deploy"
SERVICES = ["logs"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """Deleting the stack skips the Retain log group and Retain stream, which keep their events and 5-day
    retention, and deletes the stream with no DeletionPolicy, which then reads ResourceNotFoundException with
    the exact message.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-behav-logs-retain-")
    keep = ctx.unique_name("sim2real-behav-logs-retain-keep-")
    drop = ctx.unique_name("sim2real-behav-logs-retain-drop-")
    stack = ctx.unique_name("sim2real-behav-logs-retain-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "DeletionPolicy": "Retain",
                "UpdateReplacePolicy": "Retain",
                "Properties": {"LogGroupName": group, "RetentionInDays": 5,
                               "Tags": [{"Key": "sim2real", "Value": CHECK}]},
            },
            "KeepStream": {
                "Type": "AWS::Logs::LogStream",
                "DeletionPolicy": "Retain",
                "Properties": {"LogGroupName": {"Ref": "LogGroup"}, "LogStreamName": keep},
            },
            "DropStream": {
                "Type": "AWS::Logs::LogStream",
                "Properties": {"LogGroupName": {"Ref": "LogGroup"}, "LogStreamName": drop},
            },
        },
    }

    # The retained group outlives the stack by design, so its own delete is registered BEFORE
    # the stack's: LIFO runs the stack teardown first, then removes what Retain left behind.
    ctx.on_cleanup(lambda: _delete_group_if_present(logs, group))
    stack_id = cfn.create_stack(
        StackName=stack, TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))

    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}; failures {_failed_events(cfn, stack_id)!r}"
    )

    ts = int(time.time() * 1000)
    kept_events = [(ts, "retain me"), (ts + 1, "retain me too")]
    dropped_events = [(ts + 2, "this stream is deleted with the stack")]
    for name, evs in ((keep, kept_events), (drop, dropped_events)):
        logs.put_log_events(logGroupName=group, logStreamName=name,
                            logEvents=[{"timestamp": t, "message": m} for t, m in evs])
    assert _read_events(logs, group, keep, len(kept_events)) == kept_events, "keep stream misread"
    assert _read_events(logs, group, drop, len(dropped_events)) == dropped_events, "drop stream misread"

    cfn.delete_stack(StackName=stack_id)
    status = _wait_stack(cfn, stack_id)
    assert status == "DELETE_COMPLETE", f"stack delete ended {status!r}"
    statuses = _resource_statuses(cfn, stack_id)
    assert "DELETE_SKIPPED" in statuses.get("LogGroup", []), (
        f"Retain LogGroup should report DELETE_SKIPPED; per-resource statuses {statuses!r}"
    )
    assert "DELETE_COMPLETE" in statuses.get("DropStream", []), (
        f"DropStream (no DeletionPolicy) should report DELETE_COMPLETE; {statuses!r}"
    )

    g = _describe_group(logs, group)
    assert g is not None, f"Retain log group {group!r} was deleted with its stack"
    assert g.get("retentionInDays") == 5, (
        f"retained group lost its retention: retentionInDays={g.get('retentionInDays')!r}"
    )
    streams = _stream_names(logs, group)
    assert streams == {keep}, (
        f"after stack delete the group holds streams {sorted(streams)!r}, expected only {keep!r}"
    )
    assert _read_events(logs, group, keep, len(kept_events)) == kept_events, (
        "events in the retained stream changed after the stack was deleted"
    )
    code, message = _expect_error(lambda: logs.get_log_events(logGroupName=group, logStreamName=drop))
    assert code == "ResourceNotFoundException", (
        f"reading the deleted DropStream returned {code!r}, expected ResourceNotFoundException"
    )
    expected = "The specified log stream does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _wait_stack(cfn: Any, stack_id: str, timeout_s: float = 900.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _STACK_TERMINAL:
            return status
        time.sleep(2)
    raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s}s")


def _stack_events(cfn: Any, stack_id: str) -> list[dict]:
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return events


def _resource_statuses(cfn: Any, stack_id: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for e in reversed(_stack_events(cfn, stack_id)):
        out.setdefault(e["LogicalResourceId"], []).append(e["ResourceStatus"])
    return out


def _failed_events(cfn: Any, stack_id: str) -> list[tuple]:
    return [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
            for e in _stack_events(cfn, stack_id) if e["ResourceStatus"].endswith("FAILED")]


def _describe_group(logs: Any, name: str) -> dict | None:
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        for g in page["logGroups"]:
            if g["logGroupName"] == name:
                return g
    return None


def _stream_names(logs: Any, group: str) -> set[str]:
    names: set[str] = set()
    for page in logs.get_paginator("describe_log_streams").paginate(logGroupName=group):
        names.update(s["logStreamName"] for s in page["logStreams"])
    return names


def _read_events(logs: Any, group: str, stream: str, expected: int,
                 timeout_s: float = 60.0) -> list[tuple[int, str]]:
    deadline = time.monotonic() + timeout_s
    got: list[tuple[int, str]] = []
    while time.monotonic() < deadline:
        resp = logs.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True)
        got = [(e["timestamp"], e["message"]) for e in resp["events"]]
        if len(got) >= expected:
            return got
        time.sleep(2)
    raise AssertionError(f"{group}/{stream} held {len(got)} of {expected} events: {got!r}")


def _expect_error(fn: Any) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded and returned {result!r}")


def _delete_group_if_present(logs: Any, name: str) -> None:
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise RuntimeError(f"{CHECK}: log group {name} not deleted: {exc!r}") from exc


def _teardown_stack(cfn: Any, stack_id: str) -> None:
    try:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status != "DELETE_COMPLETE":
            cfn.delete_stack(StackName=stack_id)
            status = _wait_stack(cfn, stack_id)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"{CHECK}: stack {stack_id} delete failed: {exc!r}") from exc
    if status != "DELETE_COMPLETE":
        raise RuntimeError(f"{CHECK}: stack {stack_id} ended {status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
