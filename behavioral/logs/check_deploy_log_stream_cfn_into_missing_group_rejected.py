"""deploy-log-stream-cfn-into-missing-group-rejected."""
from __future__ import annotations

import json
import sys
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-log-stream-cfn-into-missing-group-rejected"
GROUP = "deploy"
SERVICES = ["logs"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _template(group: str, stream: str, *, with_group: bool) -> dict:
    resources: dict = {
        "LogStream": {
            "Type": "AWS::Logs::LogStream",
            # A literal name, not a Ref: the template is valid CloudFormation either way, so
            # the fault can only surface when the stream's create reaches CloudWatch Logs.
            "Properties": {"LogGroupName": group, "LogStreamName": stream},
        },
    }
    if with_group:
        resources["LogGroup"] = {
            "Type": "AWS::Logs::LogGroup",
            "Properties": {"LogGroupName": group, "RetentionInDays": 1,
                           "Tags": [{"Key": "sim2real", "Value": CHECK}]},
        }
        resources["LogStream"]["DependsOn"] = "LogGroup"
    return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources}


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack with only a LogStream into a missing group rolls back without creating the stream or
    the group; the same template with the LogGroup deploys and the stream accepts writes.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    missing = ctx.unique_name("sim2real-behav-logs-nogroup-")
    stream = ctx.unique_name("sim2real-behav-logs-nogroup-s-")
    bad_stack = ctx.unique_name("sim2real-behav-logs-nogroup-bad-")
    good_group = ctx.unique_name("sim2real-behav-logs-nogroup-ok-")
    good_stack = ctx.unique_name("sim2real-behav-logs-nogroup-ok-")

    bad_id = cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=json.dumps(_template(missing, stream, with_group=False)),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, bad_id))
    status = _wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack with a LogStream into a missing group ended {status!r}, expected ROLLBACK_COMPLETE"
    )
    statuses = _resource_statuses(cfn, bad_id)
    assert "CREATE_FAILED" in statuses.get("LogStream", []), (
        f"LogStream never reported CREATE_FAILED; per-resource statuses {statuses!r}"
    )
    assert "CREATE_COMPLETE" not in statuses.get("LogStream", []), (
        f"LogStream reported CREATE_COMPLETE into a missing group: {statuses!r}"
    )
    assert _describe_group(logs, missing) is None, (
        f"log group {missing!r} exists: the failed stream create created its parent implicitly"
    )

    # Positive control: identical stream, with its group in the template.
    good_id = cfn.create_stack(
        StackName=good_stack,
        TemplateBody=json.dumps(_template(good_group, stream, with_group=True)),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, good_id))
    status = _wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {_resource_statuses(cfn, good_id)!r}"
    )
    ts = int(time.time() * 1000)
    logs.put_log_events(logGroupName=good_group, logStreamName=stream,
                        logEvents=[{"timestamp": ts, "message": "control stream works"}])
    got = _read_events(logs, good_group, stream, 1)
    assert got == [(ts, "control stream works")], f"control stream returned {got!r}"
    # The broken stack still left nothing in its would-be group after the control ran.
    code, message = _error(lambda: logs.describe_log_streams(logGroupName=missing))
    assert code == "ResourceNotFoundException", (
        f"describe_log_streams on the never-created group returned {code!r}"
    )
    assert message == "The specified log group does not exist.", (
        f"describe_log_streams on the never-created group returned message {message!r}"
    )


def _wait_stack(cfn: Any, stack_id: str, timeout_s: float = 900.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _STACK_TERMINAL:
            return status
        time.sleep(2)
    raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s}s")


def _resource_statuses(cfn: Any, stack_id: str) -> dict[str, list[str]]:
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    out: dict[str, list[str]] = {}
    for e in reversed(events):
        out.setdefault(e["LogicalResourceId"], []).append(e["ResourceStatus"])
    return out


def _describe_group(logs: Any, name: str) -> dict | None:
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        for g in page["logGroups"]:
            if g["logGroupName"] == name:
                return g
    return None


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


def _error(fn: Any) -> tuple[str, str | None]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded and returned {result!r}")


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
