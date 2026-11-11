"""deploy-log-group-cfn-rename-replaces-group-and-drops-events."""
from __future__ import annotations

import json
import sys
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-log-group-cfn-rename-replaces-group-and-drops-events"
GROUP = "deploy"
SERVICES = ["logs"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _template(group: str, stream: str) -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": group, "RetentionInDays": 1,
                               "Tags": [{"Key": "sim2real", "Value": CHECK}]},
            },
            "LogStream": {
                "Type": "AWS::Logs::LogStream",
                "Properties": {"LogGroupName": {"Ref": "LogGroup"}, "LogStreamName": stream},
            },
        },
        "Outputs": {"GroupArn": {"Value": {"Fn::GetAtt": ["LogGroup", "Arn"]}}},
    }


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """Changing LogGroupName replaces the group: new physical id and ARN, the stream recreated with
    no old events, the old group deleted, and the new group writable.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    old = ctx.unique_name("sim2real-behav-logs-rename-old-")
    new = ctx.unique_name("sim2real-behav-logs-rename-new-")
    stream = ctx.unique_name("sim2real-behav-logs-rename-s-")
    stack = ctx.unique_name("sim2real-behav-logs-rename-")

    stack_id = cfn.create_stack(
        StackName=stack, TemplateBody=json.dumps(_template(old, stream)),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"create ended {status!r}: {_failed_events(cfn, stack_id)!r}"
    old_arn = _outputs(cfn, stack_id)["GroupArn"]
    assert _physical_id(cfn, stack_id, "LogGroup") == old, "LogGroup physical id is not its name"

    ts = int(time.time() * 1000)
    sent = [(ts, "written to the original group")]
    logs.put_log_events(logGroupName=old, logStreamName=stream,
                        logEvents=[{"timestamp": t, "message": m} for t, m in sent])
    assert _read_events(logs, old, stream, 1) == sent, "original group did not serve its event"

    cfn.update_stack(StackName=stack_id, TemplateBody=json.dumps(_template(new, stream)),
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"rename update ended {status!r}: {_failed_events(cfn, stack_id)!r}"

    phys = _physical_id(cfn, stack_id, "LogGroup")
    new_arn = _outputs(cfn, stack_id)["GroupArn"]
    assert phys == new, f"after rename LogGroup physical id is {phys!r}, expected {new!r}"
    expected_arn = old_arn.replace(f":log-group:{old}", f":log-group:{new}")
    assert expected_arn != old_arn and new_arn == expected_arn, (
        f"GroupArn output after rename is {new_arn!r}, expected {expected_arn!r} (was {old_arn!r})"
    )

    assert _describe_group(logs, old) is None, (
        f"old log group {old!r} survived its replacement"
    )
    code, message = _expect_error(lambda: logs.get_log_events(logGroupName=old, logStreamName=stream))
    assert code == "ResourceNotFoundException", (
        f"reading the replaced group returned {code!r}, expected ResourceNotFoundException"
    )
    expected = "The specified log group does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    g = _describe_group(logs, new)
    assert g is not None and g.get("retentionInDays") == 1, f"replacement group described {g!r}"
    assert _stream_names(logs, new) == {stream}, (
        f"replacement group streams {sorted(_stream_names(logs, new))!r}, expected [{stream!r}]"
    )
    carried = _events(logs, new, stream)
    assert carried == [], f"replacement group carried events over from the old one: {carried!r}"

    ts2 = int(time.time() * 1000)
    after = [(ts2, "written to the replacement group")]
    logs.put_log_events(logGroupName=new, logStreamName=stream,
                        logEvents=[{"timestamp": t, "message": m} for t, m in after])
    assert _read_events(logs, new, stream, 1) == after, "replacement group did not serve its event"


def _wait_stack(cfn: Any, stack_id: str, timeout_s: float = 900.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _STACK_TERMINAL:
            return status
        time.sleep(2)
    raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s}s")


def _outputs(cfn: Any, stack_id: str) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"]
            for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0].get("Outputs", [])}


def _physical_id(cfn: Any, stack_id: str, logical: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical)[
        "StackResourceDetail"]["PhysicalResourceId"]


def _failed_events(cfn: Any, stack_id: str) -> list[tuple]:
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out += [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
                for e in page["StackEvents"] if e["ResourceStatus"].endswith("FAILED")]
    return out


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


def _events(logs: Any, group: str, stream: str) -> list[tuple[int, str]]:
    resp = logs.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True)
    return [(e["timestamp"], e["message"]) for e in resp["events"]]


def _read_events(logs: Any, group: str, stream: str, expected: int,
                 timeout_s: float = 60.0) -> list[tuple[int, str]]:
    deadline = time.monotonic() + timeout_s
    got: list[tuple[int, str]] = []
    while time.monotonic() < deadline:
        got = _events(logs, group, stream)
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
