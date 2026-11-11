"""deploy-log-group-cfn-then-put-events-succeeds."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-log-group-cfn-then-put-events-succeeds"
GROUP = "deploy"
SERVICES = ["logs"]

_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "CREATE_FAILED",
}


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Logs::LogGroup/LogStream accepts PutLogEvents and
    GetLogEvents returns the exact same ordered payload as an equivalent API-created group."""
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    cfn_group_name = ctx.unique_name("sim2real-behav-logs-cfn-group-")
    cfn_stream_name = ctx.unique_name("sim2real-behav-logs-cfn-stream-")
    api_group_name = ctx.unique_name("sim2real-behav-logs-api-group-")
    api_stream_name = ctx.unique_name("sim2real-behav-logs-api-stream-")
    stack_name = ctx.unique_name("sim2real-behav-logs-stack-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": cfn_group_name, "RetentionInDays": 1},
            },
            "LogStream": {
                "Type": "AWS::Logs::LogStream",
                "Properties": {
                    "LogGroupName": {"Ref": "LogGroup"},
                    "LogStreamName": cfn_stream_name,
                },
            },
        },
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    status = _wait_stack_terminal(cfn, stack_name, timeout_s=300, interval_s=10)
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE, got {status}"

    # API-created twin, used as the fidelity baseline.
    logs.create_log_group(logGroupName=api_group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=api_group_name))
    logs.create_log_stream(logGroupName=api_group_name, logStreamName=api_stream_name)

    base_ts = int(time.time() * 1000)
    messages = ["cfn-fidelity-alpha", "cfn-fidelity-beta", "cfn-fidelity-gamma"]
    events = [{"timestamp": base_ts + i, "message": m} for i, m in enumerate(messages)]

    put_cfn = logs.put_log_events(
        logGroupName=cfn_group_name, logStreamName=cfn_stream_name, logEvents=events
    )
    put_api = logs.put_log_events(
        logGroupName=api_group_name, logStreamName=api_stream_name, logEvents=events
    )
    assert "rejectedLogEventsInfo" not in put_cfn, (
        f"CFN-deployed group rejected events: {put_cfn.get('rejectedLogEventsInfo')}"
    )
    assert "rejectedLogEventsInfo" not in put_api, (
        f"API-created twin rejected events: {put_api.get('rejectedLogEventsInfo')}"
    )

    cfn_messages = _poll_for_messages(logs, cfn_group_name, cfn_stream_name, expected=3)
    api_messages = _poll_for_messages(logs, api_group_name, api_stream_name, expected=3)

    assert cfn_messages == messages, f"CFN group returned {cfn_messages}, expected {messages}"
    assert api_messages == messages, f"API group returned {api_messages}, expected {messages}"
    assert cfn_messages == api_messages, "CFN-deployed group diverged from API-created twin"


def _wait_stack_terminal(cfn: Any, stack_name: str, timeout_s: float, interval_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        status = resp["Stacks"][0]["StackStatus"]
        if status in _TERMINAL_STACK_STATUSES:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state, last seen {status}")


def _delete_stack(cfn: Any, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _poll_for_messages(logs: Any, group_name: str, stream_name: str, expected: int, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    messages: list[str] = []
    while time.monotonic() < deadline:
        resp = logs.get_log_events(
            logGroupName=group_name, logStreamName=stream_name, startFromHead=True
        )
        messages = [e["message"] for e in resp["events"]]
        if len(messages) >= expected:
            return messages
        time.sleep(2)
    raise AssertionError(
        f"{group_name}/{stream_name} had only {len(messages)} of {expected} expected events "
        f"after {timeout_s}s: {messages!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
