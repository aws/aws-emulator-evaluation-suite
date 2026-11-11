"""log-sfn-sync-child-failure-cause-redacts-input-but-keeps-failed-status."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-sfn-sync-child-failure-cause-redacts-input-but-keeps-failed-status"
GROUP = "execution_logging"
SERVICES = ["stepfunctions"]

_CHILD_ERROR = "Sim2Real.ChildBoom"
_CHILD_CAUSE = "child intentionally failed"
_SYNC_RESOURCE = "startExecution.sync:2"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """includeExecutionData=false strips Input/InputDetails from the auto-generated cause of a
    failed .sync:2 child on TaskFailed and ExecutionFailed, while Status FAILED and the child's own
    Error/Cause survive; an includeExecutionData=true twin carries the child's input verbatim."""
    role = _role(ctx)
    child_arn = _child(ctx, role)
    red_group, red_arn = _log_group(ctx)
    full_group, full_arn = _log_group(ctx)
    sm_red = _parent(ctx, role, child_arn, _logging("ALL", red_arn, include=False))
    sm_full = _parent(ctx, role, child_arn, _logging("ALL", full_arn, include=True))
    _warm_up(ctx, sm_red, red_group)
    _warm_up(ctx, sm_full, full_group)

    marker_red = ctx.unique_name("sim2real-secret-red-")
    marker_full = ctx.unique_name("sim2real-secret-full-")
    red_arn_exec = _start(ctx, sm_red, {"mode": "fail", "marker": marker_red})
    full_arn_exec = _start(ctx, sm_full, {"mode": "fail", "marker": marker_full})
    red_d = _wait_terminal(ctx, red_arn_exec)
    full_d = _wait_terminal(ctx, full_arn_exec)
    assert red_d["status"] == "FAILED", f"redacted parent must FAIL: {red_d!r}"
    assert full_d["status"] == "FAILED", f"full parent must FAIL: {full_d!r}"

    red_events = _await_history(ctx, red_group, red_d, "ExecutionFailed")
    full_events = _await_history(ctx, full_group, full_d, "ExecutionFailed")

    for ev_type in ("TaskFailed", "ExecutionFailed"):
        logged = [e for e in red_events if e["type"] == ev_type]
        assert len(logged) == 1, f"redacted {ev_type}: expected exactly one, got {logged!r}"
        details = logged[0]["details"]
        assert details.get("error") == "States.TaskFailed", (
            f"redacted {ev_type}.error must be States.TaskFailed: {details!r}")
        cause = json.loads(details["cause"])
        assert "Input" not in cause and "InputDetails" not in cause, (
            f"redacted {ev_type}.cause must drop Input/InputDetails: {cause!r}")
        assert cause.get("Status") == "FAILED", (
            f"redacted {ev_type}.cause must keep the child's Status FAILED: {cause!r}")
        assert cause.get("Error") == _CHILD_ERROR and cause.get("Cause") == _CHILD_CAUSE, (
            f"redacted {ev_type}.cause must keep the child's own Error/Cause: {cause!r}")
        assert marker_red not in details["cause"], (
            f"redacted {ev_type}.cause leaked the marker: {details['cause']!r}")
    assert marker_red not in json.dumps(red_events), (
        f"marker {marker_red!r} leaked somewhere into the redacted log")

    for ev_type in ("TaskFailed", "ExecutionFailed"):
        logged = [e for e in full_events if e["type"] == ev_type]
        assert len(logged) == 1, f"full {ev_type}: expected exactly one, got {logged!r}"
        details = logged[0]["details"]
        cause = json.loads(details["cause"])
        assert cause.get("Status") == "FAILED", f"full {ev_type}.cause: {cause!r}"
        got_input = json.loads(cause["Input"])
        assert got_input == {"mode": "fail", "marker": marker_full}, (
            f"full {ev_type}.cause.Input must carry the child's own input verbatim: {got_input!r}")
        assert cause.get("InputDetails") == {"Included": True}, (
            f"full {ev_type}.cause.InputDetails must report Included=True: {cause!r}")


_LOG_BUDGET_S = 240.0
_DELIVERY_S = 300.0
_POLL_S = 4.0
_VALIDATION_STREAM = "log_stream_created_by_aws_to_validate_log_delivery_subscriptions"

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

# Documented at cw-logs.html: these log-delivery actions take no resource scope.
_LOG_ACTIONS = [
    "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
    "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
    "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    "logs:CreateLogStream", "logs:PutLogEvents",
]

# Documented at connect-stepfunctions.html: the .sync integration also needs an EventBridge
# managed rule to observe the child's completion.
_SYNC_ACTIONS = [
    "states:StartExecution", "states:DescribeExecution", "states:StopExecution",
    "events:PutTargets", "events:PutRule", "events:DescribeRule",
]

_CHILD_DEFINITION = json.dumps({
    "StartAt": "Route",
    "States": {
        "Route": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.mode", "StringEquals": "fail", "Next": "Boom"}],
            "Default": "Done",
        },
        "Boom": {"Type": "Fail", "Error": _CHILD_ERROR, "Cause": _CHILD_CAUSE},
        "Done": {"Type": "Succeed"},
    },
})


def _parent_definition(child_arn: str) -> str:
    return json.dumps({
        "StartAt": "StartChild",
        "States": {
            "StartChild": {
                "Type": "Task",
                "Resource": f"arn:aws:states:::states:{_SYNC_RESOURCE}",
                "Parameters": {
                    "StateMachineArn": child_arn,
                    "Input": {"mode.$": "$.mode", "marker.$": "$.marker"},
                },
                "End": True,
            },
        },
    })


def _role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnsync-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real: sfn sync-integration log redaction",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="allow",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": _LOG_ACTIONS + _SYNC_ACTIONS, "Resource": "*"}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="allow"))
    return arn


def _log_group(ctx) -> tuple[str, str]:
    """A fresh vended-logs group; returns (name, the ':*'-qualified ARN sfn requires)."""
    logs = ctx.client("logs")
    account = ctx.account
    name = ctx.unique_name("/aws/vendedlogs/states/sim2real-behav-sync-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK[:250]})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name, f"arn:aws:logs:{ctx.region}:{account}:log-group:{name}:*"


def _logging(level: str, group_arn: str, *, include: bool) -> dict:
    return {"level": level, "includeExecutionData": include,
            "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": group_arn}}]}


def _create_with_retry(ctx, **kwargs) -> str:
    """CreateStateMachine, retrying only the AccessDeniedException raised while the new role's
    trust and permissions propagate (IAM exposes no condition to poll)."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(**kwargs)["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied after 120s: {last}")


def _child(ctx, role_arn: str) -> str:
    name = ctx.unique_name("sim2real-behav-sfnsync-child-")[:80]
    return _create_with_retry(
        ctx, name=name, definition=_CHILD_DEFINITION, roleArn=role_arn, type="STANDARD",
        tags=[{"key": "sim2real", "value": CHECK[:250]}])


def _parent(ctx, role_arn: str, child_arn: str, logging: dict) -> str:
    name = ctx.unique_name("sim2real-behav-sfnsync-parent-")[:80]
    return _create_with_retry(
        ctx, name=name, definition=_parent_definition(child_arn), roleArn=role_arn,
        type="STANDARD", loggingConfiguration=logging,
        tags=[{"key": "sim2real", "value": CHECK[:250]}])


def _start(ctx, sm_arn: str, payload: dict) -> str:
    sfn = ctx.client("stepfunctions")
    arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(payload))["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, arn))
    return arn


def _stop_if_running(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


def _wait_terminal(ctx, arn: str) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {arn} still RUNNING after 120s: {last!r}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _read_group(ctx, group: str, start_ms: int | None = None) -> list[dict]:
    """Every delivered JSON event in the group, across all its streams, from start_ms on; []
    while no stream exists yet."""
    logs = ctx.client("logs")
    out, kwargs = [], {"logGroupName": group, "limit": 10000}
    if start_ms is not None:
        kwargs["startTime"] = start_ms
    while True:
        try:
            resp = logs.filter_log_events(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return out
            raise
        for event in resp["events"]:
            if event["logStreamName"] == _VALIDATION_STREAM:
                continue
            try:
                out.append(json.loads(event["message"]))
            except ValueError:
                raise AssertionError(
                    f"non-JSON message in {group}/{event['logStreamName']}: "
                    f"{event['message'][:300]!r}") from None
        if not resp.get("nextToken"):
            return out
        kwargs["nextToken"] = resp["nextToken"]


def _of(events: list[dict], exec_arn: str) -> list[dict]:
    return sorted((e for e in events if e.get("execution_arn") == exec_arn),
                  key=lambda e: int(e["id"]))


def _complete(events: list[dict], until_type: str) -> bool:
    """Whether every history event up to the until_type event has been delivered: delivery is
    per event and unordered, so the terminal record can arrive before an earlier TaskFailed."""
    term = [int(e["id"]) for e in events if e["type"] == until_type]
    return bool(term) and {int(e["id"]) for e in events} >= set(range(1, term[0] + 1))


def _await_history(ctx, group: str, desc: dict, until_type: str) -> list[dict]:
    """Poll the group, every stream from the execution's start on, until the execution's whole
    history through until_type is delivered. Asserts content, never latency."""
    exec_arn = desc["executionArn"]
    start_ms = int(desc["startDate"].timestamp() * 1000) - 60_000
    timeout_s = _budget_s(ctx, _DELIVERY_S)
    deadline = time.monotonic() + timeout_s
    events: list[dict] = []
    while True:
        events = _of(_read_group(ctx, group, start_ms), exec_arn)
        if _complete(events, until_type):
            return events
        if time.monotonic() >= deadline:
            break
        time.sleep(_POLL_S)
    held = [(e.get("id"), e.get("type")) for e in events]
    if _budget_spent(ctx):
        raise TimeoutError(
            f"{exec_arn}: history through {until_type} not yet delivered to {group} when the run "
            f"budget ended; held {held}; not graded")
    raise AssertionError(
        f"{exec_arn}: history through {until_type} not delivered to {group} within "
        f"{timeout_s:.0f}s; held {held}")


def _warm_up(ctx, sm_arn: str, group: str) -> None:
    """Start executions until one is delivered completely, since executions started in the
    first seconds after log delivery is created can lose events for good."""
    deadline = time.monotonic() + _LOG_BUDGET_S
    while time.monotonic() < deadline:
        arn = _start(ctx, sm_arn, {"mode": "ok", "marker": "warmup"})
        _wait_terminal(ctx, arn)
        until = time.monotonic() + 12.0
        while time.monotonic() < until:
            events = _of(_read_group(ctx, group), arn)
            if any(e["type"] == "ExecutionSucceeded" for e in events):
                return
            time.sleep(_POLL_S)
    raise AssertionError(
        f"log delivery to {group} never produced one complete warm-up execution in "
        f"{_LOG_BUDGET_S}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
