"""deep-sfn-language-fail-long-error-untrimmed-in-sync-and-logs-trimmed-in-standard-history."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-fail-long-error-untrimmed-in-sync-and-logs-trimmed-in-standard-history"
GROUP = "fail_state"
SERVICES = ["stepfunctions"]

_LONG_ERROR = "\n" * 300
_STANDARD_TRIM = _LONG_ERROR[:253] + "..."
_LOG_ACTIONS = [
    "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
    "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
    "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    "logs:PutLogEvents", "logs:CreateLogStream", "logs:DescribeLogStreams",
]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Fail state's 300-character ErrorPath value is preserved verbatim by StartSyncExecution
    and the EXPRESS workflow's delivered CloudWatch Logs event, but a STANDARD workflow's
    DescribeExecution and GetExecutionHistory both trim it to 253 characters plus '...'.
    """
    role_arn = _role(ctx)
    definition = json.dumps({"StartAt": "F", "States": {"F": {
        "Type": "Fail", "ErrorPath": "$.e", "Cause": "static-cause"}}})
    std_arn = _state_machine(ctx, role_arn, definition, "STANDARD", logging=None)
    group, group_arn = _log_group(ctx)
    exp_arn = _state_machine(ctx, role_arn, definition, "EXPRESS", logging={
        "level": "ALL", "includeExecutionData": True,
        "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": group_arn}}],
    })
    _warm_up(ctx, exp_arn, group)

    short = "short-error"
    short_desc, _ = _run_standard(ctx, std_arn, short)
    assert short_desc.get("error") == short, (
        f"control: a short ErrorPath value must survive DescribeExecution untouched, "
        f"got {short_desc.get('error')!r}"
    )

    long_desc, long_exec_arn = _run_standard(ctx, std_arn, _LONG_ERROR)
    assert long_desc["status"] == "FAILED", f"expected FAILED, got {long_desc['status']!r}"
    got = long_desc.get("error")
    assert got == _STANDARD_TRIM, (
        f"STANDARD's DescribeExecution must trim a 300-char ErrorPath value to its first 253 "
        f"characters plus '...' (256 total), got {got!r}"
    )
    history = _history(ctx, long_exec_arn)
    hist_errors = [e["executionFailedEventDetails"]["error"] for e in history
                   if e["type"] == "ExecutionFailed"]
    assert hist_errors == [_STANDARD_TRIM], (
        f"GetExecutionHistory's ExecutionFailed event must carry the same trim, got {hist_errors!r}"
    )

    short_resp = ctx.client("stepfunctions").start_sync_execution(
        stateMachineArn=exp_arn, input=json.dumps({"e": short})
    )
    assert short_resp.get("error") == short, (
        f"control: StartSyncExecution must return a short error untouched, "
        f"got {short_resp.get('error')!r}"
    )

    long_resp = ctx.client("stepfunctions").start_sync_execution(
        stateMachineArn=exp_arn, input=json.dumps({"e": _LONG_ERROR})
    )
    assert long_resp["status"] == "FAILED", f"expected FAILED, got {long_resp['status']!r}"
    assert long_resp.get("error") == _LONG_ERROR, (
        f"StartSyncExecution must return the full 300-character error untrimmed, "
        f"got {len(long_resp.get('error') or '')} character(s)"
    )
    logged = _await_logged_error(ctx, group, long_resp["executionArn"])
    assert logged == _LONG_ERROR, (
        f"the EXPRESS execution's delivered CloudWatch Logs ExecutionFailed event must carry the "
        f"full 300-character error untrimmed, got {len(logged)} character(s)"
    )


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _role(ctx) -> str:
    """An execution role this check owns, with the log-delivery actions EXPRESS logging needs."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnlang-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST,
        Description="sim2real-behav sfn long-error-trim check role",
        Tags=[{"Key": "sim2real", "Value": "sfn-language"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="logs",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": _LOG_ACTIONS, "Resource": "*"}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="logs"))
    return arn


def _log_group(ctx) -> tuple[str, str]:
    """A fresh vended-logs group; returns (name, the ':*'-qualified ARN sfn requires)."""
    logs = ctx.client("logs")
    account = ctx.account
    name = ctx.unique_name("/aws/vendedlogs/states/sim2real-behav-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": "sfn-language"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name, f"arn:aws:logs:{ctx.region}:{account}:log-group:{name}:*"


def _state_machine(ctx, role_arn, definition, type_, logging):
    """Create a machine, absorbing IAM trust/log-delivery propagation with a bounded retry."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnlang-sm-")
    kwargs = dict(name=name, definition=definition, roleArn=role_arn, type=type_,
                  tags=[{"key": "sim2real", "value": "sfn-language"}])
    if logging is not None:
        kwargs["loggingConfiguration"] = logging
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(**kwargs)["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine kept refusing the freshly created role: {last!r}")


def _stop_if_running(sfn, exec_arn):
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn, error="sim2real.cleanup")


def _run_standard(ctx, sm_arn, err_value, *, timeout_s=150.0):
    """Start one STANDARD execution and poll DescribeExecution until it is terminal."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-x-"),
        input=json.dumps({"e": err_value}),
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] in _TERMINAL:
            return desc, exec_arn
        time.sleep(2)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {desc!r}")


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events = []
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        events.extend(page["events"])
    return events


def _read_log_group(ctx, group):
    """Every delivered, JSON-parsed event in ``group``. [] while no stream exists yet."""
    logs = ctx.client("logs")
    out, kwargs = [], {"logGroupName": group, "limit": 10000}
    while True:
        try:
            resp = logs.filter_log_events(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return out
            raise
        for event in resp["events"]:
            try:
                out.append(json.loads(event["message"]))
            except ValueError:
                continue
        if not resp.get("nextToken"):
            return out
        kwargs["nextToken"] = resp["nextToken"]


def _warm_up(ctx, sm_arn, group, *, budget_s=180.0, poll_s=4.0):
    """Run executions until one is fully delivered to ``group``: the first deliveries after
    logging is enabled on a fresh state machine can be lost for good."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        resp = sfn.start_sync_execution(stateMachineArn=sm_arn, input=json.dumps({"e": "warm"}))
        exec_arn = resp["executionArn"]
        until = time.monotonic() + 12.0
        while time.monotonic() < until:
            events = _read_log_group(ctx, group)
            if any(e.get("execution_arn") == exec_arn and e.get("type") == "ExecutionFailed"
                   for e in events):
                return
            time.sleep(poll_s)
    raise AssertionError(f"log delivery to {group} never produced one complete warm-up execution")


def _await_logged_error(ctx, group, exec_arn, *, budget_s=120.0, poll_s=3.0):
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        for event in _read_log_group(ctx, group):
            if event.get("execution_arn") == exec_arn and event.get("type") == "ExecutionFailed":
                return event["details"]["error"]
        time.sleep(poll_s)
    raise AssertionError(f"{group}: no ExecutionFailed event for {exec_arn} within {budget_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
