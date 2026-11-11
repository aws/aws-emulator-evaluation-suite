"""redrive-of-succeeded-execution-rejected-no-executionredriven-logged."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-of-succeeded-execution-rejected-no-executionredriven-logged"
GROUP = "execution_logging"
SERVICES = ["logs", "stepfunctions"]

_LOG_BUDGET_S = 180.0
_POLL_S = 2.0

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

# Documented at cw-logs.html: these log-delivery actions take no resource scope.
_LOG_ACTIONS = [
    "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
    "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
    "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    "logs:CreateLogStream", "logs:PutLogEvents",
]

_DEFINITION = json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}})


@tags("axis:rejection", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RedriveExecution on a SUCCEEDED execution is rejected with ExecutionNotRedrivable, and
    no ExecutionRedriven event is ever delivered to its level-ALL log group."""
    sfn = ctx.client("stepfunctions")
    role_arn = _role(ctx)
    group, group_arn = _log_group(ctx)
    sm_arn = _state_machine(ctx, role_arn, group_arn)

    _warm_up(ctx, sm_arn, group)

    marker = ctx.unique_name("m")[-16:]
    exec_arn = _start(ctx, sm_arn, marker)
    _wait_terminal(ctx, exec_arn)
    latency_s, _events = _latency_until_logged(ctx, group, exec_arn, "ExecutionSucceeded")

    expected = (
        "ExecutionNotRedrivable",
        f"Execution {exec_arn} invalid for redrive as: Execution is SUCCEEDED and cannot be redriven",
    )
    refusal = _client_error(lambda: sfn.redrive_execution(executionArn=exec_arn))
    assert refusal == expected, (
        f"redriving a SUCCEEDED execution must fail with {expected!r}; got {refusal!r}"
    )

    window = max(10.0, 3.0 * latency_s)
    deadline = time.monotonic() + window
    while time.monotonic() < deadline:
        time.sleep(_POLL_S)
    events = [e for e in _read_group(ctx, group) if e.get("execution_arn") == exec_arn]
    types = {e["type"] for e in events}
    assert "ExecutionRedriven" not in types, (
        f"the refused RedriveExecution must have no effect, yet ExecutionRedriven was logged: "
        f"{[(e.get('id'), e.get('type')) for e in events]}"
    )

    described = sfn.describe_execution(executionArn=exec_arn)
    assert (described["status"], described["redriveCount"]) == ("SUCCEEDED", 0), (
        f"DescribeExecution must still show SUCCEEDED, redriveCount 0; got "
        f"{(described['status'], described.get('redriveCount'))!r}"
    )


def _role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnredlogneg-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real: sfn redrive-rejection log agreement",
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
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
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("/aws/vendedlogs/states/sim2real-behav-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK[:250]})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name, f"arn:aws:logs:{ctx.region}:{account}:log-group:{name}:*"


def _state_machine(ctx, role_arn: str, group_arn: str) -> str:
    """CreateStateMachine, retrying only the AccessDeniedException raised while the role's
    trust and log-delivery grant propagate (IAM exposes no condition to poll)."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnredlogneg-")[:80]
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_DEFINITION, roleArn=role_arn,
                loggingConfiguration={
                    "level": "ALL", "includeExecutionData": True,
                    "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": group_arn}}],
                },
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied after 120s: {last}")


def _start(ctx, sm_arn: str, marker: str) -> str:
    sfn = ctx.client("stepfunctions")
    arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps({"marker": marker}))["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, arn))
    return arn


def _stop_if_running(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float = 60.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} still RUNNING after {timeout_s}s: {last!r}")


def _client_error(fn) -> tuple[str, str]:
    """(error code, message) of a call expected to fail; RAISES if the call succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but succeeded: {resp!r}")


def _read_group(ctx, group: str) -> list[dict]:
    """Every delivered event in the group, or [] while no stream exists yet."""
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


_VALIDATION_STREAM = "log_stream_created_by_aws_to_validate_log_delivery_subscriptions"


def _latency_until_logged(ctx, group: str, exec_arn: str, event_type: str,
                          *, budget_s: float = _LOG_BUDGET_S) -> tuple[float, list[dict]]:
    """Poll until ``event_type`` for ``exec_arn`` is delivered; returns (latency_s, events)."""
    start = time.monotonic()
    while time.monotonic() - start < budget_s:
        events = [e for e in _read_group(ctx, group) if e.get("execution_arn") == exec_arn]
        if any(e.get("type") == event_type for e in events):
            return time.monotonic() - start, events
        time.sleep(_POLL_S)
    raise AssertionError(f"{event_type} for {exec_arn} never delivered to {group} within {budget_s}s")


def _warm_up(ctx, sm_arn: str, group: str) -> None:
    """Run executions until one's ExecutionSucceeded is fully delivered, since an execution
    started in the first seconds of a fresh log-delivery wiring can lose events for good."""
    deadline = time.monotonic() + _LOG_BUDGET_S
    while time.monotonic() < deadline:
        marker = ctx.unique_name("warm")[-16:]
        exec_arn = _start(ctx, sm_arn, marker)
        d = _wait_terminal(ctx, exec_arn)
        assert d["status"] == "SUCCEEDED", f"warm-up execution ended {d['status']!r}"
        settle = time.monotonic() + 12.0
        while time.monotonic() < settle:
            events = [e for e in _read_group(ctx, group) if e.get("execution_arn") == exec_arn]
            if any(e.get("type") == "ExecutionSucceeded" for e in events):
                return
            time.sleep(_POLL_S)
    raise AssertionError(f"log group {group} never received a warm-up ExecutionSucceeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
