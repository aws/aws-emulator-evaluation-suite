"""xsvc-sfn-3-express-execution-history-api-rejected-while-logs-carry-it."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-3-express-execution-history-api-rejected-while-logs-carry-it"
GROUP = "express_execution_logging"
SERVICES = ["logs", "stepfunctions"]


@tags("axis:rejection", "dp:api", "plane:data", "cap:c3", "concern:e2e")
def run(ctx) -> None:
    """An async EXPRESS execution's history is refused by DescribeExecution and GetExecutionHistory
    (InvalidArn on the ARN StartExecution minted), while CloudWatch Logs holds that same execution's
    complete history, because the logs are where EXPRESS history lives.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = _role(ctx)
    group, group_arn = _log_group(ctx, account)
    sm_arn = _state_machine(ctx, role_arn, _logging("ALL", True, group_arn))
    _warm_up(ctx, sm_arn, group, {"mode": "ok", "marker": "warm"}, _complete)

    sfn = ctx.client("stepfunctions")
    marker = ctx.unique_name("sim2real-mark-")
    payload = json.dumps({"mode": "ok", "marker": marker})
    arn = sfn.start_execution(stateMachineArn=sm_arn, input=payload)["executionArn"]
    assert ":express:" in arn, f"expected an express execution ARN, got {arn!r}"

    # Positive control first: the execution ran and its whole history reached the logs.
    logged = _of(_await(ctx, group, lambda evs: _complete(_of(evs, arn)),
                        "the async execution's complete history"), arn)
    assert json.loads(logged[0]["details"]["input"]) == json.loads(payload), (
        f"the logged ExecutionStarted must carry this execution's input; got {logged[0]!r}")
    assert logged[-1]["type"] == "ExecutionSucceeded", (
        f"the logged history must end ExecutionSucceeded; got {[e['type'] for e in logged]}")

    expected = ("InvalidArn", "Invalid Arn: 'Resource type not valid in this context: express'")
    got = _error(lambda: sfn.describe_execution(executionArn=arn))
    assert got == expected, (
        f"DescribeExecution on an EXPRESS execution ARN must be rejected with {expected!r}; got {got!r}")
    got = _error(lambda: sfn.get_execution_history(executionArn=arn))
    assert got == expected, (
        f"GetExecutionHistory on an EXPRESS execution ARN must be rejected with {expected!r}; got {got!r}")
    # The rejection removed nothing: the logs still hold the full history afterwards.
    after = _of(_read_group(ctx, group), arn)
    assert [e["id"] for e in after] == [e["id"] for e in logged], (
        f"the logged history changed after the rejected reads: {[e['id'] for e in after]}")


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; a SUCCESS raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("the call SUCCEEDED, but real AWS rejects it")


# ===== helpers =====

_LOG_BUDGET_S = 240.0
_POLL_S = 4.0
_VALIDATION_STREAM = "log_stream_created_by_aws_to_validate_log_delivery_subscriptions"

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})

# Documented at step-functions/latest/dg/cw-logs.html: these take no resource scope.
_LOG_ACTIONS = [
    "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
    "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
    "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    "logs:CreateLogStream", "logs:PutLogEvents",
]

# Choice on $.mode: "boom" -> a Fail state; anything else -> SDK Task
# (sts:GetCallerIdentity needs no IAM grant) -> Succeed.
_DEFINITION = json.dumps({
    "StartAt": "Route",
    "States": {
        "Route": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.mode", "StringEquals": "boom", "Next": "Boom"}],
            "Default": "Who",
        },
        "Who": {
            "Type": "Task",
            "Resource": "arn:aws:states:::aws-sdk:sts:getCallerIdentity",
            "Parameters": {},
            "ResultSelector": {"account.$": "$.Account"},
            "ResultPath": "$.who",
            "Next": "Done",
        },
        "Boom": {"Type": "Fail", "Error": "Sim2realBoom", "Cause": "deliberate Fail state"},
        "Done": {"Type": "Succeed"},
    },
})


def _role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-sfn3-log-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real-xsvc: sfn express logging",
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


def _log_group(ctx, account: str) -> tuple[str, str]:
    logs = ctx.client("logs")
    name = ctx.unique_name("/aws/vendedlogs/states/sim2real-xsvc-sfn3-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK[:250]})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name, f"arn:aws:logs:{ctx.region}:{account}:log-group:{name}:*"


def _logging(level: str, include: bool, group_arn: str) -> dict:
    return {"level": level, "includeExecutionData": include,
            "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": group_arn}}]}


def _state_machine(ctx, role_arn: str, logging: dict) -> str:
    """CreateStateMachine (EXPRESS), retrying only the AccessDeniedException raised while
    the new role's trust propagates — IAM exposes no condition to poll."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-xsvc-sfn3-log-")[:80]
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_DEFINITION, roleArn=role_arn, type="EXPRESS",
                loggingConfiguration=logging,
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied after 120s: {last}")


def _read_group(ctx, group: str) -> list[dict]:
    """Every delivered JSON event in the group; [] while no stream exists yet."""
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
            # Delivery plumbing AWS writes when a subscription is validated; not an event.
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


def _complete(logged: list[dict]) -> bool:
    """The execution's terminal event has landed AND every id before it has too — vended
    delivery does not preserve order, so the terminal event alone is not enough."""
    term = [int(e["id"]) for e in logged if e["type"] == "ExecutionSucceeded"]
    return bool(term) and {int(e["id"]) for e in logged} >= set(range(1, term[0] + 1))


def _await(ctx, group: str, done, what: str) -> list[dict]:
    deadline = time.monotonic() + _LOG_BUDGET_S
    events: list[dict] = []
    while time.monotonic() < deadline:
        events = _read_group(ctx, group)
        if done(events):
            return events
        time.sleep(_POLL_S)
    raise AssertionError(
        f"{what}: not delivered to {group} within {_LOG_BUDGET_S}s; the group held "
        f"{[(e.get('execution_arn', '')[-8:], e.get('id'), e.get('type')) for e in events]}")


def _warm_up(ctx, sm_arn: str, group: str, payload: dict, done) -> None:
    """On AWS, an execution started in the first seconds after
    the log delivery is created is never delivered, while executions started ~15-20s later
    are. So start warm-up executions until ONE is delivered completely — an observable
    condition, not a sleep — and assert only on executions started after it. `done` judges
    one execution's delivered events."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + _LOG_BUDGET_S
    started: list[str] = []
    while time.monotonic() < deadline:
        started.append(sfn.start_execution(
            stateMachineArn=sm_arn, input=json.dumps(payload)
        )["executionArn"])
        until = time.monotonic() + 12.0
        while time.monotonic() < until:
            events = _read_group(ctx, group)
            if any(done(_of(events, arn)) for arn in started):
                return
            time.sleep(_POLL_S)
    raise AssertionError(
        f"log delivery to {group} never delivered one complete warm-up execution within "
        f"{_LOG_BUDGET_S}s across {len(started)} async executions")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
