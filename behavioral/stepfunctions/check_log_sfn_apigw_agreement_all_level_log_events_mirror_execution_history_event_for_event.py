"""log-sfn-apigw-agreement-all-level-log-events-mirror-execution-history-event-for-event."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-sfn-apigw-agreement-all-level-log-events-mirror-execution-history-event-for-event"
GROUP = "execution_logging"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """At level ALL with includeExecutionData, the log events for each execution match its
    GetExecutionHistory event for event (ids, types, links, timestamps, details), attributed by
    execution_arn; an identical machine at level OFF delivers nothing, not even a stream."""
    role = _role(ctx)
    definition = _definition(ctx)
    all_group, all_arn = _log_group(ctx)
    off_group, off_arn = _log_group(ctx)
    sm_all = _state_machine(ctx, role, definition, _logging("ALL", all_arn))
    sm_off = _state_machine(ctx, role, definition, _logging("OFF", off_arn))

    _warm_up(ctx, sm_all, all_group, {"mode": "ok", "warm": True}, _all_delivered)

    off_exec = _start(ctx, sm_off, {"mode": "ok", "arm": "off"})
    marker = ctx.unique_name("sim2real-mark-")
    ok_exec = _start(ctx, sm_all, {"mode": "ok", "marker": marker})
    catch_exec = _start(ctx, sm_all, {"mode": "catch", "marker": marker})
    for arn, want in ((off_exec, "SUCCEEDED"), (ok_exec, "SUCCEEDED"), (catch_exec, "SUCCEEDED")):
        status = _wait_terminal(ctx, arn)["status"]
        assert status == want, f"execution {arn} ended {status!r}, expected {want!r}"

    ok_hist = _history(ctx, ok_exec)
    catch_hist = _history(ctx, catch_exec)
    ok_types = [h["type"] for h in ok_hist]
    for t in ("ExecutionStarted", "TaskStateEntered", "TaskScheduled", "TaskStarted",
              "TaskSucceeded", "TaskStateExited", "ExecutionSucceeded"):
        assert t in ok_types, f"the ok execution's history lacks {t}: {ok_types}"
    assert "TaskFailed" in [h["type"] for h in catch_hist], (
        f"the catch execution's history lacks TaskFailed: {[h['type'] for h in catch_hist]}")

    events = _await(
        ctx, all_group,
        lambda evs: _complete(evs, ok_exec, ok_hist) and _complete(evs, catch_exec, catch_hist),
        "the full history of both measured executions",
    )
    for arn, hist, who in ((ok_exec, ok_hist, "ok"), (catch_exec, catch_hist, "catch")):
        logged = _of(events, arn)
        assert [e["id"] for e in logged] == [str(h["id"]) for h in hist], (
            f"{who}: log ids {[e['id'] for e in logged]} != history ids "
            f"{[h['id'] for h in hist]}")
        assert [e["type"] for e in logged] == [h["type"] for h in hist], (
            f"{who}: log type sequence {[e['type'] for e in logged]} != history "
            f"{[h['type'] for h in hist]}")
        _assert_mirrors(logged, hist, arn, compare_details=True, who=who)

    started = _of(events, ok_exec)[0]
    assert json.loads(started["details"]["input"]) == {"mode": "ok", "marker": marker}, (
        f"ExecutionStarted input in the log is {started['details'].get('input')!r}")

    # Effect absent at the one broken link (level OFF): nothing, not even a stream.
    off_events = _read_group(ctx, off_group)
    assert off_events == [], (
        f"level OFF delivered {[(e.get('id'), e.get('type')) for e in off_events]}")
    streams = ctx.client("logs").describe_log_streams(logGroupName=off_group)["logStreams"]
    assert streams == [], f"level OFF created streams {[s['logStreamName'] for s in streams]}"



_LOG_BUDGET_S = 240.0
_POLL_S = 4.0

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


def _definition(ctx) -> str:
    """Pass -> SDK Task (sts:GetCallerIdentity) -> Choice on $.mode: fail -> Fail with input
    Error/Cause; catch -> a caught, ungranted sfn:DescribeActivity Task (still SUCCEEDS);
    otherwise Succeed."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    missing = f"arn:aws:states:{ctx.region}:{account}:activity:sim2real-absent-{CHECK[:20]}"
    return json.dumps({
        "StartAt": "Prep",
        "States": {
            "Prep": {"Type": "Pass", "Next": "Who"},
            "Who": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:sts:getCallerIdentity",
                "Parameters": {},
                "ResultSelector": {"account.$": "$.Account"},
                "ResultPath": "$.who",
                "Next": "Route",
            },
            "Route": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.mode", "StringEquals": "fail", "Next": "Boom"},
                    {"Variable": "$.mode", "StringEquals": "catch", "Next": "Denied"},
                ],
                "Default": "Done",
            },
            "Denied": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:sfn:describeActivity",
                "Parameters": {"ActivityArn": missing},
                "Catch": [{"ErrorEquals": ["States.ALL"], "ResultPath": "$.caught", "Next": "Done"}],
                "Next": "Done",
            },
            "Boom": {"Type": "Fail", "ErrorPath": "$.ename", "CausePath": "$.ecause"},
            "Done": {"Type": "Succeed"},
        },
    })


def _role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnlog-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real: sfn execution-log agreement",
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
    """A fresh vended-logs group; returns (name, the ':*'-qualified ARN sfn requires)."""
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("/aws/vendedlogs/states/sim2real-behav-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK[:250]})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    return name, f"arn:aws:logs:{ctx.region}:{account}:log-group:{name}:*"


def _logging(level: str, group_arn: str, include: bool = True) -> dict:
    return {"level": level, "includeExecutionData": include,
            "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": group_arn}}]}


def _state_machine(ctx, role_arn: str, definition: str, logging: dict) -> str:
    """CreateStateMachine, retrying only the AccessDeniedException raised while the new
    role's trust and log-delivery grant propagate (IAM exposes no condition to poll)."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnlog-")[:80]
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn,
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


def _history(ctx, arn: str) -> list[dict]:
    sfn = ctx.client("stepfunctions")
    out, kwargs = [], {"executionArn": arn, "maxResults": 1000}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        out.extend(resp["events"])
        if not resp.get("nextToken"):
            return out
        kwargs["nextToken"] = resp["nextToken"]


def _read_group(ctx, group: str) -> list[dict]:
    """Every delivered event in the group, parsed. [] while no stream exists yet."""
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
            # Re-enabling logging by UpdateStateMachine makes CloudWatch Logs
            # write a non-JSON probe message into this AWS-named stream. It is delivery
            # plumbing, not an execution event; any OTHER non-JSON message still fails.
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


def _of(events: list[dict], exec_arn: str) -> list[dict]:
    return sorted((e for e in events if e.get("execution_arn") == exec_arn),
                  key=lambda e: int(e["id"]))


def _complete(events: list[dict], exec_arn: str, history: list[dict]) -> bool:
    return {e["id"] for e in _of(events, exec_arn)} >= {str(h["id"]) for h in history}


def _await(ctx, group: str, done, what: str) -> list[dict]:
    """Poll the group until done(events) holds. Asserts content, never latency."""
    deadline = time.monotonic() + _LOG_BUDGET_S
    events: list[dict] = []
    while time.monotonic() < deadline:
        events = _read_group(ctx, group)
        if done(events):
            return events
        time.sleep(_POLL_S)
    raise AssertionError(
        f"{what}: not delivered to {group} within {_LOG_BUDGET_S}s; the group held "
        f"{[(e.get('execution_arn', '')[-8:], e.get('id'), e.get('type')) for e in events]}"
    )


def _warm_up(ctx, sm_arn: str, group: str, payload: dict, done) -> str:
    """Start executions until one is delivered completely, since executions started in the
    first seconds after log delivery is created can lose events for good; only executions
    started after it are asserted on."""
    deadline = time.monotonic() + _LOG_BUDGET_S
    pending: list[tuple[str, list[dict]]] = []
    while time.monotonic() < deadline:
        arn = _start(ctx, sm_arn, payload)
        _wait_terminal(ctx, arn)
        pending.append((arn, _history(ctx, arn)))
        until = time.monotonic() + 12.0
        while time.monotonic() < until:
            events = _read_group(ctx, group)
            for exec_arn, hist in pending:
                if done(_of(events, exec_arn), hist):
                    return exec_arn
            time.sleep(_POLL_S)
    raise AssertionError(
        f"log delivery to {group} never produced one complete warm-up execution in "
        f"{_LOG_BUDGET_S}s across {len(pending)} executions"
    )


def _all_delivered(evs: list[dict], hist: list[dict]) -> bool:
    return {e["id"] for e in evs} >= {str(h["id"]) for h in hist}


def _details(h: dict) -> dict:
    """The one '<x>EventDetails' member of a history event, or {} if it has none."""
    keys = [k for k in h if k.endswith("EventDetails")]
    assert len(keys) <= 1, f"history event {h['id']} has several detail members: {keys}"
    return h[keys[0]] if keys else {}


def _ms(ts) -> str:
    return str(round(ts.timestamp() * 1000))


def _assert_mirrors(logged: list[dict], history: list[dict], exec_arn: str,
                    *, compare_details: bool, who: str) -> None:
    """Field-by-field: the delivered log events for one execution ARE its history."""
    by_id = {str(h["id"]): h for h in history}
    ids = [e["id"] for e in logged]
    assert len(ids) == len(set(ids)), f"{who}: duplicate log event ids {sorted(ids, key=int)}"
    for ev in logged:
        h = by_id.get(ev["id"])
        assert h is not None, (
            f"{who}: log event id {ev['id']} ({ev.get('type')}) has no history event")
        got = {
            "type": ev.get("type"),
            "previous_event_id": ev.get("previous_event_id"),
            "event_timestamp": ev.get("event_timestamp"),
            "execution_arn": ev.get("execution_arn"),
            "redrive_count": ev.get("redrive_count"),
        }
        want = {
            "type": h["type"],
            "previous_event_id": str(h["previousEventId"]),
            "event_timestamp": _ms(h["timestamp"]),
            "execution_arn": exec_arn,
            "redrive_count": "0",
        }
        assert got == want, f"{who}: log event {ev['id']} disagrees with history: {got!r} != {want!r}"
        if compare_details:
            assert ev.get("details") == _details(h), (
                f"{who}: {h['type']} (id {ev['id']}) details disagree - log "
                f"{ev.get('details')!r} vs history {_details(h)!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
