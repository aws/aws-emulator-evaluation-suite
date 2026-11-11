"""log-sfn-apigw-agreement-redacted-log-keeps-transitions-and-errors-while-history-keeps-payload."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-sfn-apigw-agreement-redacted-log-keeps-transitions-and-errors-while-history-keeps-payload"
GROUP = "execution_logging"
SERVICES = ["stepfunctions"]

_PAYLOAD_KEYS = {"input", "output", "parameters", "inputDetails", "outputDetails"}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """includeExecutionData=false strips exactly the payload fields from every delivered event
    while keeping every transition, id and failure error/cause; history still has the payload,
    and an includeExecutionData=true twin delivers it verbatim."""
    role = _role(ctx)
    definition = _definition(ctx)
    red_group, red_arn = _log_group(ctx)
    full_group, full_arn = _log_group(ctx)
    sm_red = _state_machine(ctx, role, definition, _logging("ALL", red_arn, include=False))
    sm_full = _state_machine(ctx, role, definition, _logging("ALL", full_arn, include=True))
    _warm_up(ctx, sm_red, red_group, {"mode": "ok"}, _all_delivered)
    _warm_up(ctx, sm_full, full_group, {"mode": "ok"}, _all_delivered)

    marker = ctx.unique_name("sim2real-secret-")
    payloads = {
        "catch": {"mode": "catch", "marker": marker},
        "fail": {"mode": "fail", "marker": marker, "ename": "Sim2Real.Redact",
                 "ecause": "cause survives redaction"},
    }
    red = {k: _start(ctx, sm_red, p) for k, p in payloads.items()}
    full = {k: _start(ctx, sm_full, p) for k, p in payloads.items()}
    for arn in list(red.values()) + list(full.values()):
        _wait_terminal(ctx, arn)
    red_hist = {k: _history(ctx, a) for k, a in red.items()}
    full_hist = {k: _history(ctx, a) for k, a in full.items()}

    # History is NOT redacted: the marker is in the redacted arm's own history.
    for k, hist in red_hist.items():
        started = _details(hist[0])
        assert hist[0]["type"] == "ExecutionStarted" and marker in started.get("input", ""), (
            f"{k}: GetExecutionHistory must keep the input on a redacted-logging machine; "
            f"first event was {hist[0]!r}")

    red_events = _await(ctx, red_group, lambda evs: all(
        _complete(evs, red[k], red_hist[k]) for k in red), "redacted arm full histories")
    full_events = _await(ctx, full_group, lambda evs: all(
        _complete(evs, full[k], full_hist[k]) for k in full), "full arm full histories")

    for k in red:
        logged = _of(red_events, red[k])
        assert [(e["id"], e["type"]) for e in logged] == [
            (str(h["id"]), h["type"]) for h in red_hist[k]], (
            f"{k}: redacted log transitions {[(e['id'], e['type']) for e in logged]} != history")
        _assert_mirrors(logged, red_hist[k], red[k], compare_details=False, who=f"redacted-{k}")
        for ev in logged:
            leaked = set(ev.get("details", {})) & _PAYLOAD_KEYS
            assert not leaked, f"{k}: redacted {ev['type']} still carries {sorted(leaked)}: {ev!r}"
            want = {kk: v for kk, v in _details(
                next(h for h in red_hist[k] if str(h["id"]) == ev["id"])).items()
                if kk not in _PAYLOAD_KEYS}
            assert ev.get("details") == want, (
                f"{k}: redacted {ev['type']} details {ev.get('details')!r}, expected the "
                f"history details minus payload fields {want!r}")
        assert marker not in json.dumps(logged), f"{k}: marker {marker!r} leaked into the redacted log"

    failed = [e for e in _of(red_events, red["fail"]) if e["type"] == "ExecutionFailed"]
    assert len(failed) == 1 and failed[0]["details"] == {
        "error": "Sim2Real.Redact", "cause": "cause survives redaction"}, (
        f"redacted ExecutionFailed must keep error/cause: {failed!r}")
    task_failed = [e for e in _of(red_events, red["catch"]) if e["type"] == "TaskFailed"]
    assert len(task_failed) == 1 and task_failed[0]["details"].get("error"), (
        f"redacted TaskFailed must keep its error: {task_failed!r}")

    # Positive twin: payload present and verbatim.
    for k in full:
        logged = _of(full_events, full[k])
        _assert_mirrors(logged, full_hist[k], full[k], compare_details=True, who=f"full-{k}")
        assert marker in json.dumps(logged), f"{k}: includeExecutionData=true lost the payload"



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
