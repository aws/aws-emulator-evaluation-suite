"""xsvc-sfn-3-express-include-execution-data-false-logs-same-events-without-payload."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-sfn-3-express-include-execution-data-false-logs-same-events-without-payload"
GROUP = "express_execution_logging"
SERVICES = ["logs", "stepfunctions"]

# Every `details` member that carries execution data (input, output, task parameters)
# and the truncation flags that only accompany it.
_PAYLOAD_KEYS = {"input", "inputDetails", "output", "outputDetails", "parameters"}


@tags("axis:happy-path", "dp:api", "plane:data", "cap:c3", "concern:e2e")
def run(ctx) -> None:
    """includeExecutionData=false keeps every ALL-level event of an EXPRESS run but strips its
    input, output and task parameters, compared event-for-event against a twin machine with
    includeExecutionData=true that proves the payload would otherwise be there.
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = _role(ctx)
    arms = {}
    for key, include in (("full", True), ("redacted", False)):
        group, group_arn = _log_group(ctx, account)
        sm_arn = _state_machine(ctx, role_arn, _logging("ALL", include, group_arn))
        arms[key] = (sm_arn, group)
    for sm_arn, group in arms.values():
        _warm_up(ctx, sm_arn, group, {"mode": "ok", "marker": "warm"}, _complete)

    sfn = ctx.client("stepfunctions")
    marker = ctx.unique_name("sim2real-mark-")
    payload = json.dumps({"mode": "ok", "marker": marker})
    execs = {key: sfn.start_execution(stateMachineArn=sm, input=payload)["executionArn"]
             for key, (sm, _) in arms.items()}
    got = {key: _of(_await(ctx, arms[key][1], lambda evs, a=execs[key]: _complete(_of(evs, a)),
                           f"the {key} arm's complete event sequence"), execs[key])
           for key in arms}

    full, red = got["full"], got["redacted"]
    assert [(e["id"], e["type"]) for e in red] == [(e["id"], e["type"]) for e in full], (
        "includeExecutionData=false must not drop or add events — the redacted arm's "
        f"(id, type) sequence {[(e['id'], e['type']) for e in red]} differs from the full "
        f"arm's {[(e['id'], e['type']) for e in full]}")
    full_payload = [e["type"] for e in full if _PAYLOAD_KEYS & set(e["details"])]
    for want in ("ExecutionStarted", "TaskScheduled", "TaskSucceeded", "ExecutionSucceeded"):
        assert want in full_payload, (
            f"control: with includeExecutionData=true, {want} must carry execution data, or "
            f"the redaction below proves nothing; payload-bearing types were {full_payload}")
    assert marker in json.dumps(full), (
        f"control: the full arm must carry the input marker {marker!r} somewhere")
    leaked = [(e["type"], sorted(_PAYLOAD_KEYS & set(e["details"]))) for e in red
              if _PAYLOAD_KEYS & set(e["details"])]
    assert leaked == [], (
        f"includeExecutionData=false must strip execution data from every event; these "
        f"events still carry payload members: {leaked}")
    blob = json.dumps(red)
    assert marker not in blob, (
        f"the input marker {marker!r} leaked into the redacted log events: "
        f"{blob[max(0, blob.find(marker) - 150):blob.find(marker) + 40]}")
    names = [(e["type"], e["details"].get("name")) for e in red if "StateEntered" in e["type"]]
    assert ("TaskStateEntered", "Who") in names, (
        "redaction must keep the non-payload details (the state name) — the redacted "
        f"arm's state-entered events were {names}")
    assert all(e["execution_arn"] == execs["redacted"] for e in red), (
        "every redacted event must still be attributed to its execution")


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
    """Start executions until one is fully delivered; executions started in the first seconds
    after the log delivery is created are never delivered, while ones ~15-20s later are."""
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
