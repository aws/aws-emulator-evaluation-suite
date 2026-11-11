"""log-level-selects-which-history-events-reach-cloudwatch-logs."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-level-selects-which-history-events-reach-cloudwatch-logs"
GROUP = "observability"
SERVICES = ["stepfunctions"]

_LOG_DEADLINE_S = 300.0
_LOG_INTERVAL_S = 2.0
_PROBE_EVERY_S = 15.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """loggingConfiguration.level decides WHICH execution-history event types are
    delivered to CloudWatch Logs, and includeExecutionData=false redacts the payload.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/cw-logs.html
    """
    _role_name, role_arn = _create_sfn_role(ctx)

    # Four state machines from ONE definition, differing only in loggingConfiguration,
    # each with its own log group, all created in the same instant. That makes the
    # ERROR/FATAL arms twin controls for the ALL arm rather than untested absences.
    arms = {
        "all": _arm(ctx, role_arn, level="ALL", include_data=True),
        "redacted": _arm(ctx, role_arn, level="ALL", include_data=False),
        "error": _arm(ctx, role_arn, level="ERROR", include_data=True),
        "fatal": _arm(ctx, role_arn, level="FATAL", include_data=True),
    }

    marker = ctx.unique_name("sim2real-marker-")

    # Log delivery for a just-created state machine is wired asynchronously: an execution
    # started in its first seconds can lose its earliest events (ExecutionStarted) for good.
    probes = _await_delivery_live(ctx, [arms["all"], arms["redacted"]])

    # --- Leg 1: a SUCCESSFUL execution on every arm ------------------------------------
    ok_execs = {}
    for key, arm in arms.items():
        ok_execs[key] = _start(ctx, arm["sm_arn"], {"mode": "ok", "marker": marker})
    for key, exec_arn in ok_execs.items():
        desc = _wait_terminal(ctx, exec_arn, timeout_s=120.0)
        assert desc["status"] == "SUCCEEDED", (
            f"the {key} arm's mode=ok execution must SUCCEED so the log-level table is "
            f"read against a known history; got {desc['status']} "
            f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
        )

    # ALL: both execution-level events land, and the payload is present.
    # CloudWatch Logs vended delivery does not preserve execution-history order:
    # ExecutionStarted (chronologically first) can arrive AFTER ExecutionSucceeded, so
    # waiting on the terminal event alone is not a safe "everything has landed" signal.
    # Wait for the whole expected set instead of one representative member.
    all_events = _await_log_types(
        ctx, arms["all"]["log_group"], {"ExecutionStarted", "ExecutionSucceeded"}, ignore=probes
    )
    all_types = {e["type"] for e in all_events}
    assert "ExecutionStarted" in all_types, (
        "level=ALL must deliver ExecutionStarted to its log group; the delivered event "
        f"types were {sorted(all_types)}"
    )
    started = _one(all_events, "ExecutionStarted", "level=ALL")
    assert started.get("execution_arn") == ok_execs["all"], (
        "the delivered ExecutionStarted event must name the execution that produced it; "
        f"expected execution_arn={ok_execs['all']}, got "
        f"{started.get('execution_arn')!r}"
    )
    assert marker in json.dumps(started), (
        "level=ALL with includeExecutionData=true must include the execution input, so "
        f"the marker {marker!r} must appear in the ExecutionStarted event; the event was "
        f"{json.dumps(started)[:300]}"
    )

    # REDACTED: identical wiring and level, so delivery is proven on the same path —
    # then the payload must be absent from the WHOLE group, not merely from one event.
    redacted_events = _await_log_types(
        ctx, arms["redacted"]["log_group"], {"ExecutionStarted", "ExecutionSucceeded"},
        ignore=probes,
    )
    redacted_types = {e["type"] for e in redacted_events}
    assert "ExecutionStarted" in redacted_types, (
        "the includeExecutionData=false arm is still level=ALL, so it must deliver "
        "ExecutionStarted — without this positive control the redaction assertion below "
        f"would pass against a target that logs nothing. Types were {sorted(redacted_types)}"
    )
    blob = json.dumps(redacted_events)
    assert marker not in blob, (
        f"includeExecutionData=false must redact the execution payload, so the marker "
        f"{marker!r} must appear in NO delivered event; it appeared in "
        f"{blob[max(0, blob.find(marker) - 120):blob.find(marker) + 60]}"
    )

    # ERROR and FATAL: a successful execution has no ERROR-tier event, so both groups
    # must stay empty even though logging is ON, read once the twin ALL arms delivered the
    # same-instant execution; Leg 2 re-proves the absence after these groups receive events.
    for key in ("error", "fatal"):
        events = _read_log_events(ctx, arms[key]["log_group"])
        assert events == [], (
            f"level={key.upper()} must deliver NOTHING for an execution that only "
            "produced ALL-tier events (ExecutionStarted/ExecutionSucceeded are "
            f"'Not logged' at {key.upper()}); got {[e.get('type') for e in events]}"
        )
    for key in ("error", "fatal"):
        streams = ctx.client("logs").describe_log_streams(
            logGroupName=arms[key]["log_group"]
        )["logStreams"]
        assert streams == [], (
            f"level={key.upper()} must not even create a log stream for a purely "
            f"successful execution; got {[s['logStreamName'] for s in streams]}"
        )

    # --- Leg 2 (repair): a FAILING execution re-proves delivery on those same arms -----
    fail_execs = {}
    for key in ("all", "error", "fatal"):
        fail_execs[key] = _start(
            ctx, arms[key]["sm_arn"], {"mode": "boom", "marker": marker}
        )
    for key, exec_arn in fail_execs.items():
        desc = _wait_terminal(ctx, exec_arn, timeout_s=120.0)
        assert desc["status"] == "FAILED", (
            f"the {key} arm's mode=boom execution must FAIL so the ERROR/FATAL tiers "
            f"have something to log; got {desc['status']}"
        )

    # The ALL arm saw the failure too, which proves the same failing history really does
    # contain the events the ERROR/FATAL arms selected from.
    all_fail_events = _await_log_types(
        ctx,
        arms["all"]["log_group"],
        {"ExecutionStarted", "FailStateEntered", "ExecutionFailed"},
        exec_arn=fail_execs["all"],
    )
    all_fail_types = {e["type"] for e in all_fail_events}
    for want in ("ExecutionStarted", "FailStateEntered", "ExecutionFailed"):
        assert want in all_fail_types, (
            f"level=ALL must deliver {want} for the failing execution, otherwise the "
            f"ERROR/FATAL absences below prove nothing; types were {sorted(all_fail_types)}"
        )

    error_events = _await_log_types(
        ctx, arms["error"]["log_group"], {"FailStateEntered", "ExecutionFailed"},
        exec_arn=fail_execs["error"],
    )
    error_types = {e["type"] for e in error_events}
    assert "FailStateEntered" in error_types, (
        "level=ERROR must deliver FailStateEntered ('Logged' at ERROR in the log-level "
        f"table); the delivered types were {sorted(error_types)}"
    )
    # Read after the ALL twin delivered this history's ExecutionStarted and this group its
    # later events, so a suppressed ExecutionStarted is told apart from one still in flight.
    error_hold_events = _absent(
        ctx, arms["error"]["log_group"], {"ExecutionStarted"}, ok_execs["error"]
    )
    assert "ExecutionStarted" not in {e["type"] for e in error_hold_events}, (
        "level=ERROR must still suppress ExecutionStarted even on a failing execution "
        "('Not logged' at ERROR) — a target that switches to all-or-nothing logging as "
        "soon as an error occurs fails here. Delivered types were "
        f"{sorted({e['type'] for e in error_hold_events})}"
    )

    _await_log_types(
        ctx, arms["fatal"]["log_group"], {"ExecutionFailed"}, exec_arn=fail_execs["fatal"]
    )
    # Same contrast as the ERROR arm: the ALL and ERROR twins delivered FailStateEntered first.
    fatal_hold_events = _absent(
        ctx, arms["fatal"]["log_group"], {"FailStateEntered", "ExecutionStarted"},
        ok_execs["fatal"],
    )
    fatal_hold_types = {e["type"] for e in fatal_hold_events}
    assert "FailStateEntered" not in fatal_hold_types, (
        "level=FATAL must deliver ExecutionFailed but NOT FailStateEntered ('Not logged' "
        "at FATAL) — this is the only observable difference between ERROR and FATAL for "
        f"this workflow. Delivered types were {sorted(fatal_hold_types)}"
    )
    assert "ExecutionStarted" not in fatal_hold_types, (
        "level=FATAL must suppress ExecutionStarted even on a failing execution; "
        f"delivered types were {sorted(fatal_hold_types)}"
    )



_DEFINITION = json.dumps(
    {
        "Comment": "one success path and one Fail path, selected by $.mode",
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.mode", "StringEquals": "boom", "Next": "Boom"}
                ],
                "Default": "Ok",
            },
            "Ok": {"Type": "Pass", "Result": {"ok": True}, "End": True},
            "Boom": {
                "Type": "Fail",
                "Error": "LogLevelBoom",
                "Cause": "deliberate failure to produce ERROR/FATAL tier events",
            },
        },
    }
)

_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

# Per the Step Functions logging docs these actions do not accept a resource scope.
_LOG_ACTIONS = [
    "logs:CreateLogDelivery",
    "logs:GetLogDelivery",
    "logs:UpdateLogDelivery",
    "logs:DeleteLogDelivery",
    "logs:ListLogDeliveries",
    "logs:PutResourcePolicy",
    "logs:DescribeResourcePolicies",
    "logs:DescribeLogGroups",
    "logs:CreateLogStream",
    "logs:PutLogEvents",
]


def _create_sfn_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnlog-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Path="/sim2real/",
        Description="SimParity draft: sfn log level delivery",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": _LOG_ACTIONS, "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return name, arn


def _arm(ctx, role_arn: str, *, level: str, include_data: bool) -> dict:
    """One log group plus one state machine wired to it at the given level."""
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    group = ctx.unique_name("/aws/vendedlogs/states/sim2real-behav-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": "1", "check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    group_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}:*"
    sm_arn = _create_state_machine(
        ctx,
        role_arn,
        logging={
            "level": level,
            "includeExecutionData": include_data,
            "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": group_arn}}],
        },
    )
    return {"log_group": group, "sm_arn": sm_arn, "level": level}


def _create_state_machine(ctx, role_arn: str, *, logging: dict) -> str:
    """CreateStateMachine, bounded-retrying only the AccessDeniedException raised while
    the freshly created role's PassRole grant propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnlog-")
    deadline = _deadline(ctx, 120.0)
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=_DEFINITION,
                roleArn=role_arn,
                loggingConfiguration=logging,
                tags=[
                    {"key": "sim2real", "value": "1"},
                    {"key": "sim2real-check", "value": CHECK},
                ],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
    raise AssertionError(
        "CreateStateMachine with a logging configuration was still AccessDenied 120s "
        f"after the role granting it was created. Last error: {last}"
    )


def _start(ctx, sm_arn: str, payload: dict) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps(payload)
    )["executionArn"]
    ctx.on_cleanup(lambda a=exec_arn: sfn.stop_execution(executionArn=a))
    return exec_arn


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = _deadline(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(
        f"execution {exec_arn} still RUNNING after {timeout_s}s; this definition is a "
        f"Choice plus a Pass or Fail and cannot legitimately take that long. Last: {last!r}"
    )


def _read_log_events(ctx, group: str) -> list[dict]:
    """Every JSON log event in the group, or [] while the group has no stream yet
    (ResourceNotFoundException means nothing was delivered)."""
    logs = ctx.client("logs")
    out: list[dict] = []
    kwargs = {"logGroupName": group, "limit": 1000}
    while True:
        try:
            resp = logs.filter_log_events(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return out
            raise
        for event in resp["events"]:
            out.append(json.loads(event["message"]))
        token = resp.get("nextToken")
        if not token:
            return out
        kwargs["nextToken"] = token


def _deadline(ctx, timeout_s: float) -> float:
    """A monotonic deadline ``timeout_s`` away, capped by the check's remaining run time."""
    left = ctx.time_left()
    return time.monotonic() + (timeout_s if left is None else min(timeout_s, left))


def _await_delivery_live(ctx, arms: list[dict]) -> set[str]:
    """Start mode=ok probe executions on the level=ALL arms until each group holds a probe's
    ExecutionStarted, which shows delivery is wired; returns every probe execution ARN."""
    probes: dict[str, set[str]] = {arm["log_group"]: set() for arm in arms}
    pending = {arm["log_group"]: arm for arm in arms}
    deadline = _deadline(ctx, _LOG_DEADLINE_S)
    next_probe_at = time.monotonic()
    while True:
        if time.monotonic() >= next_probe_at:
            for group, arm in pending.items():
                probes[group].add(_start(ctx, arm["sm_arn"], {"mode": "ok"}))
            next_probe_at = time.monotonic() + _PROBE_EVERY_S
        for group in list(pending):
            if any(
                e.get("type") == "ExecutionStarted" and e.get("execution_arn") in probes[group]
                for e in _read_log_events(ctx, group)
            ):
                del pending[group]
        if not pending:
            return set().union(*probes.values())
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"log groups {sorted(pending)} never received an ExecutionStarted event for any "
                f"of the probe executions started within {_LOG_DEADLINE_S}s"
            )
        time.sleep(_LOG_INTERVAL_S)


def _await_log_types(
    ctx, group: str, want_types: set[str], *, exec_arn: str | None = None, ignore=frozenset()
) -> list[dict]:
    """Bounded poll until EVERY type in want_types is delivered, since vended log delivery
    does not preserve history order (ExecutionStarted can land last). Returns the group's
    events, only exec_arn's when given, never those of the probe executions in ignore."""
    deadline = _deadline(ctx, _LOG_DEADLINE_S)
    last: list[dict] = []
    while True:
        last = [
            e for e in _read_log_events(ctx, group)
            if e.get("execution_arn") not in ignore
            and (exec_arn is None or e.get("execution_arn") == exec_arn)
        ]
        got = {e.get("type") for e in last}
        if want_types <= got:
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(_LOG_INTERVAL_S)
    raise AssertionError(
        f"log group {group} never received {sorted(want_types - {e.get('type') for e in last})} "
        f"within {_LOG_DEADLINE_S}s; the types it did receive were "
        f"{sorted({e.get('type') for e in last})}"
    )


def _absent(ctx, group: str, forbidden_types: set[str], earlier_exec_arn: str) -> list[dict]:
    """Every event in the group, asserting none of forbidden_types and nothing from the
    earlier successful execution was delivered."""
    events = _read_log_events(ctx, group)
    got = {e.get("type") for e in events}
    bad = got & forbidden_types
    assert not bad, (
        f"expected {sorted(forbidden_types)} to never be delivered to {group}; saw "
        f"{sorted(bad)} among delivered types {sorted(got)}"
    )
    early = [e.get("type") for e in events if e.get("execution_arn") == earlier_exec_arn]
    assert early == [], (
        f"{group} must deliver nothing for the earlier successful execution; got {early}"
    )
    return events


def _one(events: list[dict], want_type: str, who: str) -> dict:
    matching = [e for e in events if e.get("type") == want_type]
    assert len(matching) == 1, (
        f"{who} must deliver exactly one {want_type} event for one execution; got "
        f"{len(matching)}"
    )
    return matching[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
