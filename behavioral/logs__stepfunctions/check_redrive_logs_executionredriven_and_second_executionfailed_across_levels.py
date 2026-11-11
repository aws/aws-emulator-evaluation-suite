"""redrive-logs-executionredriven-and-second-executionfailed-across-levels."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-logs-executionredriven-and-second-executionfailed-across-levels"
GROUP = "execution_logging"
SERVICES = ["logs", "stepfunctions"]

_LOG_BUDGET_S = 240.0
_POLL_S = 2.0

# The ERROR/FATAL tier for the event types this check's Activity-backed Task definition can
# produce. ActivityFailed follows TaskFailed's ERROR-only tier; an ExecutionRedriven event at
# ERROR or FATAL is accepted but not required.
_ERROR_TIER = {"ActivityFailed", "ExecutionFailed"}
_FATAL_TIER = {"ExecutionFailed"}

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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Redriving a FAILED execution appends ExecutionRedriven and a second ExecutionFailed
    (redrive_count 1); CloudWatch Logs mirrors both at level ALL (with and without data),
    delivers the second ExecutionFailed at ERROR and FATAL too, and nothing at OFF."""
    sfn = ctx.client("stepfunctions")
    role_arn = _role(ctx)
    activity_arn = _activity(ctx)

    arms = {
        "all": _arm(ctx, role_arn, activity_arn, level="ALL", include_data=True),
        "all_nodata": _arm(ctx, role_arn, activity_arn, level="ALL", include_data=False),
        "error": _arm(ctx, role_arn, activity_arn, level="ERROR", include_data=True),
        "fatal": _arm(ctx, role_arn, activity_arn, level="FATAL", include_data=True),
        "off": _arm(ctx, role_arn, activity_arn, level="OFF", include_data=True),
    }

    # Warm up delivery on every level but OFF: an execution started in the first seconds
    # after a log group is wired can lose its events for good.
    for key in ("all", "all_nodata", "error", "fatal"):
        _warm_up(ctx, arms[key], activity_arn)

    results = {key: _redrive_cycle(ctx, arm, activity_arn) for key, arm in arms.items()}

    # --- ALL and ALL_NODATA: the delivered log mirrors the full post-redrive history ---
    for key in ("all", "all_nodata"):
        r = results[key]
        events = _await(
            ctx, arms[key]["log_group"], r["exec_arn"],
            lambda evs, hist=r["hist2"]: _ids(evs) >= _hist_ids(hist),
            f"{key}: the full post-redrive history",
        )
        assert _ids(events) == _hist_ids(r["hist2"]), (
            f"{key}: delivered ids {sorted(_ids(events), key=int)} must equal the post-redrive "
            f"history ids {sorted(_hist_ids(r['hist2']), key=int)}"
        )
        by_type = {e["type"]: e for e in events}
        assert "ExecutionRedriven" in by_type, (
            f"{key}: level=ALL must deliver ExecutionRedriven; got types {sorted(by_type)}"
        )
        redriven_hist = _one(r["hist2"], "ExecutionRedriven")
        assert redriven_hist["executionRedrivenEventDetails"]["redriveCount"] == 1, (
            f"{key}: the history's ExecutionRedriven must carry redriveCount 1; got "
            f"{redriven_hist['executionRedrivenEventDetails']!r}"
        )
        second_failed_hist = [h for h in r["hist2"] if h["type"] == "ExecutionFailed"][-1]
        failed_logs = [e for e in events if e["type"] == "ExecutionFailed"]
        assert len(failed_logs) == 2, (
            f"{key}: exactly two ExecutionFailed log events expected, got "
            f"{[e['id'] for e in failed_logs]}"
        )
        second_failed_log = sorted(failed_logs, key=lambda e: int(e["id"]))[-1]
        assert second_failed_log["id"] == str(second_failed_hist["id"]), (
            f"{key}: the second ExecutionFailed log id {second_failed_log['id']!r} must equal "
            f"the history's {second_failed_hist['id']!r}"
        )
        assert second_failed_log["redrive_count"] == "1", (
            f"{key}: the second ExecutionFailed log event must carry redrive_count '1'; got "
            f"{second_failed_log.get('redrive_count')!r}"
        )
        redriven_log = by_type["ExecutionRedriven"]
        assert redriven_log["redrive_count"] == "0", (
            f"{key}: the ExecutionRedriven log event itself must still read redrive_count '0' "
            f"(the increment is visible starting with the events it produces); got "
            f"{redriven_log.get('redrive_count')!r}"
        )
        first_failed_log = sorted(failed_logs, key=lambda e: int(e["id"]))[0]
        assert first_failed_log["redrive_count"] == "0", (
            f"{key}: the FIRST ExecutionFailed log event must still read redrive_count '0'; got "
            f"{first_failed_log.get('redrive_count')!r}"
        )

    # --- ERROR and FATAL: at minimum the documented tier, each delivered with redrive_count 1
    # on the second ExecutionFailed; the ALL twin proves the same history held those ids ---
    for key, tier in (("error", _ERROR_TIER), ("fatal", _FATAL_TIER)):
        r = results[key]
        hist2 = r["hist2"]
        want_ids = {str(h["id"]) for h in hist2 if h["type"] in tier}
        events = _await(
            ctx, arms[key]["log_group"], r["exec_arn"],
            lambda evs, want=want_ids: want <= _ids(evs),
            f"{key}: the documented {sorted(tier)} tier for the post-redrive history",
        )
        failed_logs = sorted((e for e in events if e["type"] == "ExecutionFailed"),
                              key=lambda e: int(e["id"]))
        assert len(failed_logs) == 2, (
            f"{key}: expected exactly two delivered ExecutionFailed events, got "
            f"{[e['id'] for e in failed_logs]}"
        )
        assert failed_logs[0]["redrive_count"] == "0" and failed_logs[1]["redrive_count"] == "1", (
            f"{key}: the two ExecutionFailed events must read redrive_count '0' then '1'; got "
            f"{[e.get('redrive_count') for e in failed_logs]!r}"
        )
        hist_second_failed = [h for h in hist2 if h["type"] == "ExecutionFailed"][-1]
        assert failed_logs[1]["id"] == str(hist_second_failed["id"]), (
            f"{key}: the second delivered ExecutionFailed id {failed_logs[1]['id']!r} must equal "
            f"the history's {hist_second_failed['id']!r}"
        )
        delivered_types = {e["type"] for e in events}
        assert delivered_types <= (tier | {"ExecutionRedriven"}), (
            f"{key}: level={key.upper()} must deliver only its documented tier plus possibly "
            f"ExecutionRedriven; got {sorted(delivered_types)}"
        )

    # --- OFF: nothing, not even a stream, despite the same redrive happening server-side ---
    off_events = _read_group(ctx, arms["off"]["log_group"])
    assert off_events == [], (
        f"level OFF delivered {[(e.get('id'), e.get('type')) for e in off_events]}"
    )
    streams = ctx.client("logs").describe_log_streams(
        logGroupName=arms["off"]["log_group"])["logStreams"]
    assert streams == [], f"level OFF created streams {[s['logStreamName'] for s in streams]}"
    off_described = sfn.describe_execution(executionArn=results["off"]["exec_arn"])
    assert (off_described["status"], off_described["redriveCount"]) == ("FAILED", 1), (
        f"the OFF arm's execution must still be redriven server-side even though nothing is "
        f"logged; got {(off_described['status'], off_described.get('redriveCount'))!r}"
    )


def _role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnredlog-")[:64]
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Path="/sim2real/",
        Description="sim2real: sfn redrive log-level agreement",
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


def _activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnredlog-")[:80]
    arn = sfn.create_activity(name=name, tags=[{"key": "sim2real", "value": CHECK[:250]}])["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _arm(ctx, role_arn: str, activity_arn: str, *, level: str, include_data: bool) -> dict:
    """One log group plus one state machine (a single failing activity Task) wired to it."""
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    group = ctx.unique_name("/aws/vendedlogs/states/sim2real-behav-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": CHECK[:250]})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    group_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{group}:*"
    definition = json.dumps({
        "StartAt": "Flaky",
        "States": {"Flaky": {"Type": "Task", "Resource": activity_arn, "End": True}},
    })
    sm_arn = _create_state_machine(ctx, role_arn, definition, logging={
        "level": level, "includeExecutionData": include_data,
        "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": group_arn}}],
    })
    return {"log_group": group, "sm_arn": sm_arn, "level": level}


def _create_state_machine(ctx, role_arn: str, definition: str, *, logging: dict) -> str:
    """CreateStateMachine, retrying only the AccessDeniedException raised while the role's
    trust and log-delivery grant propagate (IAM exposes no condition to poll)."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnredlog-")[:80]
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, loggingConfiguration=logging,
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


def _get_task(ctx, activity_arn: str, marker: str, *, timeout_s: float = 60.0) -> str:
    """Poll GetActivityTask (itself a long poll) until the task carrying ``marker`` arrives."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.get_activity_task(activityArn=activity_arn, workerName="sim2real-behav")
        token = resp.get("taskToken")
        if token:
            assert json.loads(resp["input"])["marker"] == marker, (
                f"activity task input marker mismatch: {resp['input']!r} vs {marker!r}"
            )
            return token
    raise AssertionError(f"no activity task for marker {marker!r} within {timeout_s}s")


def _fail_task(ctx, token: str, label: str, marker: str) -> None:
    ctx.client("stepfunctions").send_task_failure(
        taskToken=token, error=f"Sim2Real.{label}", cause=f"{label} for {marker}",
    )


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


def _history(ctx, exec_arn: str) -> list[dict]:
    sfn = ctx.client("stepfunctions")
    out, kwargs = [], {"executionArn": exec_arn, "maxResults": 1000}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        out.extend(resp["events"])
        if not resp.get("nextToken"):
            return out
        kwargs["nextToken"] = resp["nextToken"]


def _redrive_cycle(ctx, arm: dict, activity_arn: str) -> dict:
    """Fail an execution once, redrive it, fail it again; returns both history snapshots."""
    marker = ctx.unique_name("m")[-16:]
    exec_arn = _start(ctx, arm["sm_arn"], marker)
    token1 = _get_task(ctx, activity_arn, marker)
    _fail_task(ctx, token1, "First", marker)
    d1 = _wait_terminal(ctx, exec_arn)
    assert d1["status"] == "FAILED", f"{arm['level']}: first attempt ended {d1['status']!r}"
    assert (d1["redriveCount"], d1["redriveStatus"]) == (0, "REDRIVABLE"), (
        f"{arm['level']}: before redrive expected redriveCount 0, REDRIVABLE; got "
        f"{(d1.get('redriveCount'), d1.get('redriveStatus'))!r}"
    )
    hist1 = _history(ctx, exec_arn)

    ctx.client("stepfunctions").redrive_execution(executionArn=exec_arn)
    token2 = _get_task(ctx, activity_arn, marker)
    _fail_task(ctx, token2, "Second", marker)
    d2 = _wait_terminal(ctx, exec_arn)
    assert d2["status"] == "FAILED", f"{arm['level']}: second attempt ended {d2['status']!r}"
    assert d2["redriveCount"] == 1, (
        f"{arm['level']}: after redrive expected redriveCount 1; got {d2.get('redriveCount')!r}"
    )
    hist2 = _history(ctx, exec_arn)
    assert "ExecutionRedriven" in {h["type"] for h in hist2}, (
        f"{arm['level']}: history must contain ExecutionRedriven; types "
        f"{[h['type'] for h in hist2]}"
    )
    return {"exec_arn": exec_arn, "marker": marker, "hist1": hist1, "hist2": hist2}


def _warm_up(ctx, arm: dict, activity_arn: str) -> None:
    """Run failing executions until one's ExecutionFailed is fully delivered, since an
    execution started in the first seconds of a fresh log-delivery wiring can lose events."""
    deadline = time.monotonic() + _LOG_BUDGET_S
    while time.monotonic() < deadline:
        marker = ctx.unique_name("warm")[-16:]
        exec_arn = _start(ctx, arm["sm_arn"], marker)
        token = _get_task(ctx, activity_arn, marker)
        _fail_task(ctx, token, "Warm", marker)
        d = _wait_terminal(ctx, exec_arn)
        assert d["status"] == "FAILED", f"warm-up execution ended {d['status']!r}"
        settle = time.monotonic() + 12.0
        while time.monotonic() < settle:
            events = [e for e in _read_group(ctx, arm["log_group"]) if e.get("execution_arn") == exec_arn]
            if any(e.get("type") == "ExecutionFailed" for e in events):
                return
            time.sleep(_POLL_S)
    raise AssertionError(f"log group {arm['log_group']} never received a warm-up ExecutionFailed")


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


# Re-enabling logging by UpdateStateMachine makes CloudWatch Logs write a non-JSON probe
# message into this AWS-named stream; it is delivery plumbing, not an execution event.
_VALIDATION_STREAM = "log_stream_created_by_aws_to_validate_log_delivery_subscriptions"


def _await(ctx, group: str, exec_arn: str, done, what: str) -> list[dict]:
    """Poll the group's events for exec_arn until done(events) holds."""
    deadline = time.monotonic() + _LOG_BUDGET_S
    events: list[dict] = []
    while time.monotonic() < deadline:
        events = [e for e in _read_group(ctx, group) if e.get("execution_arn") == exec_arn]
        if done(events):
            return events
        time.sleep(_POLL_S)
    raise AssertionError(
        f"{what}: not delivered to {group} within {_LOG_BUDGET_S}s; delivered "
        f"{[(e.get('id'), e.get('type'), e.get('redrive_count')) for e in events]}"
    )


def _ids(events: list[dict]) -> set[str]:
    return {e["id"] for e in events}


def _hist_ids(history: list[dict]) -> set[str]:
    return {str(h["id"]) for h in history}


def _one(history: list[dict], event_type: str) -> dict:
    matching = [h for h in history if h["type"] == event_type]
    assert len(matching) == 1, f"expected exactly one {event_type}, got {len(matching)}"
    return matching[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
