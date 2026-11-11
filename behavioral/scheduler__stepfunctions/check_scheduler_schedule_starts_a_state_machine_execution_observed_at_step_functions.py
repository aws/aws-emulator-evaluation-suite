"""scheduler-schedule-starts-a-state-machine-execution-observed-at-step-functions."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scheduler-schedule-starts-a-state-machine-execution-observed-at-step-functions"
GROUP = "event-propagation"
SERVICES = ["scheduler", "stepfunctions"]

_FIRE_OFFSET_S = 15
_EXECUTION_TIMEOUT_S = 240
_TERMINAL_TIMEOUT_S = 90
_QUIET_FLOOR_S = 10
_EARLY_SLACK_S = 5
_LATE_SLACK_S = 90


# timing:real-time — schedule: 15 s https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A schedule targeting a state machine starts an execution whose input has every context
    attribute substituted, succeeds, and starts at the nominal instant; a DISABLED twin starts none.
    Evidence is read at Step Functions; Scheduler's own API does not show that an execution ran.

    Reference: https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-context-attributes.html
    """
    sfn = ctx.client("stepfunctions")
    sch = ctx.client("scheduler")

    machine_arn = _create_state_machine(ctx)
    role_arn = _scheduler_role(
        ctx, [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": machine_arn}]
    )

    # The instant is re-anchored on every CreateSchedule attempt: IAM propagation can hold the
    # call off, and an at() instant computed before that could be in the past when it is accepted.
    anchor: dict = {}

    def _anchored_expression() -> str:
        anchor["nominal"] = datetime.datetime.now(datetime.timezone.utc).replace(
            microsecond=0
        ) + datetime.timedelta(seconds=_FIRE_OFFSET_S)
        return f"at({anchor['nominal'].strftime('%Y-%m-%dT%H:%M:%S')})"

    enabled_marker = ctx.unique_name("enabled-")
    disabled_marker = ctx.unique_name("disabled-")
    payload_template = {
        "marker": None,
        "at": "<aws.scheduler.scheduled-time>",
        "exec": "<aws.scheduler.execution-id>",
        "arn": "<aws.scheduler.schedule-arn>",
        "attempt": "<aws.scheduler.attempt-number>",
    }

    enabled_schedule_arn = _create_schedule(
        ctx,
        expression=_anchored_expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="ENABLED",
        Target={
            "Arn": machine_arn,
            "RoleArn": role_arn,
            "Input": json.dumps({**payload_template, "marker": enabled_marker}),
        },
    )
    nominal = anchor["nominal"]
    expression = f"at({nominal.strftime('%Y-%m-%dT%H:%M:%S')})"
    disabled_schedule_arn = _create_schedule(
        ctx,
        expression=lambda: expression,
        ScheduleExpressionTimezone="UTC",
        FlexibleTimeWindow={"Mode": "OFF"},
        State="DISABLED",
        Target={
            "Arn": machine_arn,
            "RoleArn": role_arn,
            "Input": json.dumps({**payload_template, "marker": disabled_marker}),
        },
    )

    matched = _poll_until(
        lambda: _executions_by_marker(ctx, machine_arn, {enabled_marker, disabled_marker}),
        lambda found: enabled_marker in found,
        timeout_s=_budget_s(ctx, _EXECUTION_TIMEOUT_S),
        interval_s=2.0,
        ctx=ctx,
        description=(
            f"Step Functions to record an execution of {machine_arn} started by the ENABLED schedule "
            f"{enabled_schedule_arn} due at {nominal.isoformat()}"
        ),
    )
    execution = matched[enabled_marker]

    described = _poll_until(
        lambda: sfn.describe_execution(executionArn=execution["executionArn"]),
        lambda d: d["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
        timeout_s=_budget_s(ctx, _TERMINAL_TIMEOUT_S),
        interval_s=1.0,
        ctx=ctx,
        description=(
            f"execution {execution['executionArn']} to reach a terminal status (the poll's terminal "
            f"set deliberately includes the failure values so a failed execution is reported as a "
            f"failure rather than as a timeout)"
        ),
    )
    assert described["status"] == "SUCCEEDED", (
        f"the execution started by the schedule ended {described['status']!r}, expected SUCCEEDED "
        f"for a single Pass state; stopDate={described.get('stopDate')!r}"
    )

    delivered = json.loads(described["input"])
    assert delivered["marker"] == enabled_marker, (
        f"the execution input carries marker {delivered.get('marker')!r}, expected "
        f"{enabled_marker!r} — the wrong schedule's payload reached Step Functions"
    )
    assert "<aws.scheduler" not in described["input"], (
        f"a reserved context-attribute token survived unsubstituted into the execution input: "
        f"{described['input']!r}"
    )
    assert delivered["arn"] == enabled_schedule_arn, (
        f"<aws.scheduler.schedule-arn> was substituted as {delivered['arn']!r}, expected the "
        f"schedule's own ARN {enabled_schedule_arn!r}"
    )
    assert delivered["attempt"] == "1", (
        f"<aws.scheduler.attempt-number> was substituted as {delivered['attempt']!r}, expected '1' "
        f"for a first, successful delivery"
    )
    reported = _parse_iso(delivered["at"])
    assert reported == nominal, (
        f"<aws.scheduler.scheduled-time> resolved to {reported.isoformat()}, expected the nominal "
        f"instant {nominal.isoformat()} (raw {delivered['at']!r})"
    )
    # A Pass state echoes its input, so the output proves the payload reached the state machine's own
    # data plane and not merely its execution record.
    assert json.loads(described["output"]) == delivered, (
        f"the Pass state's output {described['output']!r} does not echo its input "
        f"{described['input']!r}"
    )

    started = described["startDate"]
    if started.tzinfo is None:
        started = started.replace(tzinfo=datetime.timezone.utc)
    early = (nominal - started).total_seconds()
    late = (started - nominal).total_seconds()
    assert early <= _EARLY_SLACK_S, (
        f"Step Functions recorded the execution starting at {started.isoformat()}, {early:.1f}s "
        f"BEFORE the schedule's nominal instant {nominal.isoformat()}; a Mode=OFF schedule cannot "
        f"fire early"
    )
    assert late <= _LATE_SLACK_S, (
        f"Step Functions recorded the execution starting at {started.isoformat()}, {late:.1f}s after "
        f"the schedule's nominal instant {nominal.isoformat()}, beyond the {_LATE_SLACK_S}s slack"
    )

    # The enabled twin's arrival shows the shared due time has passed; the window is re-listed
    # throughout so a late disabled-twin execution is still seen.
    after = _watch_for_markers(
        ctx, machine_arn, {enabled_marker, disabled_marker},
        window_s=_QUIET_FLOOR_S,
    )
    assert disabled_marker not in after, (
        f"the DISABLED schedule {disabled_schedule_arn}, due at the same instant on the same state "
        f"machine and execution role, started execution "
        f"{after.get(disabled_marker, {}).get('executionArn')!r}; State was ignored"
    )
    still = sch.get_schedule(Name=disabled_schedule_arn.rsplit("/", 1)[-1])
    assert still["State"] == "DISABLED", (
        f"the disabled twin reports State {still['State']!r} after its due time passed; it must not "
        f"have been consumed or silently flipped, or the absence above proves nothing"
    )


_MANAGED_TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}]
# CreateSchedule validates the target role by assuming it, and IAM is eventually consistent, so the
# first attempts fail with ValidationException. The bounded retry is the wait.
_CREATE_TIMEOUT_S = 180

# A single Pass state: no downstream permissions are needed, and Pass echoes its input to its output,
# which is what makes the payload observable at the consumer's data plane.
_DEFINITION = {
    "Comment": "sim2real fidelity probe: echo the scheduler payload",
    "StartAt": "Echo",
    "States": {"Echo": {"Type": "Pass", "End": True}},
}


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _parse_iso(value: str) -> datetime.datetime:
    """Parse scheduled-time, which Scheduler renders as e.g. '2022-03-22T18:59:43Z'."""
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _role(ctx, prefix: str, principal: str, statements: list[dict]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAGS_KV
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="sim2real-target",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return arn


def _scheduler_role(ctx, statements: list[dict]) -> str:
    return _role(ctx, "sim2real-behav-sched-role-", "scheduler.amazonaws.com", statements)


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_state_machine(ctx) -> str:
    """Create or adopt a STANDARD state machine; EXPRESS does not serve describe_execution."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sched-sm-")
    exec_role = _role(ctx, "sim2real-behav-sched-smrole-", "states.amazonaws.com", [])
    create_s = _budget_s(ctx, _CREATE_TIMEOUT_S)
    deadline = time.monotonic() + create_s
    last = None
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(_DEFINITION),
                roleArn=exec_role,
                type="STANDARD",
                tags=[{"key": "sim2real:managed", "value": "true"}],
            )["stateMachineArn"]
            break
        except sfn.exceptions.StateMachineAlreadyExists:
            arn = _find_state_machine(ctx, name)
            break
        except ClientError as exc:
            last = exc
            # CreateStateMachine validates the execution role by assuming it, and IAM is eventually
            # consistent. The bounded retry is the wait.
            if exc.response.get("Error", {}).get("Code") != "AccessDeniedException":
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("CreateStateMachine to be accepted: the run budget ended first; not graded") from last
                raise AssertionError(
                    f"CreateStateMachine still refused after {create_s:.0f}s of IAM "
                    f"propagation: {last!r}"
                ) from last
            time.sleep(1)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _find_state_machine(ctx, name: str) -> str:
    sfn = ctx.client("stepfunctions")
    token = None
    while True:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = sfn.list_state_machines(**kwargs)
        for item in page["stateMachines"]:
            if item["name"] == name:
                return item["stateMachineArn"]
        token = page.get("nextToken")
        if not token:
            raise AssertionError(
                f"state machine {name!r} reported as already existing but is absent from "
                f"ListStateMachines"
            )


def _create_schedule(ctx, *, expression, **kwargs) -> str:
    """Create a schedule, retrying the IAM-propagation ValidationException; returns its ARN.

    `expression` is called on every attempt, so an at() instant can be re-anchored per attempt.
    """
    sch = ctx.client("scheduler")
    name = kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-sched-")
    create_s = _budget_s(ctx, _CREATE_TIMEOUT_S)
    deadline = time.monotonic() + create_s
    last = None
    while True:
        try:
            arn = sch.create_schedule(
                Name=name, ScheduleExpression=expression(), **kwargs
            )["ScheduleArn"]
            break
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") != "ValidationException":
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("CreateSchedule to be accepted: the run budget ended first; not graded") from last
                raise AssertionError(
                    f"CreateSchedule still refused after {create_s:.0f}s of IAM "
                    f"propagation: {last!r}"
                ) from last
            time.sleep(1)
    ctx.on_cleanup(lambda: _delete_schedule(ctx, name))
    return arn


def _delete_schedule(ctx, name: str) -> None:
    try:
        ctx.client("scheduler").delete_schedule(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _executions_by_marker(ctx, machine_arn: str, wanted: set[str]) -> dict[str, dict]:
    """Every execution of `machine_arn` whose input carries one of `wanted`, keyed by marker.

    Only describe_execution carries the input, so each listed execution is described.
    """
    sfn = ctx.client("stepfunctions")
    found: dict[str, dict] = {}
    token = None
    while True:
        kwargs = {"stateMachineArn": machine_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = sfn.list_executions(**kwargs)
        for item in page["executions"]:
            detail = sfn.describe_execution(executionArn=item["executionArn"])
            raw = detail["input"]
            for marker in wanted:
                if marker in raw and marker not in found:
                    found[marker] = item
        token = page.get("nextToken")
        if not token:
            return found


def _watch_for_markers(ctx, machine_arn: str, wanted: set[str], *, window_s: float) -> dict:
    """Re-list executions for a bounded window, accumulating every marker seen; never raises."""
    found: dict[str, dict] = {}
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        found.update(_executions_by_marker(ctx, machine_arn, wanted))
        time.sleep(2)
    return found


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str, ctx=None):
    """Poll until `predicate` holds; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"waited {timeout_s}s for {description}; last observation was {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
