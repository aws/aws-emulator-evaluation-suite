"""sfn-retry-interval-seconds-zero-retries-with-no-wait."""
from __future__ import annotations

import json
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-retry-interval-seconds-zero-retries-with-no-wait"
GROUP = "error_handling"
SERVICES = ["stepfunctions"]

_MAX_ATTEMPTS = 1
_TASK_TIMEOUT_SECONDS = 1
_CONTROL_INTERVAL_SECONDS = 10

_SCHEDULED_TYPES = ("ActivityScheduled", "TaskScheduled")
_FAILED_TYPES = ("ActivityTimedOut", "TaskTimedOut", "ActivityFailed", "TaskFailed")

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


# timing:real-time — workflow: 10 s https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """A Retry with IntervalSeconds 0 schedules the extra attempt immediately: its wait between
    the failed attempt and the retry is under half the wait of a twin Retry with IntervalSeconds
    10, which waits at least its 10 s.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
    """
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _definition(activity_arn, 0))
    control_sm_arn = _create_state_machine(
        ctx, role_arn, _definition(activity_arn, _CONTROL_INTERVAL_SECONDS))

    absorber = _ActivityAbsorber(ctx, activity_arn)
    absorber.start()
    ctx.on_cleanup(absorber.stop)

    exec_arn = _start(ctx, sm_arn)
    control_exec_arn = _start(ctx, control_sm_arn)
    desc = _wait_terminal(ctx, exec_arn, timeout_s=60.0)
    control_desc = _wait_terminal(ctx, control_exec_arn, timeout_s=90.0)

    assert desc["status"] == "FAILED", (
        "the retrier must exhaust its one retry and leave the execution FAILED (no Catch is "
        f"present); got {desc['status']} error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    assert desc.get("error") == "States.Timeout", (
        f"the surviving error after retry exhaustion must be States.Timeout; got "
        f"{desc.get('error')!r} cause={desc.get('cause')!r}"
    )

    events = _history(ctx, exec_arn)
    scheduled = [e for e in events if e["type"] in _SCHEDULED_TYPES]
    failed = [e for e in events if e["type"] in _FAILED_TYPES]
    assert len(scheduled) == _MAX_ATTEMPTS + 1, (
        f"MaxAttempts={_MAX_ATTEMPTS} must produce {_MAX_ATTEMPTS + 1} schedule events "
        f"(1 initial + {_MAX_ATTEMPTS} retry); got {len(scheduled)} out of "
        f"{[e['type'] for e in events]}"
    )
    assert len(failed) == _MAX_ATTEMPTS + 1, (
        f"both attempts must time out; got {len(failed)} out of {[e['type'] for e in events]}"
    )

    waits = _attempt_gaps(events)
    assert len(waits) == _MAX_ATTEMPTS, (
        f"there must be exactly {_MAX_ATTEMPTS} retry wait between the "
        f"{_MAX_ATTEMPTS + 1} attempts; measured {len(waits)}: {waits}"
    )
    observed = waits[0]

    # Control: the same machine with IntervalSeconds 10 genuinely waits before its retry.
    assert control_desc["status"] == "FAILED" and control_desc.get("error") == "States.Timeout", (
        f"the IntervalSeconds={_CONTROL_INTERVAL_SECONDS} control must also exhaust its retry "
        f"with States.Timeout; got {control_desc['status']} error={control_desc.get('error')!r}"
    )
    control_waits = _attempt_gaps(_history(ctx, control_exec_arn))
    assert len(control_waits) == _MAX_ATTEMPTS, (
        f"the control must have exactly {_MAX_ATTEMPTS} retry wait; measured {control_waits}"
    )
    control = control_waits[0]
    assert control >= _CONTROL_INTERVAL_SECONDS, (
        f"IntervalSeconds={_CONTROL_INTERVAL_SECONDS} must wait at least that long before the "
        f"retry; observed {control:.2f}s"
    )
    assert 0.0 <= observed < control / 2, (
        f"IntervalSeconds=0 must schedule the retry immediately: its wait must be well under "
        f"the {control:.2f}s the IntervalSeconds={_CONTROL_INTERVAL_SECONDS} control waited; "
        f"observed {observed:.2f}s"
    )


def _definition(activity_arn: str, interval_s: int) -> str:
    """An activity Task whose only worker grabs the token and does nothing, so every attempt
    times out after _TASK_TIMEOUT_SECONDS. No Catch, so retry exhaustion fails the execution."""
    return json.dumps({
        "StartAt": "Attempt",
        "States": {
            "Attempt": {
                "Type": "Task",
                "Resource": activity_arn,
                "TimeoutSeconds": _TASK_TIMEOUT_SECONDS,
                "Retry": [{
                    "ErrorEquals": ["States.Timeout"],
                    "IntervalSeconds": interval_s,
                    "MaxAttempts": _MAX_ATTEMPTS,
                }],
                "End": True,
            }
        },
    })


def _attempt_gaps(events: list[dict]) -> list[float]:
    """Seconds between each attempt's failure and the next attempt's scheduling — the retrier's
    own wait, with the task's own timeout excluded by construction."""
    ordered = sorted(events, key=lambda e: e["id"])
    gaps: list[float] = []
    pending_fail = None
    for event in ordered:
        if event["type"] in _FAILED_TYPES:
            pending_fail = event
        elif event["type"] in _SCHEDULED_TYPES and pending_fail is not None:
            gaps.append((event["timestamp"] - pending_fail["timestamp"]).total_seconds())
            pending_fail = None
    return gaps


class _ActivityAbsorber:
    """Polls GetActivityTask and discards every token so each attempt starts. AWS starts the
    TimeoutSeconds clock only once a token is handed out; an unpolled activity never times out."""

    def __init__(self, ctx, activity_arn: str) -> None:
        self._sfn = ctx.client("stepfunctions")
        self._activity_arn = activity_arn
        self._worker_name = ctx.unique_name("sim2real-behav-sfnzero-worker-")
        self._stop_event = threading.Event()
        self._error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "_ActivityAbsorber":
        self._thread.start()
        return self

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._sfn.get_activity_task(
                    activityArn=self._activity_arn, workerName=self._worker_name
                )
            except ClientError as exc:
                if not self._stop_event.is_set():
                    self._error = exc
                return

    def stop(self) -> None:
        self._stop_event.set()
        self._thread.join(timeout=2.0)
        error, self._error = self._error, None
        if error is not None:
            raise error


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnzero-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create_activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-sfnzero-act-"),
        tags=[{"key": "sim2real", "value": CHECK}],
    )["activityArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_activity(activityArn=arn),
                              "ActivityDoesNotExist"))
    return arn


def _create_state_machine(ctx, role_arn: str, definition: str) -> str:
    """CreateStateMachine, retrying only the AccessDeniedException a fresh role's trust has not
    yet propagated past."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnzero-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc.response["Error"]
            time.sleep(3.0)
            continue
        ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn),
                                  "StateMachineDoesNotExist"))
        return arn
    raise AssertionError(
        f"CreateStateMachine still AccessDenied 120s after role creation; last error {last!r}"
    )


def _start(ctx, sm_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-x-"),
        input=json.dumps({"probe": CHECK}),
    )["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float) -> dict:
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
    events: list[dict] = []
    kwargs = {"executionArn": exec_arn}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return events
        kwargs["nextToken"] = token


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
