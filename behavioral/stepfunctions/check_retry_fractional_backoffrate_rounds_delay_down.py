"""retry-fractional-backoffrate-rounds-delay-down."""
from __future__ import annotations

import json
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retry-fractional-backoffrate-rounds-delay-down"
GROUP = "error_handling"
SERVICES = ["stepfunctions"]

_INTERVAL_SECONDS = 5
_BACKOFF_RATE = 1.5
_MAX_ATTEMPTS = 2
_TASK_TIMEOUT_SECONDS = 1
# wait #1 = IntervalSeconds * BackoffRate^0 = 5s, exact.
# wait #2 = IntervalSeconds * BackoffRate^1 = 7.5s in exact arithmetic, but the service
# truncates the fractional second rather than rounding to nearest or up, so it is observed
# at 7s: strictly below 7.5s and at or above 7.0s.
_WAIT_1_S = 5.0
_WAIT_2_FLOOR_S = 7.0
_WAIT_2_UNROUNDED_S = 7.5
_SLACK_S = 5.0


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """A fractional BackoffRate's computed delay is truncated to whole seconds, not
    rounded to the nearest or the next whole second.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
    """
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _definition(activity_arn))

    absorber = _ActivityAbsorber(ctx, activity_arn)
    absorber.start()
    ctx.on_cleanup(absorber.stop)

    exec_arn = _start(ctx, sm_arn)
    desc = _wait_terminal(ctx, exec_arn, timeout_s=120.0)
    absorber.stop()

    assert desc["status"] == "FAILED", (
        "the retrier must exhaust (no Catch is present) and leave the execution FAILED; "
        f"got {desc['status']} error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    assert desc.get("error") == "States.Timeout", (
        f"the surviving error after retry exhaustion must be States.Timeout; "
        f"got {desc.get('error')!r} cause={desc.get('cause')!r}"
    )

    events = _history(ctx, exec_arn)
    scheduled = [e for e in events if e["type"] in _SCHEDULED_TYPES]
    assert len(scheduled) == _MAX_ATTEMPTS + 1, (
        f"MaxAttempts={_MAX_ATTEMPTS} must schedule the task exactly {_MAX_ATTEMPTS + 1} "
        f"times (1 initial + {_MAX_ATTEMPTS} retries); got {len(scheduled)}"
    )

    waits = _attempt_gaps(events)
    assert len(waits) == _MAX_ATTEMPTS, (
        f"there must be exactly {_MAX_ATTEMPTS} retry waits; measured {len(waits)}: {waits}"
    )

    assert _WAIT_1_S <= waits[0] < _WAIT_1_S + _SLACK_S, (
        f"wait #1 (BackoffRate^0, unaffected by rounding) must be ~{_WAIT_1_S}s; "
        f"observed {waits[0]:.2f}s. All measured waits: {[round(w, 2) for w in waits]}"
    )
    assert _WAIT_2_FLOOR_S <= waits[1] < _WAIT_2_UNROUNDED_S, (
        f"wait #2 (IntervalSeconds={_INTERVAL_SECONDS} * BackoffRate={_BACKOFF_RATE}^1 = "
        f"{_WAIT_2_UNROUNDED_S}s in exact arithmetic) must be observed rounded DOWN to "
        f"{_WAIT_2_FLOOR_S}s, never reaching the unrounded {_WAIT_2_UNROUNDED_S}s; "
        f"observed {waits[1]:.2f}s. All measured waits: {[round(w, 2) for w in waits]}"
    )


def _attempt_gaps(events: list[dict]) -> list[float]:
    """Seconds between each attempt's timeout and the next attempt's scheduling."""
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


_SCHEDULED_TYPES = ("ActivityScheduled",)
_FAILED_TYPES = ("ActivityTimedOut",)


class _ActivityAbsorber:
    """Polls GetActivityTask and discards every token so each attempt starts, then times
    out on its own: AWS starts the TimeoutSeconds clock only once a token is handed out."""

    def __init__(self, ctx, activity_arn: str) -> None:
        self._sfn = ctx.client("stepfunctions")
        self._activity_arn = activity_arn
        self._worker_name = ctx.unique_name("sim2real-behav-sfnretry-worker-")
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
        self._thread.join(timeout=5.0)
        error, self._error = self._error, None
        if error is not None:
            raise error


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


def _definition(activity_arn: str) -> str:
    """An activity Task whose only worker grabs the token and does nothing, so every attempt
    times out after TASK_TIMEOUT_SECONDS. No Lambda, so no cold start pollutes the waits."""
    return json.dumps(
        {
            "Comment": "retry arithmetic with a fractional BackoffRate",
            "StartAt": "Attempt",
            "States": {
                "Attempt": {
                    "Type": "Task",
                    "Resource": activity_arn,
                    "TimeoutSeconds": _TASK_TIMEOUT_SECONDS,
                    "Retry": [
                        {
                            "ErrorEquals": ["States.Timeout"],
                            "IntervalSeconds": _INTERVAL_SECONDS,
                            "MaxAttempts": _MAX_ATTEMPTS,
                            "BackoffRate": _BACKOFF_RATE,
                        }
                    ],
                    "End": True,
                }
            },
        }
    )


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnretry-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Path="/sim2real/",
        Description="sim2real-behav sfn fractional backoff check role",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-sfnretry-act-"),
        tags=[
            {"key": "sim2real", "value": "1"},
            {"key": "sim2real-check", "value": CHECK},
        ],
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _create_state_machine(ctx, role_arn: str, definition: str) -> str:
    """CreateStateMachine, bounded-retrying the AccessDeniedException raised while the
    freshly created role's trust policy propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnretry-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                tags=[
                    {"key": "sim2real", "value": "1"},
                    {"key": "sim2real-check", "value": CHECK},
                ],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied 120s after the role was created: {last!r}")


def _stop_if_running(sfn, exec_arn: str) -> None:
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn, error="sim2real.cleanup")


def _start(ctx, sm_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps({"probe": CHECK})
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
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
    raise AssertionError(f"execution {exec_arn} still RUNNING after {timeout_s}s; last={last!r}")


def _history(ctx, exec_arn: str) -> list[dict]:
    sfn = ctx.client("stepfunctions")
    events: list[dict] = []
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        events.extend(page["events"])
    return events


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
