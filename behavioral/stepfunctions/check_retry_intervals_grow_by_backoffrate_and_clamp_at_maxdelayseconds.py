"""retry-intervals-grow-by-backoffrate-and-clamp-at-maxdelayseconds."""
from __future__ import annotations

import json
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retry-intervals-grow-by-backoffrate-and-clamp-at-maxdelayseconds"
GROUP = "task_state"
SERVICES = ["stepfunctions"]

_INTERVAL_SECONDS = 2
_BACKOFF_RATE = 3.0
_MAX_DELAY_SECONDS = 7
_MAX_ATTEMPTS = 4
_TASK_TIMEOUT_SECONDS = 1
_SLACK_S = 4.0

# 2 -> 6 -> min(18, 7) -> min(54, 7)
_EXPECTED_WAITS = [2.0, 6.0, 7.0, 7.0]
# What the same retrier would produce with MaxDelaySeconds absent.
_UNCLAMPED_WAITS = [2.0, 6.0, 18.0, 54.0]


# timing:real-time — workflow: 2 s https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Retry field's observed wait between attempts grows by BackoffRate and is capped
    by MaxDelaySeconds, measured from the execution history's own timestamps.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
    """
    _role_name, role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _definition(activity_arn))

    absorber = _ActivityAbsorber(ctx, activity_arn)
    absorber.start()
    ctx.on_cleanup(absorber.stop)

    exec_arn = _start(ctx, sm_arn)
    # 5 attempts x 1s timeout + waits 2+6+7+7 = 22s -> ~27s, plus scheduling slop.
    desc = _wait_terminal(ctx, exec_arn, timeout_s=_budget_s(ctx, 180.0))

    assert desc["status"] == "FAILED", (
        "the retrier must exhaust and leave the execution FAILED (no Catch is present); "
        f"got {desc['status']} error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    assert desc.get("error") == "States.Timeout", (
        "the surviving error after retry exhaustion must be the task's own "
        f"States.Timeout; got error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )

    events = _history(ctx, exec_arn)
    scheduled = [e for e in events if e["type"] in _SCHEDULED_TYPES]
    failed = [e for e in events if e["type"] in _FAILED_TYPES]

    assert len(scheduled) == _MAX_ATTEMPTS + 1, (
        f"a retrier with MaxAttempts={_MAX_ATTEMPTS} must schedule the task exactly "
        f"{_MAX_ATTEMPTS + 1} times (1 initial + {_MAX_ATTEMPTS} retries) and then stop; "
        f"got {len(scheduled)} schedule events out of history {[e['type'] for e in events]}"
    )
    assert len(failed) == _MAX_ATTEMPTS + 1, (
        f"every one of the {_MAX_ATTEMPTS + 1} attempts must time out, so history must "
        f"carry {_MAX_ATTEMPTS + 1} timeout events; got {len(failed)} out of "
        f"{[e['type'] for e in events]}"
    )

    waits = _attempt_gaps(events)
    assert len(waits) == _MAX_ATTEMPTS, (
        f"there must be exactly {_MAX_ATTEMPTS} retry waits between the "
        f"{_MAX_ATTEMPTS + 1} attempts; measured {len(waits)}: {waits}"
    )

    for i, (observed, expected) in enumerate(zip(waits, _EXPECTED_WAITS)):
        assert observed >= expected, (
            f"retry wait #{i + 1} must be at least IntervalSeconds*BackoffRate^{i} "
            f"clamped at MaxDelaySeconds={_MAX_DELAY_SECONDS}, i.e. >= {expected}s; "
            f"observed {observed:.2f}s. All measured waits: "
            f"{[round(w, 2) for w in waits]}"
        )
        assert observed < expected + _SLACK_S, (
            f"retry wait #{i + 1} must not exceed {expected}s plus {_SLACK_S}s of "
            f"scheduling slop; observed {observed:.2f}s. A target that ignores "
            f"IntervalSeconds/BackoffRate and waits its own interval fails here. All "
            f"measured waits: {[round(w, 2) for w in waits]}"
        )

    # Without MaxDelaySeconds these two waits would be 18s and 54s.
    for i in (2, 3):
        assert waits[i] < _UNCLAMPED_WAITS[i] - _SLACK_S, (
            f"retry wait #{i + 1} must be clamped by MaxDelaySeconds="
            f"{_MAX_DELAY_SECONDS}s, far below the unclamped "
            f"IntervalSeconds*BackoffRate^{i} = {_UNCLAMPED_WAITS[i]}s; observed "
            f"{waits[i]:.2f}s"
        )

    # wait 2 / wait 1 must be BackoffRate, because neither of those two is clamped.
    ratio = waits[1] / waits[0]
    assert abs(ratio - _BACKOFF_RATE) <= 1.0, (
        f"the ratio of the second unclamped wait to the first must be BackoffRate="
        f"{_BACKOFF_RATE}; observed {waits[1]:.2f}/{waits[0]:.2f} = {ratio:.2f}"
    )
    assert waits[2] <= waits[1] + _SLACK_S, (
        f"once MaxDelaySeconds={_MAX_DELAY_SECONDS} binds, the wait must stop growing "
        f"geometrically: wait #3 ({waits[2]:.2f}s) must not exceed wait #2 "
        f"({waits[1]:.2f}s) by more than {_SLACK_S}s"
    )

    # An error name the retrier does NOT list must not be retried.
    narrow_arn = _create_state_machine(
        ctx, role_arn, _definition(activity_arn, error_equals=["SomeUnrelatedError"])
    )
    narrow_exec = _start(ctx, narrow_arn)
    narrow_desc = _wait_terminal(ctx, narrow_exec, timeout_s=_budget_s(ctx, 120.0))
    assert narrow_desc["status"] == "FAILED", (
        "the narrow-retrier execution must also FAIL; got "
        f"{narrow_desc['status']} cause={narrow_desc.get('cause')!r}"
    )
    narrow_scheduled = [
        e for e in _history(ctx, narrow_exec) if e["type"] in _SCHEDULED_TYPES
    ]
    assert len(narrow_scheduled) == 1, (
        "a retrier whose ErrorEquals does not include States.Timeout must not retry the "
        f"timeout at all, so exactly 1 schedule event may appear; got "
        f"{len(narrow_scheduled)}"
    )

    absorber.stop()



def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


_SCHEDULED_TYPES = ("ActivityScheduled", "TaskScheduled")
_FAILED_TYPES = ("ActivityTimedOut", "TaskTimedOut", "ActivityFailed", "TaskFailed")


class _ActivityAbsorber:
    """Polls GetActivityTask and discards every token so each attempt starts. AWS starts the
    TimeoutSeconds clock only once a token is handed out; an unpolled activity never times out."""

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
        # The thread is a daemon that may sit in an idle GetActivityTask long poll for up to a
        # minute; a short join suffices, since nothing it receives after stop is consulted.
        self._stop_event.set()
        self._thread.join(timeout=2.0)
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


def _definition(activity_arn: str, *, error_equals=None) -> str:
    """An activity Task whose only worker grabs the token and does nothing, so every attempt
    times out after _TASK_TIMEOUT_SECONDS. No Lambda, so no cold start pollutes the waits."""
    return json.dumps(
        {
            "Comment": "retry arithmetic over a deliberately unpolled activity",
            "StartAt": "Attempt",
            "States": {
                "Attempt": {
                    "Type": "Task",
                    "Resource": activity_arn,
                    "TimeoutSeconds": _TASK_TIMEOUT_SECONDS,
                    "Retry": [
                        {
                            "ErrorEquals": error_equals or ["States.Timeout"],
                            "IntervalSeconds": _INTERVAL_SECONDS,
                            "MaxAttempts": _MAX_ATTEMPTS,
                            "BackoffRate": _BACKOFF_RATE,
                            "MaxDelaySeconds": _MAX_DELAY_SECONDS,
                        }
                    ],
                    "End": True,
                }
            },
        }
    )


def _attempt_gaps(events: list[dict]) -> list[float]:
    """Seconds between each attempt's failure and the next attempt's scheduling — i.e.
    the retrier's wait, with the task's own 1s timeout excluded by construction."""
    ordered = sorted(events, key=lambda e: e["id"])
    gaps: list[float] = []
    pending_fail = None
    for event in ordered:
        if event["type"] in _FAILED_TYPES:
            pending_fail = event
        elif event["type"] in _SCHEDULED_TYPES and pending_fail is not None:
            gaps.append(
                (event["timestamp"] - pending_fail["timestamp"]).total_seconds()
            )
            pending_fail = None
    return gaps


def _create_sfn_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnretry-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Path="/sim2real/",
        Description="SimParity draft: sfn retry backoff arithmetic",
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
                    {
                        "Effect": "Allow",
                        "Action": ["states:DescribeStateMachine"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return name, arn


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
    """CreateStateMachine, bounded-retrying only the AccessDeniedException raised while
    the freshly created role's PassRole grant propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnretry-")
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
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
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError("CreateStateMachine accepting the fresh role: the run budget ended first; not graded")
    raise AssertionError(
        f"CreateStateMachine still AccessDenied 120s after the role was created. "
        f"Last error: {last}"
    )


def _start(ctx, sm_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps({"probe": CHECK})
    )["executionArn"]
    ctx.on_cleanup(lambda a=exec_arn: sfn.stop_execution(executionArn=a))
    return exec_arn


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"execution {exec_arn} leaving RUNNING: the run budget ended first; not graded")
    raise AssertionError(
        f"execution {exec_arn} still RUNNING after {timeout_s}s; the retrier's total "
        f"budget is {_MAX_ATTEMPTS + 1} x {_TASK_TIMEOUT_SECONDS}s timeouts plus "
        f"{sum(_EXPECTED_WAITS)}s of waits. Last: {last!r}"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
