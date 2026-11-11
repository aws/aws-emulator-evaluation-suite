"""retry-multi-name-retrier-shares-counter-across-alternating-errors."""
from __future__ import annotations

import json
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retry-multi-name-retrier-shares-counter-across-alternating-errors"
GROUP = "error_handling"
SERVICES = ["stepfunctions"]

_INTERVAL_SECONDS = 5
_BACKOFF_RATE = 3.0
_MAX_ATTEMPTS = 2
# 1 initial attempt + 2 retries; the retrier names BOTH errors, so one shared
# counter and backoff sequence must govern both, however the failures alternate.
_SCRIPT = (
    ("fail", "java.lang.Exception", "sim2real-first"),
    ("fail", "secondError", "sim2real-second"),
    ("succeed", {"ok": True}),
)
# IntervalSeconds * BackoffRate^0, IntervalSeconds * BackoffRate^1: 5s then 15s.
_EXPECTED_WAITS = [_INTERVAL_SECONDS * _BACKOFF_RATE ** i for i in range(_MAX_ATTEMPTS)]
_SLACK_S = 5.0


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """One Retrier naming two error names keeps a single attempt counter and backoff
    sequence across them: 3 total attempts (1+MaxAttempts) and waits 5s then 15s.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
    """
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _definition(activity_arn))

    worker = _ScriptedWorker(ctx, activity_arn, _SCRIPT)
    worker.start()
    ctx.on_cleanup(worker.stop)

    exec_arn = _start(ctx, sm_arn)
    desc = _wait_terminal(ctx, exec_arn, timeout_s=120.0)
    worker.stop()

    assert desc["status"] == "SUCCEEDED", (
        "the retrier must exhaust the alternating failures and let the 3rd attempt "
        f"succeed; got {desc['status']} error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    assert json.loads(desc["output"]) == {"ok": True}, (
        f"the successful attempt's own output must survive unchanged, got {desc['output']!r}"
    )

    events = _history(ctx, exec_arn)
    scheduled = [e for e in events if e["type"] == "ActivityScheduled"]
    failed = [e for e in events if e["type"] == "ActivityFailed"]
    assert len(scheduled) == _MAX_ATTEMPTS + 1, (
        f"a single retrier naming both errors with MaxAttempts={_MAX_ATTEMPTS} must run the "
        f"task exactly {_MAX_ATTEMPTS + 1} times total, no matter which of its listed errors "
        f"came back each time; got {len(scheduled)} ActivityScheduled events"
    )
    assert len(failed) == _MAX_ATTEMPTS, (
        f"exactly {_MAX_ATTEMPTS} attempts must fail before the 3rd succeeds; got "
        f"{len(failed)} ActivityFailed events"
    )
    assert [e["activityFailedEventDetails"]["error"] for e in sorted(failed, key=lambda e: e["id"])] == [
        "java.lang.Exception", "secondError"
    ], (
        f"the two failures must carry the exact alternating error names the worker raised; "
        f"got {[e['activityFailedEventDetails']['error'] for e in failed]!r}"
    )

    waits = _attempt_gaps(events)
    assert len(waits) == _MAX_ATTEMPTS, (
        f"there must be exactly {_MAX_ATTEMPTS} waits between the "
        f"{_MAX_ATTEMPTS + 1} attempts; measured {len(waits)}: {waits}"
    )
    for i, (observed, expected) in enumerate(zip(waits, _EXPECTED_WAITS)):
        assert expected <= observed < expected + _SLACK_S, (
            f"wait #{i + 1}, counted from the SHARED retrier regardless of which named error "
            f"triggered it, must be IntervalSeconds={_INTERVAL_SECONDS} * "
            f"BackoffRate={_BACKOFF_RATE}^{i} = {expected}s (+/- scheduling slop); "
            f"observed {observed:.2f}s. All measured waits: {[round(w, 2) for w in waits]}"
        )


class _ScriptedWorker:
    """Answers each GetActivityTask call with the next outcome in ``script``, then repeats
    the last outcome forever, so an engine that over-retries is observable rather than hung."""

    def __init__(self, ctx, activity_arn: str, script) -> None:
        self._sfn = ctx.client("stepfunctions")
        self._activity_arn = activity_arn
        self._worker_name = ctx.unique_name("sim2real-behav-sfnretry-worker-")
        self._script = list(script)
        self._calls = 0
        self._stop_event = threading.Event()
        self._error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> "_ScriptedWorker":
        self._thread.start()
        return self

    def _run(self) -> None:
        try:
            while not self._stop_event.is_set():
                resp = self._sfn.get_activity_task(
                    activityArn=self._activity_arn, workerName=self._worker_name
                )
                token = resp.get("taskToken")
                if not token:
                    continue
                self._calls += 1
                action = self._script[min(self._calls, len(self._script)) - 1]
                if action[0] == "fail":
                    self._sfn.send_task_failure(
                        taskToken=token, error=action[1], cause=action[2]
                    )
                else:
                    self._sfn.send_task_success(taskToken=token, output=json.dumps(action[1]))
        except ClientError as exc:
            if not self._stop_event.is_set():
                self._error = exc

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
    return json.dumps(
        {
            "Comment": "a retrier naming two error names shares one counter and backoff",
            "StartAt": "Attempt",
            "States": {
                "Attempt": {
                    "Type": "Task",
                    "Resource": activity_arn,
                    "Retry": [
                        {
                            "ErrorEquals": ["java.lang.Exception", "secondError"],
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


def _attempt_gaps(events: list[dict]) -> list[float]:
    """Seconds between each attempt's failure and the next attempt's scheduling."""
    ordered = sorted(events, key=lambda e: e["id"])
    gaps: list[float] = []
    pending_fail = None
    for event in ordered:
        if event["type"] == "ActivityFailed":
            pending_fail = event
        elif event["type"] == "ActivityScheduled" and pending_fail is not None:
            gaps.append((event["timestamp"] - pending_fail["timestamp"]).total_seconds())
            pending_fail = None
    return gaps


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnretry-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Path="/sim2real/",
        Description="sim2real-behav sfn multi-name retrier check role",
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
