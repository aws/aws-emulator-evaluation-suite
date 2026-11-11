"""sfn-parallel-branch-task-local-catch-handles-failure."""
from __future__ import annotations

import json
import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-parallel-branch-task-local-catch-handles-failure"
GROUP = "parallel_state"
SERVICES = ["stepfunctions"]

_TASK_TIMEOUT_SECONDS = 1
_RETRY_MAX_ATTEMPTS = 1
_RETRY_INTERVAL_SECONDS = 1

_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


# timing:real-time — workflow: 1 s https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data",
      "timing:real-time")
def run(ctx) -> None:
    """A Retry/Catch declared on a Task inside one Parallel branch handles that branch's
    failure locally — the Parallel itself needs no Catch and still SUCCEEDS, with the sibling
    branch's own output intact.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
    """
    role_arn = _create_sfn_role(ctx)
    activity_arn = _create_activity(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _definition(activity_arn))

    absorber = _ActivityAbsorber(ctx, activity_arn)
    absorber.start()
    ctx.on_cleanup(absorber.stop)

    exec_arn = _start(ctx, sm_arn)
    desc = _wait_terminal(ctx, exec_arn, timeout_s=60.0)

    assert desc["status"] == "SUCCEEDED", (
        "a branch's Task-level Catch must absorb that branch's failure, and the Parallel (which "
        f"declares no Catch of its own) must still SUCCEED; got status={desc['status']!r} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    assert desc.get("error") is None and desc.get("cause") is None, (
        "a failure caught inside a branch must never surface at the execution level; got "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )

    output = json.loads(desc["output"])
    assert output == ["locally-caught", "sibling-fine"], (
        "the Parallel's output must be the two branches' own outputs in order: the first "
        "branch's Task-level Catch routing to 'locally-caught', and the untouched sibling's "
        f"'sibling-fine'; got {output!r}"
    )

    events = _history(ctx, exec_arn)
    timed_out = [e for e in events if e["type"] in ("ActivityTimedOut", "TaskTimedOut")]
    assert len(timed_out) == _RETRY_MAX_ATTEMPTS + 1, (
        f"the branch's Task must time out {_RETRY_MAX_ATTEMPTS + 1} times (1 initial attempt + "
        f"{_RETRY_MAX_ATTEMPTS} retry) before its Catch absorbs the failure locally; got "
        f"{len(timed_out)} timeout events out of {[e['type'] for e in events]}"
    )


def _definition(activity_arn: str) -> dict:
    """Branch A's Task retries once, then a local Catch routes to its own handler; branch B is
    an untouched Pass. Neither failure nor any error field reaches the Parallel, which declares
    no Catch of its own."""
    return {
        "StartAt": "P",
        "States": {
            "P": {
                "Type": "Parallel",
                "Branches": [
                    {
                        "StartAt": "AlwaysTimesOut",
                        "States": {
                            "AlwaysTimesOut": {
                                "Type": "Task",
                                "Resource": activity_arn,
                                "TimeoutSeconds": _TASK_TIMEOUT_SECONDS,
                                "Retry": [{
                                    "ErrorEquals": ["States.Timeout"],
                                    "IntervalSeconds": _RETRY_INTERVAL_SECONDS,
                                    "MaxAttempts": _RETRY_MAX_ATTEMPTS,
                                }],
                                "Catch": [{
                                    "ErrorEquals": ["States.ALL"],
                                    "ResultPath": "$.err",
                                    "Next": "LocalHandler",
                                }],
                                "Next": "Unreached",
                            },
                            "LocalHandler": {"Type": "Pass", "Result": "locally-caught", "End": True},
                            "Unreached": {"Type": "Pass", "Result": "unreached", "End": True},
                        },
                    },
                    {
                        "StartAt": "Sibling",
                        "States": {
                            "Sibling": {"Type": "Pass", "Result": "sibling-fine", "End": True},
                        },
                    },
                ],
                "End": True,
            }
        },
    }


class _ActivityAbsorber:
    """Polls GetActivityTask and discards every token so each attempt starts. AWS starts the
    TimeoutSeconds clock only once a token is handed out; an unpolled activity never times out."""

    def __init__(self, ctx, activity_arn: str) -> None:
        self._sfn = ctx.client("stepfunctions")
        self._activity_arn = activity_arn
        self._worker_name = ctx.unique_name("sim2real-behav-sfnplocal-worker-")
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
    name = ctx.unique_name("sim2real-behav-sfnplocal-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create_activity(ctx) -> str:
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-sfnplocal-act-"),
        tags=[{"key": "sim2real", "value": CHECK}],
    )["activityArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_activity(activityArn=arn),
                              "ActivityDoesNotExist"))
    return arn


def _create_state_machine(ctx, role_arn: str, definition: dict) -> str:
    """CreateStateMachine, retrying only the AccessDeniedException a fresh role's trust has not
    yet propagated past."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnplocal-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
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
