"""metrics-states-stream-late-activity-result-rejected-after-task-timeout-and-only-timed-out-moves."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-states-stream-late-activity-result-rejected-after-task-timeout-and-only-timed-out-moves"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "stepfunctions"]

_NAMESPACE = "AWS/States"
_METRIC_BUDGET_S = 600.0
_POLL_S = 10.0
_TASK_TIMEOUT_S = 5


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html
@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A worker answering after the Task TimeoutSeconds gets TaskTimedOut and its exact message; the execution fails.

    Only ActivitiesTimedOut/ExecutionsFailed move; an in-time control moves the succeeded counters.
    """
    sfn = ctx.client("stepfunctions")
    cw = ctx.client("cloudwatch")

    role_arn = _states_role(ctx)
    slow_act = _activity(ctx, sfn, "late-")
    ctrl_act = _activity(ctx, sfn, "ctrl-")
    slow_sm = _state_machine(ctx, sfn, role_arn, _definition(slow_act, _TASK_TIMEOUT_S))
    ctrl_sm = _state_machine(ctx, sfn, role_arn, _definition(ctrl_act, 300))

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)

    ex_slow = _start(ctx, sfn, slow_sm)
    ex_ctrl = _start(ctx, sfn, ctrl_sm)
    slow_token = _poll_task(sfn, slow_act)["taskToken"]
    ctrl_token = _poll_task(sfn, ctrl_act)["taskToken"]

    # Positive control: the in-time answer is accepted and completes its execution.
    sfn.send_task_success(taskToken=ctrl_token, output=json.dumps({"ok": 1}))
    ctrl = _wait_terminal(sfn, ex_ctrl)
    assert ctrl["status"] == "SUCCEEDED", f"control execution ended {ctrl['status']!r}"

    # The subject's task must time out on its own; poll the execution for the transition.
    slow = _wait_terminal(sfn, ex_slow)
    assert slow["status"] == "FAILED", (
        f"a Task state past its TimeoutSeconds must FAIL the execution; got {slow['status']!r}"
    )
    assert slow.get("error") == "States.Timeout", (
        f"execution error is {slow.get('error')!r}; expected 'States.Timeout'"
    )

    code, message = _error(lambda: sfn.send_task_success(
        taskToken=slow_token, output=json.dumps({"late": True})))
    assert code == "TaskTimedOut", (
        f"SendTaskSuccess with a timed-out task token must be refused with TaskTimedOut; got {code!r}"
    )
    assert message == f"Task Timed Out: '{slow_act}'", f"TaskTimedOut message {message!r}"
    after = sfn.describe_execution(executionArn=ex_slow)
    assert after["status"] == "FAILED" and "output" not in after, (
        f"the refused late answer changed the execution: status {after['status']!r}, "
        f"output {after.get('output')!r}"
    )

    slow_a = [{"Name": "ActivityArn", "Value": slow_act}]
    ctrl_a = [{"Name": "ActivityArn", "Value": ctrl_act}]
    slow_s = [{"Name": "StateMachineArn", "Value": slow_sm}]
    ctrl_s = [{"Name": "StateMachineArn", "Value": ctrl_sm}]
    want = {
        "slow ActivitiesTimedOut": 1.0,
        "slow ExecutionsFailed": 1.0,
        "ctrl ActivitiesSucceeded": 1.0,
        "ctrl ExecutionsSucceeded": 1.0,
    }
    reads = {
        "slow ActivitiesTimedOut": ("ActivitiesTimedOut", slow_a),
        "slow ExecutionsFailed": ("ExecutionsFailed", slow_s),
        "ctrl ActivitiesSucceeded": ("ActivitiesSucceeded", ctrl_a),
        "ctrl ExecutionsSucceeded": ("ExecutionsSucceeded", ctrl_s),
    }
    settle_started = time.monotonic()
    got = _poll(lambda: {k: _sum(cw, m, d, window_start) for k, (m, d) in reads.items()},
                lambda r: r == want, f"AWS/States sums to reach {want!r}")
    settle_s = time.monotonic() - settle_started

    # Effect-absent, held past the barrier: the subject's counters for the outcome that was
    # refused, and the control's counters for the outcome it never had.
    absent = {
        "slow ActivitiesSucceeded": ("ActivitiesSucceeded", slow_a),
        "slow ExecutionsSucceeded": ("ExecutionsSucceeded", slow_s),
        "slow ExecutionsTimedOut": ("ExecutionsTimedOut", slow_s),
        "ctrl ActivitiesTimedOut": ("ActivitiesTimedOut", ctrl_a),
        "ctrl ExecutionsFailed": ("ExecutionsFailed", ctrl_s),
    }
    # Real AWS publishes the untouched counters as explicit zero-valued datapoints in the same
    # batch as the moved ones, so a hold as long as the barrier took to settle, never under
    # 10 s, suffices.
    hold_until = time.monotonic() + max(10.0, settle_s)
    while True:
        seen = {k: _stats(cw, m, d, window_start, "Sum") for k, (m, d) in absent.items()}
        nonzero = {k: v for k, v in seen.items() if any(p["Sum"] > 0 for p in v)}
        assert not nonzero, (
            f"counters that must not move did: {nonzero!r} (positive sums settled at {got!r})"
        )
        if time.monotonic() >= hold_until:
            break
        time.sleep(_POLL_S)


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


def _definition(activity: str, timeout_s: int) -> str:
    return json.dumps({
        "StartAt": "Work",
        "States": {"Work": {"Type": "Task", "Resource": activity, "TimeoutSeconds": timeout_s,
                            "End": True}},
    })


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call was ACCEPTED; real AWS refuses it")


def _states_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnlate-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Description="sim2real sfn metrics",
        Tags=[{"Key": "sim2real", "Value": CHECK[:200]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _activity(ctx, sfn, suffix: str) -> str:
    arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-act-" + suffix),
        tags=[{"key": "sim2real", "value": "1"}],
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))
    return arn


def _state_machine(ctx, sfn, role_arn: str, definition: str) -> str:
    name = ctx.unique_name("sim2real-behav-sfnlate-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)  # IAM propagation of the fresh role: no observable to poll
    raise AssertionError(f"CreateStateMachine AccessDenied for 120s after role create: {last}")


def _start(ctx, sfn, sm_arn: str) -> str:
    arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    ctx.on_cleanup(lambda: _stop_quiet(sfn, arn))
    return arn


def _stop_quiet(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


def _poll_task(sfn, activity: str) -> dict:
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        task = sfn.get_activity_task(activityArn=activity, workerName="sim2real-worker")
        if task.get("taskToken"):
            return task
    raise AssertionError(f"GetActivityTask on {activity} returned no task within 120s")


def _wait_terminal(sfn, arn: str, timeout_s: float = 180.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {arn} still RUNNING after {timeout_s}s: {last!r}")


def _stats(cw, metric: str, dims: list, start, stat: str) -> list:
    return cw.get_metric_statistics(
        Namespace=_NAMESPACE, MetricName=metric, Dimensions=dims, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2), Period=60,
        Statistics=[stat],
    )["Datapoints"]


def _sum(cw, metric: str, dims: list, start) -> float:
    return float(sum(d["Sum"] for d in _stats(cw, metric, dims, start, "Sum")))


def _poll(read, done, what: str):
    deadline = time.monotonic() + _METRIC_BUDGET_S
    last = None
    while time.monotonic() < deadline:
        last = read()
        if done(last):
            return last
        time.sleep(_POLL_S)
    raise AssertionError(f"timed out after {_METRIC_BUDGET_S}s waiting for {what}; last {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
