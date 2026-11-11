"""metrics-states-stream-activity-metrics-attribute-worker-outcomes-to-the-activity-arn-series."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-states-stream-activity-metrics-attribute-worker-outcomes-to-the-activity-arn-series"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "stepfunctions"]

_NAMESPACE = "AWS/States"
_METRIC_BUDGET_S = 600.0
_POLL_S = 10.0


# timing:real-time — metric: 13 s https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cw-metrics.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """A worker that completes one task and fails another moves AWS/States [ActivityArn] counters.

    Scheduled/Started 2, Succeeded/Failed 1; the [StateMachineArn] series reads the executions, and
    activity counters appear neither under the state machine nor under a never-polled twin activity.
    """
    sfn = ctx.client("stepfunctions")
    cw = ctx.client("cloudwatch")

    role_arn = _states_role(ctx)
    activity = _activity(ctx, sfn, "subj-")
    twin = _activity(ctx, sfn, "twin-")
    definition = json.dumps({
        "StartAt": "Work",
        "States": {"Work": {"Type": "Task", "Resource": activity, "TimeoutSeconds": 300,
                            "End": True}},
    })
    sm_arn = _state_machine(ctx, sfn, role_arn, definition)

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)

    # Execution 1: the worker completes the task.
    ex_ok = _start(ctx, sfn, sm_arn, {"mode": "ok"})
    task = _poll_task(ctx, sfn, activity)
    assert json.loads(task["input"]) == {"mode": "ok"}, (
        f"GetActivityTask handed the worker input {task['input']!r}; expected the execution's "
        "input {'mode': 'ok'}"
    )
    sfn.send_task_success(taskToken=task["taskToken"], output=json.dumps({"done": True}))
    ok = _wait_terminal(sfn, ex_ok)
    assert ok["status"] == "SUCCEEDED", f"completed-task execution ended {ok['status']!r}"
    assert json.loads(ok["output"]) == {"done": True}, (
        f"execution output {ok.get('output')!r} is not the worker's SendTaskSuccess output"
    )

    # Execution 2: the worker fails the task.
    ex_bad = _start(ctx, sfn, sm_arn, {"mode": "boom"})
    task = _poll_task(ctx, sfn, activity)
    sfn.send_task_failure(taskToken=task["taskToken"], error="WorkerBoom", cause="deliberate")
    bad = _wait_terminal(sfn, ex_bad)
    assert bad["status"] == "FAILED", f"failed-task execution ended {bad['status']!r}"
    assert bad.get("error") == "WorkerBoom", (
        f"execution error is {bad.get('error')!r}; expected the worker's own 'WorkerBoom'"
    )

    act_dims = [{"Name": "ActivityArn", "Value": activity}]
    sm_dims = [{"Name": "StateMachineArn", "Value": sm_arn}]
    want = {
        ("act", "ActivitiesScheduled"): 2.0,
        ("act", "ActivitiesStarted"): 2.0,
        ("act", "ActivitiesSucceeded"): 1.0,
        ("act", "ActivitiesFailed"): 1.0,
        ("sm", "ExecutionsStarted"): 2.0,
        ("sm", "ExecutionsSucceeded"): 1.0,
        ("sm", "ExecutionsFailed"): 1.0,
    }
    dims = {"act": act_dims, "sm": sm_dims}

    def _read():
        return {k: _sum(cw, k[1], dims[k[0]], window_start) for k in want}

    got = _poll(_read, lambda r: r == want, "AWS/States activity and execution sums "
                f"to reach {want!r}")
    assert got == want, f"settled sums {got!r} != expected {want!r}"

    run_time = _stats(cw, "ActivityRunTime", act_dims, window_start, "SampleCount")
    assert sum(d["SampleCount"] for d in run_time) == 2.0, (
        "ActivityRunTime under [ActivityArn] must carry one sample per started task (2); got "
        f"{run_time!r}"
    )

    # Series-family separation, read AFTER the positive family arrived (the barrier above).
    for metric in ("ActivitiesSucceeded", "ActivitiesScheduled"):
        leaked = _stats(cw, metric, sm_dims, window_start, "Sum")
        assert leaked == [], (
            f"{metric} must not be published under Dimensions [StateMachineArn]; it is an "
            f"ActivityArn-family metric. Got {leaked!r}"
        )
        combined = _stats(cw, metric, sm_dims + act_dims, window_start, "Sum")
        assert combined == [], (
            f"{metric} must not be published under the combined [StateMachineArn, ActivityArn] "
            f"set; the families are separate. Got {combined!r}"
        )
    twin_pts = _stats(cw, "ActivitiesScheduled", [{"Name": "ActivityArn", "Value": twin}],
                      window_start, "Sum")
    assert twin_pts == [], (
        f"the never-used twin activity {twin} has ActivitiesScheduled datapoints {twin_pts!r}; "
        "the target is not keying activity metrics by ActivityArn"
    )
    leaked = _stats(cw, "ExecutionsSucceeded", act_dims, window_start, "Sum")
    assert leaked == [], (
        f"ExecutionsSucceeded must not be published under [ActivityArn]; got {leaked!r}"
    )


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


def _states_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnact-role-")
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
    name = ctx.unique_name("sim2real-behav-sfnact-")
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


def _start(ctx, sfn, sm_arn: str, payload: dict) -> str:
    arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(payload))["executionArn"]
    ctx.on_cleanup(lambda: _stop_quiet(sfn, arn))
    return arn


def _stop_quiet(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


def _poll_task(ctx, sfn, activity: str) -> dict:
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
