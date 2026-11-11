"""obs-sfn-1-redrive-to-succeeded-counts-once-and-second-redrive-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-sfn-1-redrive-to-succeeded-counts-once-and-second-redrive-rejected"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "stepfunctions"]

_SETTLE_BUDGET_S = 420.0
_POLL_S = 10.0


# timing:real-time — metric: 53 s https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cw-metrics.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3",
    "timing:real-time",
)
def run(ctx) -> None:
    """A FAILED execution redriven to SUCCEEDED counts AWS/States Started 1, Failed 1, Redriven 1.

    A second redrive fails with ExecutionNotRedrivable and its exact message, and the counters hold.
    """
    sfn = ctx.client("stepfunctions")
    worker = ctx.client("stepfunctions", config=Config(read_timeout=75))
    cw = ctx.client("cloudwatch")

    activity = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-obs-sfn-act-"),
        tags=[{"key": "sim2real", "value": "1"}])["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=activity))
    role_arn = _states_role(ctx)
    sm_arn = _state_machine(ctx, sfn, role_arn, json.dumps({
        "StartAt": "Work", "States": {"Work": {"Type": "Task", "Resource": activity, "End": True}}}))

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    payload = {"order": 7}
    ex = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(payload))["executionArn"]
    ctx.on_cleanup(lambda: _stop_quiet(sfn, ex))

    task = _claim(worker, activity)
    assert json.loads(task["input"]) == payload, f"first task input {task['input']!r}"
    sfn.send_task_failure(taskToken=task["taskToken"], error="sim2real.Boom", cause="first life")
    failed = _wait_terminal(sfn, ex)
    assert failed["status"] == "FAILED", f"first life ended {failed['status']!r}, expected FAILED"
    assert failed.get("error") == "sim2real.Boom", f"first life error {failed.get('error')!r}"
    assert failed.get("redriveStatus") == "REDRIVABLE", (
        f"a FAILED standard execution must be REDRIVABLE; got {failed.get('redriveStatus')!r}")

    sfn.redrive_execution(executionArn=ex)
    task = _claim(worker, activity)
    assert json.loads(task["input"]) == payload, (
        f"the redriven Task must see the original input {payload!r}; got {task['input']!r}")
    sfn.send_task_success(taskToken=task["taskToken"], output=json.dumps({"done": True}))
    done = _wait_terminal(sfn, ex)
    assert done["status"] == "SUCCEEDED", f"redriven execution ended {done['status']!r}"
    assert done.get("redriveCount") == 1, f"redriveCount {done.get('redriveCount')!r}, expected 1"
    assert json.loads(done["output"]) == {"done": True}, f"output {done.get('output')!r}"

    code, message = _error(lambda: sfn.redrive_execution(executionArn=ex))
    assert code == "ExecutionNotRedrivable", (
        f"redriving a SUCCEEDED execution must be rejected ExecutionNotRedrivable; got {code!r}")
    assert message == (
        f"Execution {ex} invalid for redrive as: Execution is SUCCEEDED and cannot be redriven"
    ), f"ExecutionNotRedrivable message {message!r}"
    t_act = time.monotonic()
    again = sfn.describe_execution(executionArn=ex)
    assert (again["status"], again.get("redriveCount")) == ("SUCCEEDED", 1), (
        f"the rejected redrive changed the execution: {again['status']!r} "
        f"redriveCount={again.get('redriveCount')!r}")

    dims = [{"Name": "StateMachineArn", "Value": sm_arn}]
    want = {"ExecutionsStarted": 1.0, "ExecutionsFailed": 1.0, "ExecutionsSucceeded": 1.0,
            "ExecutionsRedriven": 1.0, "RedrivenExecutionsSucceeded": 1.0,
            "RedrivenExecutionsFailed": 0.0, "ExecutionsAborted": 0.0}
    _ledger(lambda: {m: _sum(cw, m, dims, window_start) for m in want}, want, t_act)


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("the call succeeded; real AWS rejects it")


def _claim(worker, activity: str, timeout_s: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        task = worker.get_activity_task(activityArn=activity, workerName="sim2real-worker")
        if task.get("taskToken"):
            return task
    raise AssertionError(f"no activity task for {activity} within {timeout_s}s")


def _states_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-obs-sfn-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Description="sim2real obs-sfn metrics ledger", Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _state_machine(ctx, sfn, role_arn: str, definition: str) -> str:
    name = ctx.unique_name("sim2real-behav-obs-sfn-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
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


def _stop_quiet(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


def _wait_terminal(sfn, arn: str, timeout_s: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {arn} still RUNNING after {timeout_s}s: {last!r}")


def _sum(cw, metric: str, dims: list, start) -> float:
    pts = cw.get_metric_statistics(
        Namespace="AWS/States", MetricName=metric, Dimensions=dims, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2), Period=60, Statistics=["Sum"],
    )["Datapoints"]
    return float(sum(p["Sum"] for p in pts))


def _ledger(read, want: dict, t_act: float) -> float:
    """Poll to `want` within the settle budget, then hold it for max(3x latency, 60 s)."""
    last = None
    while True:
        last = read()
        if last == want:
            break
        if time.monotonic() - t_act > _SETTLE_BUDGET_S:
            raise AssertionError(
                f"ledger did not reach {want!r} within {_SETTLE_BUDGET_S:.0f}s; last {last!r}")
        time.sleep(_POLL_S)
    latency = time.monotonic() - t_act
    # At least 3x the measured latency, which on real AWS already spans aggregation periods.
    hold_s = max(3.0 * latency, 10.0)
    print(f"[ledger] settled {latency:.0f}s after the last act; holding {hold_s:.0f}s")
    hold_until = time.monotonic() + hold_s
    while time.monotonic() < hold_until:
        time.sleep(_POLL_S)
        now = read()
        assert now == want, (
            f"ledger moved after settling at {latency:.0f}s: {now!r} != {want!r}")
    return latency


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
