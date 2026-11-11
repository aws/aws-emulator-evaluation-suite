"""obs-sfn-1-double-stop-aborts-once-per-execution-and-failed-stays-zero."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-sfn-1-double-stop-aborts-once-per-execution-and-failed-stays-zero"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "stepfunctions"]

_SETTLE_BUDGET_S = 420.0
_POLL_S = 10.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cw-metrics.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "cap:c3",
    "timing:real-time",
)
def run(ctx) -> None:
    """Stopping one execution twice and another once counts exactly two aborts: the repeat stop
    returns the original stopDate, and AWS/States settles at ExecutionsStarted 2, ExecutionsAborted
    2 and Failed, Succeeded and TimedOut 0."""
    sfn = ctx.client("stepfunctions")
    cw = ctx.client("cloudwatch")

    role_arn = _states_role(ctx)
    sm_arn = _state_machine(ctx, sfn, role_arn, json.dumps({
        "StartAt": "Hold", "States": {"Hold": {"Type": "Wait", "Seconds": 600, "End": True}}}))

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    first = _start(ctx, sfn, sm_arn)
    second = _start(ctx, sfn, sm_arn)
    for arn in (first, second):
        _wait_running(sfn, arn)

    stop1 = sfn.stop_execution(executionArn=first, error="sim2real.FirstStop", cause="first")
    stop2 = sfn.stop_execution(executionArn=first, error="sim2real.SecondStop", cause="second")
    assert stop2["stopDate"] == stop1["stopDate"], (
        f"a repeat StopExecution must not re-stop the execution: stopDate moved "
        f"{stop1['stopDate']!r} -> {stop2['stopDate']!r}"
    )
    sfn.stop_execution(executionArn=second)
    t_act = time.monotonic()

    d1 = sfn.describe_execution(executionArn=first)
    assert d1["status"] == "ABORTED", f"stopped execution status {d1['status']!r}, expected ABORTED"
    assert (d1.get("error"), d1.get("cause")) == ("sim2real.FirstStop", "first"), (
        f"the FIRST stop's error/cause must survive the repeat stop; got "
        f"{(d1.get('error'), d1.get('cause'))!r}"
    )
    d2 = sfn.describe_execution(executionArn=second)
    assert d2["status"] == "ABORTED", f"second execution status {d2['status']!r}, expected ABORTED"

    dims = [{"Name": "StateMachineArn", "Value": sm_arn}]
    metrics = ("ExecutionsStarted", "ExecutionsAborted", "ExecutionsFailed",
               "ExecutionsSucceeded", "ExecutionsTimedOut")
    want = {"ExecutionsStarted": 2.0, "ExecutionsAborted": 2.0, "ExecutionsFailed": 0.0,
            "ExecutionsSucceeded": 0.0, "ExecutionsTimedOut": 0.0}
    _ledger(lambda: {m: _sum(cw, m, dims, window_start) for m in metrics}, want, t_act)


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


def _start(ctx, sfn, sm_arn: str) -> str:
    arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    ctx.on_cleanup(lambda: _stop_quiet(sfn, arn))
    return arn


def _stop_quiet(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


def _wait_running(sfn, arn: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=arn)
        if last["status"] == "RUNNING":
            return
        time.sleep(1.0)
    raise AssertionError(f"execution {arn} never observed RUNNING: {last!r}")


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
    # At least 3x the measured latency, and never less than one 60 s aggregation period.
    hold_s = max(3.0 * latency, 60.0)
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
