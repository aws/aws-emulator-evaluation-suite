"""execution-metrics-reach-cloudwatch-under-the-state-machine-dimension."""
from __future__ import annotations

import datetime as dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execution-metrics-reach-cloudwatch-under-the-state-machine-dimension"
GROUP = "observability"
SERVICES = ["stepfunctions"]

_NAMESPACE = "AWS/States"
_METRIC_DEADLINE_S = 420.0
_METRIC_INTERVAL_S = 2.0
_CONTROL_HOLD_S = 6.0  # fixed absence window: at least 3 control samples at _METRIC_INTERVAL_S


# timing:real-time — workflow: 15 s https://docs.aws.amazon.com/step-functions/latest/dg/statemachine-structure.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Step Functions publishes AWS/States execution metrics whose Sum is exactly the
    executions this check drove, scoped to the StateMachineArn dimension — and a twin
    state machine that ran nothing has no datapoints under its own dimension."""
    cw = ctx.client("cloudwatch")
    _role_name, role_arn = _create_sfn_role(ctx)

    # The SUBJECT and the DIMENSION CONTROL are created from the same definition in the
    # same instant. Only the subject is ever executed, so any datapoint appearing under
    # the control's dimension proves the target is not keying metrics by state machine.
    subject_arn = _create_state_machine(ctx, role_arn, _DEFINITION)
    control_arn = _create_state_machine(ctx, role_arn, _DEFINITION)

    # 3 successes (one slow, to give ExecutionTime a known floor), 2 failures, 1 timeout.
    modes = ["ok", "ok", "slow", "boom", "boom", "stall"]
    window_start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=2)
    # All six run at once; each is awaited in mode order, so the status list stays positional.
    exec_arns = [_start(ctx, subject_arn, {"mode": mode}) for mode in modes]
    terminals = [
        _wait_terminal(ctx, exec_arn, timeout_s=_budget_s(ctx, 180.0)) for exec_arn in exec_arns
    ]

    statuses = [t["status"] for t in terminals]
    assert statuses == [
        "SUCCEEDED",
        "SUCCEEDED",
        "SUCCEEDED",
        "FAILED",
        "FAILED",
        "TIMED_OUT",
    ], (
        "the six driven executions must land SUCCEEDED,SUCCEEDED,SUCCEEDED,FAILED,"
        f"FAILED,TIMED_OUT so the metric Sums below are known exactly; got {statuses}"
    )

    # Longest execution wall-clock from the reported dates: the upper bound ExecutionTime
    # must respect.
    measured_max_ms = max(
        (t["stopDate"] - t["startDate"]).total_seconds() * 1000.0 for t in terminals
    )
    driven_at = time.monotonic()

    # --- ExecutionsSucceeded: exactly 3 under the subject's dimension ------------------
    succeeded, _ = _await_metric_sum(
        ctx,
        cw,
        "ExecutionsSucceeded",
        subject_arn,
        window_start,
        want_at_least=3.0,
        driven_at=driven_at,
    )
    assert succeeded["sum"] == 3.0, (
        "AWS/States ExecutionsSucceeded Sum for dimension StateMachineArn="
        f"{subject_arn} must be exactly 3.0 (three successful executions were driven "
        f"and no others exist for this freshly created state machine); got "
        f"{succeeded['sum']}"
    )
    assert succeeded["unit"] == "Count", (
        f"ExecutionsSucceeded datapoints must carry Unit 'Count'; got "
        f"{succeeded['unit']!r}"
    )

    # --- ExecutionsFailed: exactly 2, and a timeout is NOT counted as a failure --------
    failed, _ = _await_metric_sum(
        ctx, cw, "ExecutionsFailed", subject_arn, window_start, want_at_least=2.0,
        driven_at=driven_at,
    )
    assert failed["sum"] == 2.0, (
        "AWS/States ExecutionsFailed Sum must be exactly 2.0 — the two Fail-state "
        "executions only; the TIMED_OUT execution belongs to ExecutionsTimedOut. Got "
        f"{failed['sum']}"
    )
    assert failed["unit"] == "Count", (
        f"ExecutionsFailed datapoints must carry Unit 'Count'; got {failed['unit']!r}"
    )

    timed_out, _ = _await_metric_sum(
        ctx, cw, "ExecutionsTimedOut", subject_arn, window_start, want_at_least=1.0,
        driven_at=driven_at,
    )
    assert timed_out["sum"] == 1.0, (
        "AWS/States ExecutionsTimedOut Sum must be exactly 1.0 for the single "
        f"execution-level TimeoutSeconds expiry that was driven; got {timed_out['sum']}"
    )

    # --- ExecutionTime: two-sided, floored by the ASL Wait, capped by the live clock ---
    exec_time = _metric_stats(
        cw, "ExecutionTime", subject_arn, window_start, stats=["Maximum"]
    )
    assert exec_time["datapoints"], (
        "AWS/States ExecutionTime must have at least one datapoint for dimension "
        f"StateMachineArn={subject_arn} after six executions; got none"
    )
    observed_max_ms = max(d["Maximum"] for d in exec_time["datapoints"])
    assert observed_max_ms >= 15000.0, (
        "ExecutionTime Maximum must be at least 15000ms because one execution ran a "
        f"Wait of {_SLOW_WAIT_SECONDS}s before succeeding; got {observed_max_ms:.0f}ms"
    )
    assert observed_max_ms <= measured_max_ms + 5000.0, (
        "ExecutionTime Maximum must not exceed the longest wall-clock this check "
        f"actually measured from DescribeExecution ({measured_max_ms:.0f}ms) plus 5000ms "
        f"of aggregation slack; got {observed_max_ms:.0f}ms"
    )
    assert exec_time["unit"] == "Milliseconds", (
        f"ExecutionTime datapoints must carry Unit 'Milliseconds'; got "
        f"{exec_time['unit']!r}"
    )

    # --- The dimension actually discriminates ------------------------------------------
    # The subject's datapoints from the same executions are already visible, so a datapoint misfiled
    # under the control would be visible too. Sample the control's absence over a fixed window, and
    # back the empty datapoint list with a second, independent observable: ListMetrics.
    hold_until = time.monotonic() + _CONTROL_HOLD_S
    while True:
        control = _metric_stats(
            cw, "ExecutionsSucceeded", control_arn, window_start, stats=["Sum"]
        )
        assert not control["datapoints"], (
            "the never-executed twin state machine must have NO AWS/States "
            f"ExecutionsSucceeded datapoints under StateMachineArn={control_arn}; got "
            f"{control['datapoints']!r} — the target is not scoping metrics by state "
            "machine"
        )
        if time.monotonic() >= hold_until:
            break
        time.sleep(_METRIC_INTERVAL_S)

    listed = cw.list_metrics(
        Namespace=_NAMESPACE,
        Dimensions=[{"Name": "StateMachineArn", "Value": control_arn}],
    )["Metrics"]
    assert listed == [], (
        "ListMetrics must report no AWS/States metric for the never-executed twin's "
        f"StateMachineArn={control_arn}; got {[m['MetricName'] for m in listed]}"
    )

    subject_listed = {
        m["MetricName"]
        for m in cw.list_metrics(
            Namespace=_NAMESPACE,
            Dimensions=[{"Name": "StateMachineArn", "Value": subject_arn}],
        )["Metrics"]
    }
    missing = {"ExecutionsSucceeded", "ExecutionsFailed", "ExecutionTime"} - subject_listed
    assert not missing, (
        "ListMetrics must report every driven AWS/States metric for the executed state "
        f"machine's dimension; {sorted(missing)} were absent from {sorted(subject_listed)}"
    )


_SLOW_WAIT_SECONDS = 5
# TimeoutSeconds is an EXECUTION-level cap: it bounds every mode through this one
# definition, not just Stall, so it must clear _SLOW_WAIT_SECONDS with margin for Choice/Pass transitions, while staying
# far under Stall's 300s Wait so Stall still times out promptly.
_EXECUTION_TIMEOUT_SECONDS = 15

# One definition, six behaviours selected by $.mode, so every metric below is driven
# through the SAME state machine ARN and the Sums are known exactly.
_DEFINITION = json.dumps(
    {
        "Comment": "metric fan of outcomes for one state machine dimension",
        "StartAt": "Route",
        "TimeoutSeconds": _EXECUTION_TIMEOUT_SECONDS,
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.mode", "StringEquals": "boom", "Next": "Boom"},
                    {"Variable": "$.mode", "StringEquals": "slow", "Next": "Slow"},
                    {"Variable": "$.mode", "StringEquals": "stall", "Next": "Stall"},
                ],
                "Default": "Ok",
            },
            "Ok": {"Type": "Pass", "Result": {"ok": True}, "End": True},
            # Succeeds after a real wait, giving ExecutionTime a floor.
            "Slow": {"Type": "Wait", "Seconds": _SLOW_WAIT_SECONDS, "Next": "Ok"},
            # Runs past the state machine's own TimeoutSeconds -> TIMED_OUT.
            "Stall": {"Type": "Wait", "Seconds": 300, "Next": "Ok"},
            "Boom": {
                "Type": "Fail",
                "Error": "MetricBoom",
                "Cause": "deliberate failure so ExecutionsFailed has a known Sum",
            },
        },
    }
)

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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_sfn_role(ctx) -> tuple[str, str]:
    """A states.amazonaws.com role this check creates itself, so nothing is named that
    the check did not make. Pass/Wait/Fail/Choice need no downstream grants."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnmetric-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Path="/sim2real/",
        Description="SimParity draft: sfn execution metrics",
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


def _create_state_machine(ctx, role_arn: str, definition: str) -> str:
    """CreateStateMachine, bounded-retrying only the AccessDeniedException that the
    freshly created role's PassRole grant raises until it propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnmetric-")
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
        f"CreateStateMachine still AccessDenied 120s after creating the role that "
        f"grants it; the PassRole grant never propagated. Last error: {last}"
    )


def _start(ctx, sm_arn: str, payload: dict) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps(payload)
    )["executionArn"]
    ctx.on_cleanup(lambda a=exec_arn: sfn.stop_execution(executionArn=a))
    return exec_arn


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float) -> dict:
    """Poll DescribeExecution until the execution leaves RUNNING. Raises on timeout —
    the caller, not this helper, decides which terminal status is correct."""
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
        f"execution {exec_arn} was still RUNNING after {timeout_s}s; the longest state "
        f"in this definition is a {_SLOW_WAIT_SECONDS}s Wait. Last: {last!r}"
    )


def _metric_stats(cw, metric: str, sm_arn: str, window_start, *, stats) -> dict:
    resp = cw.get_metric_statistics(
        Namespace=_NAMESPACE,
        MetricName=metric,
        Dimensions=[{"Name": "StateMachineArn", "Value": sm_arn}],
        StartTime=window_start,
        EndTime=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=2),
        Period=60,
        Statistics=stats,
    )
    points = resp["Datapoints"]
    units = {d["Unit"] for d in points if "Unit" in d}
    return {
        "datapoints": points,
        "sum": sum(d["Sum"] for d in points) if points and "Sum" in stats else 0.0,
        "unit": units.pop() if len(units) == 1 else sorted(units),
    }


def _await_metric_sum(
    ctx, cw, metric: str, sm_arn: str, window_start, *, want_at_least: float, driven_at
) -> tuple[dict, float]:
    """Bounded poll until the metric Sum reaches want_at_least, because CloudWatch
    aggregates AWS/States on a ~1 minute cadence and publishes asynchronously. Returns
    the reading plus the delivery latency."""
    deadline = time.monotonic() + _budget_s(ctx, _METRIC_DEADLINE_S)
    last = None
    while time.monotonic() < deadline:
        last = _metric_stats(cw, metric, sm_arn, window_start, stats=["Sum"])
        if last["sum"] >= want_at_least:
            return last, max(time.monotonic() - driven_at, 1.0)
        time.sleep(_METRIC_INTERVAL_S)
    if _budget_spent(ctx):
        raise TimeoutError(f"AWS/States {metric} Sum reaching {want_at_least}: the run budget ended first; not graded")
    raise AssertionError(
        f"AWS/States {metric} Sum for StateMachineArn={sm_arn} never reached "
        f"{want_at_least} within {_METRIC_DEADLINE_S}s of the executions closing; last "
        f"reading was {last['sum'] if last else 'none'} over "
        f"{len(last['datapoints']) if last else 0} datapoints"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
