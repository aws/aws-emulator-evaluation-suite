"""metrics-states-consumed-capacity-counts-start-execution-api-calls."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-states-consumed-capacity-counts-start-execution-api-calls"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "stepfunctions"]

_N_START = 12
_N_DESCRIBE = 9
_SETTLE_BUDGET_S = 180.0
_POLL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


# timing:real-time — metric: 7 s https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cw-metrics.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:metrics",
    "dp:api",
    "plane:data",
    "cap:c3",
    "timing:real-time",
)
def run(ctx) -> None:
    """ConsumedCapacity[APIName=StartExecution] in AWS/States sums to at least the number of
    StartExecution calls made, with a Maximum of one unit per request, and
    ConsumedCapacity[APIName=DescribeStateMachine] counts DescribeStateMachine calls likewise.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cw-metrics.html
    """
    sfn = ctx.client("stepfunctions")
    cw = ctx.client("cloudwatch")

    role_arn = _states_role(ctx)
    name = ctx.unique_name("sim2real-behav-obs-sfn-cc-")
    sm_arn = _create_state_machine(ctx, sfn, name, role_arn)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    t_act = datetime.now(timezone.utc)
    started = []
    for i in range(_N_START):
        arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name(f"sim2real-cc-exec-{i}-"), input="{}",
        )["executionArn"]
        started.append(arn)
    for arn in started:
        ctx.on_cleanup(lambda arn=arn: _stop_quiet(sfn, arn))

    for _ in range(_N_DESCRIBE):
        sfn.describe_state_machine(stateMachineArn=sm_arn)

    se_dims = [{"Name": "APIName", "Value": "StartExecution"}]
    ds_dims = [{"Name": "APIName", "Value": "DescribeStateMachine"}]

    se_sum, se_pts = _poll_sum_at_least(ctx, cw, se_dims, t_act, _N_START)
    assert se_sum >= _N_START, (
        f"ConsumedCapacity[APIName=StartExecution] summed {se_sum!r} over the window since the "
        f"{_N_START} StartExecution calls; expected at least {_N_START}")
    assert all(p["Maximum"] == 1.0 for p in se_pts), (
        f"ConsumedCapacity reports more than one unit for a single StartExecution request in a "
        f"datapoint: {se_pts!r}")

    # A distinct APIName value counts its own calls, proving the dimension distinguishes APIs
    # rather than folding every call into one series.
    ds_sum, _ = _poll_sum_at_least(ctx, cw, ds_dims, t_act, _N_DESCRIBE)
    assert ds_sum >= _N_DESCRIBE, (
        f"ConsumedCapacity[APIName=DescribeStateMachine] summed {ds_sum!r} over the window since "
        f"the {_N_DESCRIBE} DescribeStateMachine calls; expected at least {_N_DESCRIBE}")


def _states_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-obs-sfn-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole"}]}),
        Description="sim2real obs-sfn consumed-capacity", Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, sfn, name: str, role_arn: str) -> str:
    definition = json.dumps({"StartAt": "Mark", "States": {
        "Mark": {"Type": "Pass", "End": True}}})
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    last = None
    while time.monotonic() < deadline:
        try:
            return sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)  # IAM propagation of the fresh role: no observable to poll
    if _budget_spent(ctx):
        raise TimeoutError("CreateStateMachine past the fresh role's AccessDenied: the run budget ended first; not graded")
    raise AssertionError(f"CreateStateMachine AccessDenied for up to 120s after role create: {last}")


def _stop_quiet(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


def _read_sum(cw, dims: list, start) -> tuple[float, list]:
    pts = cw.get_metric_statistics(
        Namespace="AWS/States", MetricName="ConsumedCapacity", Dimensions=dims,
        StartTime=start, EndTime=datetime.now(timezone.utc) + timedelta(minutes=2),
        Period=60, Statistics=["Sum", "Maximum"],
    )["Datapoints"]
    return sum(p["Sum"] for p in pts), pts


def _poll_sum_at_least(ctx, cw, dims: list, start, want: float) -> tuple[float, list]:
    """Poll the summed ConsumedCapacity over ``[start, now]`` until it reaches at least ``want``.

    A lower bound, never an exact match: the account is shared with other concurrent activity, so
    another StartExecution or DescribeStateMachine call anywhere in it can only add to this series.
    """
    deadline = time.monotonic() + _budget_s(ctx, _SETTLE_BUDGET_S)
    total, pts = 0.0, []
    while True:
        total, pts = _read_sum(cw, dims, start)
        if total >= want:
            return total, pts
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"ConsumedCapacity{dims!r} to reach at least {want!r}: the run budget ended "
                    f"first; not graded")
            raise AssertionError(
                f"ConsumedCapacity{dims!r} did not reach at least {want!r} within "
                f"{_SETTLE_BUDGET_S:.0f}s; last summed {total!r}: {pts!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
