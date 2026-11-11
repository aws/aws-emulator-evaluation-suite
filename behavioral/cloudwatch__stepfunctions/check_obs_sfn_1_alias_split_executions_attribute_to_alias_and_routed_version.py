"""obs-sfn-1-alias-split-executions-attribute-to-alias-and-routed-version."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-sfn-1-alias-split-executions-attribute-to-alias-and-routed-version"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "stepfunctions"]

_SETTLE_BUDGET_S = 420.0
_POLL_S = 2.0
_N = 6
#: How long the settled ledger must then hold unchanged.
_HOLD_S = 10.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


# timing:real-time — metric: 15 s https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cw-metrics.html
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
    """Executions through a 50/50 alias count in AWS/States under the alias and the routed version.

    Per-version ExecutionsStarted equals the split DescribeExecution reported; AliasCount 1 and
    VersionCount 2 under [ResourceArn].
    """
    sfn = ctx.client("stepfunctions")
    cw = ctx.client("cloudwatch")

    role_arn = _states_role(ctx)
    name = ctx.unique_name("sim2real-behav-obs-sfn-alias-")
    created = _create_published(ctx, sfn, name, role_arn, _definition("v1"))
    sm_arn, v1 = created["stateMachineArn"], created["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v1))
    v2 = sfn.update_state_machine(
        stateMachineArn=sm_arn, definition=_definition("v2"), publish=True,
    )["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v2))
    alias_arn = sfn.create_state_machine_alias(
        name="live", description="sim2real 50/50",
        routingConfiguration=[{"stateMachineVersionArn": v1, "weight": 50},
                              {"stateMachineVersionArn": v2, "weight": 50}],
    )["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn))
    assert alias_arn == f"{sm_arn}:live", f"alias ARN {alias_arn!r} is not {sm_arn}:live"

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    execs = []
    for _ in range(_N):
        arn = sfn.start_execution(stateMachineArn=alias_arn, input="{}")["executionArn"]
        ctx.on_cleanup(lambda arn=arn: _stop_quiet(sfn, arn))
        execs.append(arn)
    # Alias routing is weighted-random, so the expected per-version split is what each run reports.
    routed = {v1: 0, v2: 0}
    for arn in execs:
        d = _wait_terminal(ctx, sfn, arn, _budget_s(ctx, 120.0))
        assert d["status"] == "SUCCEEDED", f"{arn} ended {d['status']!r}"
        assert d.get("stateMachineAliasArn") == alias_arn, (
            f"execution started through the alias reports alias {d.get('stateMachineAliasArn')!r}")
        ver = d.get("stateMachineVersionArn")
        assert ver in routed, f"execution routed to {ver!r}, not one of {sorted(routed)!r}"
        expect = "v1" if ver == v1 else "v2"
        assert json.loads(d["output"]) == expect, (
            f"execution routed to {ver!r} ran the wrong definition: output {d.get('output')!r}")
        routed[ver] += 1
    t_act = time.monotonic()
    assert sum(routed.values()) == _N, f"routed {routed!r}"

    sm_d = [{"Name": "StateMachineArn", "Value": sm_arn}]
    alias_d = sm_d + [{"Name": "Alias", "Value": "live"}]
    v1_d = sm_d + [{"Name": "Version", "Value": v1.rsplit(":", 1)[-1]}]
    v2_d = sm_d + [{"Name": "Version", "Value": v2.rsplit(":", 1)[-1]}]
    res_d = [{"Name": "ResourceArn", "Value": sm_arn}]
    want = {
        "Started[sm]": float(_N), "Started[alias]": float(_N),
        "Started[v1]": float(routed[v1]), "Started[v2]": float(routed[v2]),
        "Succeeded[alias]": float(_N),
        "AliasCount max": 1.0, "VersionCount max": 2.0,
    }

    def _read() -> dict:
        return {
            "Started[sm]": _stat(cw, "ExecutionsStarted", sm_d, window_start, "Sum"),
            "Started[alias]": _stat(cw, "ExecutionsStarted", alias_d, window_start, "Sum"),
            "Started[v1]": _stat(cw, "ExecutionsStarted", v1_d, window_start, "Sum"),
            "Started[v2]": _stat(cw, "ExecutionsStarted", v2_d, window_start, "Sum"),
            "Succeeded[alias]": _stat(cw, "ExecutionsSucceeded", alias_d, window_start, "Sum"),
            "AliasCount max": _stat(cw, "AliasCount", res_d, window_start, "Maximum"),
            "VersionCount max": _stat(cw, "VersionCount", res_d, window_start, "Maximum"),
        }

    _ledger(ctx, _read, want, t_act)


def _definition(result: str) -> str:
    return json.dumps({"StartAt": "Mark", "States": {
        "Mark": {"Type": "Pass", "Result": result, "End": True}}})


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


def _create_published(ctx, sfn, name: str, role_arn: str, definition: str) -> dict:
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    last = None
    while time.monotonic() < deadline:
        try:
            return sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                publish=True, tags=[{"key": "sim2real", "value": "1"}],
            )
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


def _wait_terminal(ctx, sfn, arn: str, timeout_s: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"execution {arn} terminal: the run budget ended first; not graded")
    raise AssertionError(f"execution {arn} still RUNNING after {timeout_s}s: {last!r}")


def _stat(cw, metric: str, dims: list, start, stat: str) -> float:
    pts = cw.get_metric_statistics(
        Namespace="AWS/States", MetricName=metric, Dimensions=dims, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2), Period=60, Statistics=[stat],
    )["Datapoints"]
    if stat == "Maximum":
        return float(max((p["Maximum"] for p in pts), default=0.0))
    return float(sum(p[stat] for p in pts))


def _ledger(ctx, read, want: dict, t_act: float) -> float:
    """Poll to `want` within the settle budget, then hold it for _HOLD_S."""
    last = None
    deadline = time.monotonic() + _budget_s(ctx, t_act + _SETTLE_BUDGET_S - time.monotonic())
    while True:
        last = read()
        if last == want:
            break
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"ledger to reach {want!r}: the run budget ended first; not graded")
            raise AssertionError(
                f"ledger did not reach {want!r} within {_SETTLE_BUDGET_S:.0f}s; last {last!r}")
        time.sleep(_POLL_S)
    latency = time.monotonic() - t_act
    hold_s = _HOLD_S
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
