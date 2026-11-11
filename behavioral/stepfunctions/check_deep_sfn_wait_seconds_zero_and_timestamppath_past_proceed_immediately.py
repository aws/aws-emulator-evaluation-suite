"""deep-sfn-wait-seconds-zero-and-timestamppath-past-proceed-immediately."""
from __future__ import annotations

import datetime as dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-wait-seconds-zero-and-timestamppath-past-proceed-immediately"
GROUP = "wait_state"
SERVICES = ["stepfunctions"]

_FUTURE_OFFSET_S = 20
_START_SLACK_S = 5.0  # second truncation of the target plus CreateStateMachine/StartExecution latency
_LATE_SLACK_S = 6.0   # how long after the target instant the Wait may still be exiting


# timing:real-time — workflow: 20 s https://docs.aws.amazon.com/step-functions/latest/dg/state-wait.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Wait with `Seconds: 0`, and one whose `TimestampPath` is already past, each proceed
    immediately: they sit in the Wait under half as long as a twin whose `TimestampPath` lies
    ~20 s ahead, which genuinely waits for that instant.
    """
    role_arn = _sfn_role(ctx)

    # --- Literal Seconds: 0.
    zero_definition = {
        "StartAt": "W",
        "States": {
            "W": {"Type": "Wait", "Seconds": 0, "Next": "Done"},
            "Done": {"Type": "Pass", "Result": "zero", "End": True},
        },
    }
    zero_sm = _create_state_machine(ctx, role_arn, zero_definition)
    zero_exec = _start(ctx, zero_sm, {})
    zero_desc = _wait_terminal(ctx, zero_exec)
    assert zero_desc["status"] == "SUCCEEDED", (
        f"a Wait with Seconds=0 must SUCCEED; got {zero_desc['status']!r} "
        f"error={zero_desc.get('error')!r} cause={zero_desc.get('cause')!r}"
    )
    assert json.loads(zero_desc["output"]) == "zero", (
        f"the Seconds=0 execution's output must be the Pass result; got {zero_desc['output']!r}"
    )
    z_in, z_out = _state_span(_history(ctx, zero_exec), "W")
    z_held = (z_out - z_in).total_seconds()

    # --- TimestampPath: future (genuine-wait control) and past (proceeds immediately) twins.
    tp_definition = {
        "StartAt": "W",
        "States": {
            "W": {"Type": "Wait", "TimestampPath": "$.until", "Next": "Done"},
            "Done": {"Type": "Pass", "End": True},
        },
    }
    tp_sm = _create_state_machine(ctx, role_arn, tp_definition)

    now = dt.datetime.now(dt.timezone.utc)
    past = (now - dt.timedelta(hours=1)).replace(microsecond=0)
    past_iso = past.strftime("%Y-%m-%dT%H:%M:%SZ")
    past_exec = _start(ctx, tp_sm, {"until": past_iso})

    future = (dt.datetime.now(dt.timezone.utc)
              + dt.timedelta(seconds=_FUTURE_OFFSET_S)).replace(microsecond=0)
    future_iso = future.strftime("%Y-%m-%dT%H:%M:%SZ")
    future_exec = _start(ctx, tp_sm, {"until": future_iso})
    started = dt.datetime.now(dt.timezone.utc)
    assert (future - started).total_seconds() > _FUTURE_OFFSET_S - _START_SLACK_S, (
        f"the future twin must start with ~{_FUTURE_OFFSET_S}s still to wait; only "
        f"{(future - started).total_seconds():.2f}s remained at start"
    )

    past_desc = _wait_terminal(ctx, past_exec)
    future_desc = _wait_terminal(ctx, future_exec)
    for label, desc, iso in (("past", past_desc, past_iso), ("future", future_desc, future_iso)):
        assert desc["status"] == "SUCCEEDED", (
            f"the {label}-TimestampPath execution must SUCCEED; got {desc['status']!r} "
            f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
        )
        assert json.loads(desc["output"]) == {"until": iso}, (
            f"the {label} twin's output must name its own `until`; got {desc['output']!r}"
        )

    p_in, p_out = _state_span(_history(ctx, past_exec), "W")
    p_held = (p_out - p_in).total_seconds()

    f_in, f_out = _state_span(_history(ctx, future_exec), "W")
    early = (future - f_out).total_seconds()
    assert f_out >= future, (
        f'a Wait whose TimestampPath resolves to "{future_iso}" must not exit before that '
        f"instant; history says it exited at {f_out.isoformat()}, {early:.2f}s early"
    )
    late = (f_out - future).total_seconds()
    assert late < _LATE_SLACK_S, (
        f'a Wait whose TimestampPath resolves to "{future_iso}" must exit within '
        f"{_LATE_SLACK_S}s of it; history says it exited {late:.2f}s late"
    )
    held = (f_out - f_in).total_seconds()
    assert held >= _FUTURE_OFFSET_S - _START_SLACK_S, (
        f"the future twin must genuinely wait ~{_FUTURE_OFFSET_S}s; it sat in the Wait {held:.2f}s"
    )
    assert held < _FUTURE_OFFSET_S + _LATE_SLACK_S, (
        f"the future twin must not wait far beyond ~{_FUTURE_OFFSET_S}s; it sat there {held:.2f}s"
    )

    # The future twin's measured dwell is the control: proceeding immediately means sitting in
    # the Wait for well under half of it.
    assert z_held < held / 2, (
        f"a Wait with Seconds=0 must proceed immediately; it sat in the Wait {z_held:.2f}s, "
        f"not well under the {held:.2f}s the future-TimestampPath twin waited"
    )
    assert p_held < held / 2, (
        f'a Wait whose TimestampPath resolves to "{past_iso}" (an hour ago) must proceed '
        f"immediately; it sat in the Wait {p_held:.2f}s, not well under the {held:.2f}s the "
        f"future-TimestampPath twin waited"
    )


_TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=1.0, description="condition", ctx=None):
    """A bounded retry that RAISES on its deadline; never returns a stale value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _sfn_role(ctx) -> str:
    """A role Step Functions can assume. These definitions call no other service, so it needs no
    permissions policy at all."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-sfn-interp-role-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Description=f"sim2real {CHECK}",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn, definition, **extra) -> str:
    """CreateStateMachine, bounded-retrying only the AccessDeniedException raised while the fresh
    role's trust propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sfn-interp-sm-")
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}], **extra,
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                if exc.response["Error"]["Code"] == "AccessDeniedException" and _budget_spent(ctx):
                    raise TimeoutError("CreateStateMachine accepting the fresh role: the run budget ended first; "
                                       "not graded") from exc
                raise
            time.sleep(2.0)


def _start(ctx, sm_arn, payload) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(payload))["executionArn"]

    def _stop():
        if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
            sfn.stop_execution(executionArn=exec_arn)

    ctx.on_cleanup(_stop)
    return exec_arn


def _wait_terminal(ctx, exec_arn, timeout_s=150.0) -> dict:
    sfn = ctx.client("stepfunctions")
    return _poll_until(lambda: sfn.describe_execution(executionArn=exec_arn),
                       lambda d: d["status"] != "RUNNING", timeout_s=_budget_s(ctx, timeout_s),
                       description=f"execution {exec_arn} leaving RUNNING", ctx=ctx)


def _history(ctx, exec_arn) -> list:
    sfn = ctx.client("stepfunctions")
    events, kwargs = [], {"executionArn": exec_arn}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if not resp.get("nextToken"):
            return sorted(events, key=lambda e: e["id"])
        kwargs["nextToken"] = resp["nextToken"]


def _entered(events, state) -> list:
    return [e for e in events if e.get("stateEnteredEventDetails", {}).get("name") == state]


def _exited(events, state) -> list:
    return [e for e in events if e.get("stateExitedEventDetails", {}).get("name") == state]


def _state_span(events, state):
    """(entered, exited) timestamps of a state visited exactly once."""
    en, ex = _entered(events, state), _exited(events, state)
    assert len(en) == 1 and len(ex) == 1, (
        f"state {state!r} must be entered and exited exactly once; got {len(en)} entered / "
        f"{len(ex)} exited in {[e['type'] for e in events]!r}"
    )
    return en[0]["timestamp"], ex[0]["timestamp"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
