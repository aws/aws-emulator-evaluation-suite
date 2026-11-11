"""deep-sfn-3-wait-absolute-timestamp-future-and-past."""
from __future__ import annotations

import datetime as dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-3-wait-absolute-timestamp-future-and-past"
GROUP = "wait_state"
SERVICES = ["stepfunctions"]

_FUTURE_OFFSET_S = 20
_START_SLACK_S = 5.0  # second truncation of the target plus CreateStateMachine/StartExecution latency
_LATE_SLACK_S = 6.0   # how long after the target instant the Wait may still be exiting
_PAST_MAX_S = 2.0     # a Timestamp already in the past must not be waited on
_WAIT = "Hold"


def _definition(iso: str) -> dict:
    return {
        "StartAt": _WAIT,
        "States": {
            _WAIT: {"Type": "Wait", "Timestamp": iso, "Next": "Done"},
            "Done": {"Type": "Pass", "Result": {"until": iso}, "End": True},
        },
    }


# timing:real-time — workflow: 20 s https://docs.aws.amazon.com/step-functions/latest/dg/state-wait.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Wait with an absolute Timestamp exits no earlier than that instant and within a few seconds
    after it, while a twin whose Timestamp is an hour in the past proceeds immediately.
    """
    role_arn = _sfn_role(ctx)
    now = dt.datetime.now(dt.timezone.utc)
    past = (now - dt.timedelta(hours=1)).replace(microsecond=0)
    past_iso = past.strftime("%Y-%m-%dT%H:%M:%SZ")
    # The past twin is created FIRST: any CreateStateMachine retry while the fresh role's trust
    # propagates is absorbed here, so the future instant below is minted only once creation is fast.
    past_sm = _create_state_machine(ctx, role_arn, _definition(past_iso))
    future = (dt.datetime.now(dt.timezone.utc)
              + dt.timedelta(seconds=_FUTURE_OFFSET_S)).replace(microsecond=0)
    future_iso = future.strftime("%Y-%m-%dT%H:%M:%SZ")
    future_sm = _create_state_machine(ctx, role_arn, _definition(future_iso))
    future_exec = _start(ctx, future_sm, {"twin": "future"})
    past_exec = _start(ctx, past_sm, {"twin": "past"})
    started = dt.datetime.now(dt.timezone.utc)
    assert (future - started).total_seconds() > _FUTURE_OFFSET_S - _START_SLACK_S, (
        f"the future twin must start with ~{_FUTURE_OFFSET_S}s still to wait; only "
        f"{(future - started).total_seconds():.2f}s remained at start"
    )

    past_desc = _wait_terminal(ctx, past_exec)
    future_desc = _wait_terminal(ctx, future_exec)
    for label, desc, iso in (("future", future_desc, future_iso), ("past", past_desc, past_iso)):
        assert desc["status"] == "SUCCEEDED", (
            f"the {label}-Timestamp execution must SUCCEED; got {desc['status']!r} "
            f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
        )
        assert json.loads(desc["output"]) == {"until": iso}, (
            f"the {label} twin's output must be its own Pass result; got {desc['output']!r}"
        )

    f_in, f_out = _state_span(_history(ctx, future_exec), _WAIT)
    early = (future - f_out).total_seconds()
    assert f_out >= future, (
        f'a Wait with Timestamp="{future_iso}" must not exit before that instant; history says it '
        f"exited at {f_out.isoformat()}, {early:.2f}s early"
    )
    late = (f_out - future).total_seconds()
    assert late < _LATE_SLACK_S, (
        f'a Wait with Timestamp="{future_iso}" must exit within {_LATE_SLACK_S}s of it; history '
        f"says it exited {late:.2f}s late"
    )
    held = (f_out - f_in).total_seconds()
    assert held >= _FUTURE_OFFSET_S - _START_SLACK_S, (
        f"the future twin must genuinely wait ~{_FUTURE_OFFSET_S}s; it sat in the Wait {held:.2f}s"
    )
    assert held < _FUTURE_OFFSET_S + _LATE_SLACK_S, (
        f"the future twin must not wait far beyond ~{_FUTURE_OFFSET_S}s; it sat there {held:.2f}s"
    )

    p_in, p_out = _state_span(_history(ctx, past_exec), _WAIT)
    p_held = (p_out - p_in).total_seconds()
    assert p_held < _PAST_MAX_S, (
        f'a Wait with Timestamp="{past_iso}" (an hour ago) must proceed immediately; it sat in '
        f"the Wait {p_held:.2f}s"
    )
    assert past_desc["stopDate"] < future, (
        f"the past-Timestamp control must finish before the future twin's target instant "
        f"{future_iso}; it stopped at {past_desc['stopDate'].isoformat()}"
    )
    assert future_desc["stopDate"] >= future, (
        f"the future twin's execution cannot have stopped before its target {future_iso}; it "
        f"stopped at {future_desc['stopDate'].isoformat()}"
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
