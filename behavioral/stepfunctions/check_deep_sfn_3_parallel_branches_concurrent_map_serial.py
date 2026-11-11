"""deep-sfn-3-parallel-branches-concurrent-map-serial."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-3-parallel-branches-concurrent-map-serial"
GROUP = "parallel"
SERVICES = ["stepfunctions"]

_BRANCH_WAIT_S = 10
_N = 3


def _branch(i: int) -> dict:
    return {
        "StartAt": f"Sleep{i}",
        "States": {f"Sleep{i}": {"Type": "Wait", "Seconds": _BRANCH_WAIT_S, "Next": f"Mark{i}"},
                   f"Mark{i}": {"Type": "Pass", "Result": i, "End": True}},
    }


_PARALLEL = {
    "StartAt": "Fan",
    "States": {"Fan": {"Type": "Parallel", "Branches": [_branch(i) for i in range(_N)], "End": True}},
}
_MAP = {
    "StartAt": "Fan",
    "States": {"Fan": {
        "Type": "Map", "ItemsPath": "$.items", "MaxConcurrency": 1,
        "ItemProcessor": {
            "ProcessorConfig": {"Mode": "INLINE"},
            "StartAt": "Sleep",
            "States": {"Sleep": {"Type": "Wait", "Seconds": _BRANCH_WAIT_S, "Next": "Mark"},
                       "Mark": {"Type": "Pass", "End": True}},
        },
        "End": True,
    }},
}

# timing:real-time — workflow: 30 s https://docs.aws.amazon.com/step-functions/latest/dg/state-wait.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Three Parallel branches that each Wait 10 s overlap in history and finish in under 20 s,
    while a MaxConcurrency=1 Map over three 10 s Waits runs them back to back for at least 30 s.
    """
    role_arn = _sfn_role(ctx)
    par_sm = _create_state_machine(ctx, role_arn, _PARALLEL)
    map_sm = _create_state_machine(ctx, role_arn, _MAP)
    par_exec = _start(ctx, par_sm, {})
    map_exec = _start(ctx, map_sm, {"items": list(range(_N))})

    par = _wait_terminal(ctx, par_exec)
    mp = _wait_terminal(ctx, map_exec)
    for label, desc in (("Parallel", par), ("Map", mp)):
        assert desc["status"] == "SUCCEEDED", (
            f"the {label} execution must SUCCEED; got {desc['status']!r} "
            f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
        )
    assert json.loads(par["output"]) == list(range(_N)), (
        f"the Parallel output must be the branch results in branch order; got {par['output']!r}"
    )

    # --- Parallel: concurrent ------------------------------------------------------------------
    pev = _history(ctx, par_exec)
    p_in, p_out = _state_span(pev, "Fan")
    p_span = (p_out - p_in).total_seconds()
    assert p_span >= _BRANCH_WAIT_S, (
        f"the Parallel state cannot finish before one branch's {_BRANCH_WAIT_S}s Wait; it spanned "
        f"{p_span:.2f}s"
    )
    assert p_span < 2 * _BRANCH_WAIT_S, (
        f"three {_BRANCH_WAIT_S}s branches run concurrently must finish in under "
        f"{2 * _BRANCH_WAIT_S}s; the Parallel state spanned {p_span:.2f}s — the branches were "
        "serialised"
    )
    starts = []
    for i in range(_N):
        b_in, b_out = _state_span(pev, f"Sleep{i}")
        held = (b_out - b_in).total_seconds()
        assert held >= _BRANCH_WAIT_S, f"branch {i}'s Wait lasted only {held:.2f}s"
        starts.append(b_in)
    skew = (max(starts) - min(starts)).total_seconds()
    assert skew < 3.0, (
        f"all {_N} branch Waits must be entered together; their entries spread over {skew:.2f}s"
    )

    # --- Map(MaxConcurrency=1): serial ---------------------------------------------------------
    mev = _history(ctx, map_exec)
    m_in, m_out = _state_span(mev, "Fan")
    m_span = (m_out - m_in).total_seconds()
    assert m_span >= _N * _BRANCH_WAIT_S, (
        f"a MaxConcurrency=1 Map over {_N} items each waiting {_BRANCH_WAIT_S}s must take at least "
        f"{_N * _BRANCH_WAIT_S}s; it spanned {m_span:.2f}s — iterations overlapped"
    )
    ins = sorted(e["timestamp"] for e in _entered(mev, "Sleep"))
    outs = sorted(e["timestamp"] for e in _exited(mev, "Sleep"))
    assert len(ins) == _N and len(outs) == _N, (
        f"the Map must run its Wait {_N} times; got {len(ins)} entered / {len(outs)} exited"
    )
    for k in range(1, _N):
        assert ins[k] >= outs[k - 1], (
            f"Map iteration {k} entered its Wait at {ins[k].isoformat()} before iteration {k - 1} "
            f"left its Wait at {outs[k - 1].isoformat()}; MaxConcurrency=1 was not honoured"
        )


_TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


def _poll_until(probe, predicate, *, timeout_s, interval_s=1.0, description="condition"):
    """A bounded retry that RAISES on its deadline; never returns a stale value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
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
    deadline = time.monotonic() + 120.0
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
                raise
            time.sleep(5.0)


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
                       lambda d: d["status"] != "RUNNING", timeout_s=timeout_s,
                       description=f"execution {exec_arn} leaving RUNNING")


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
