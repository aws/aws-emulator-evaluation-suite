"""deep-sfn-3-wait-timestamp-path-malformed-rejected."""
from __future__ import annotations

import datetime as dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-3-wait-timestamp-path-malformed-rejected"
GROUP = "wait_state"
SERVICES = ["stepfunctions"]

_WAIT = "Hold"
_EXPECTED_ERROR = "States.Runtime"
_DEFINITION = {
    "StartAt": _WAIT,
    "States": {
        _WAIT: {"Type": "Wait", "TimestampPath": "$.until", "Next": "Done"},
        "Done": {"Type": "Pass", "Result": "released", "End": True},
    },
}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Wait whose TimestampPath resolves to a non-ISO-8601 string fails with States.Runtime at the
    Wait, while the same machine given a well-formed timestamp waits for it and succeeds.
    """
    role_arn = _sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _DEFINITION)

    target = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=4)).replace(microsecond=0)
    good_iso = target.strftime("%Y-%m-%dT%H:%M:%SZ")
    good_exec = _start(ctx, sm_arn, {"until": good_iso})
    bad_exec = _start(ctx, sm_arn, {"until": "next tuesday at noon"})

    good = _wait_terminal(ctx, good_exec)
    assert good["status"] == "SUCCEEDED", (
        f"the positive control (until={good_iso!r}) must SUCCEED; got {good['status']!r} "
        f"error={good.get('error')!r} cause={good.get('cause')!r}"
    )
    assert json.loads(good["output"]) == "released", (
        f"the positive control's output must be the Pass result; got {good['output']!r}"
    )
    _g_in, g_out = _state_span(_history(ctx, good_exec), _WAIT)
    assert g_out >= target, (
        f"the positive control's Wait must not exit before {good_iso}; it exited at "
        f"{g_out.isoformat()}"
    )

    bad = _wait_terminal(ctx, bad_exec)
    assert bad["status"] == "FAILED", (
        f"a TimestampPath resolving to a non-timestamp must FAIL the execution; got "
        f"{bad['status']!r} output={bad.get('output')!r}"
    )
    assert bad.get("error") == _EXPECTED_ERROR, (
        f"the execution error must be exactly {_EXPECTED_ERROR!r}; got {bad.get('error')!r} "
        f"cause={bad.get('cause')!r}"
    )
    events = _history(ctx, bad_exec)
    assert len(_entered(events, _WAIT)) == 1, (
        f"the malformed run must reach the Wait exactly once; history {[e['type'] for e in events]!r}"
    )
    assert _exited(events, _WAIT) == [], (
        f"the Wait must never exit on a malformed timestamp; history {[e['type'] for e in events]!r}"
    )
    assert _entered(events, "Done") == [], (
        f"no state after the Wait may run; history {[e['type'] for e in events]!r}"
    )
    assert bad.get("output") is None, f"a failed execution carries no output; got {bad.get('output')!r}"


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
