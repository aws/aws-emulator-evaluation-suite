"""deep-sfn-wait-timestamppath-absent-and-array-index-unresolved-rejected."""
from __future__ import annotations

import datetime as dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-wait-timestamppath-absent-and-array-index-unresolved-rejected"
GROUP = "wait_state"
SERVICES = ["stepfunctions"]

_EXPECTED_ERROR = "States.Runtime"
_PLAIN_DEFINITION = {
    "StartAt": "W",
    "States": {
        "W": {"Type": "Wait", "TimestampPath": "$.until", "Next": "Done"},
        "Done": {"Type": "Pass", "End": True},
    },
}
_INDEXED_DEFINITION = {
    "StartAt": "W",
    "States": {
        "W": {"Type": "Wait", "TimestampPath": "$.timestamp[0]", "Next": "Done"},
        "Done": {"Type": "Pass", "End": True},
    },
}
_TARGET_OFFSET_S = 10


# timing:real-time — workflow: 10 s https://docs.aws.amazon.com/step-functions/latest/dg/state-wait.html
@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Wait TimestampPath fails the execution with States.Runtime naming the exact unresolved
    path, both plain (`$.until`) and array-indexed (`$.timestamp[0]`), when the input carries
    nothing to resolve; each machine given a resolvable value instead waits for it and succeeds.
    """
    role_arn = _sfn_role(ctx)

    plain_sm = _create_state_machine(ctx, role_arn, _PLAIN_DEFINITION)
    _assert_resolves_and_waits(ctx, plain_sm, lambda ts: {"until": ts}, label="$.until")
    _assert_fails_unresolved(ctx, plain_sm, {}, "$.until", label="$.until absent")

    indexed_sm = _create_state_machine(ctx, role_arn, _INDEXED_DEFINITION)
    _assert_resolves_and_waits(ctx, indexed_sm, lambda ts: {"timestamp": [ts]}, label="$.timestamp[0]")
    _assert_fails_unresolved(ctx, indexed_sm, {}, "$.timestamp[0]", label="$.timestamp[0] absent")


def _assert_resolves_and_waits(ctx, sm_arn, make_payload, *, label):
    target = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=_TARGET_OFFSET_S)).replace(microsecond=0)
    payload = make_payload(target.strftime("%Y-%m-%dT%H:%M:%SZ"))
    exec_arn = _start(ctx, sm_arn, payload)
    desc = _wait_terminal(ctx, exec_arn)
    assert desc["status"] == "SUCCEEDED", (
        f"[{label}] the positive control must SUCCEED; got {desc['status']!r} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    assert json.loads(desc["output"]) == payload, (
        f"[{label}] the positive control's output must be its own input; got {desc['output']!r}"
    )
    _in, out = _state_span(_history(ctx, exec_arn), "W")
    assert out >= target, (
        f"[{label}] the Wait must not exit before {target.isoformat()}; it exited at {out.isoformat()}"
    )


def _assert_fails_unresolved(ctx, sm_arn, payload, expected_path, *, label):
    exec_arn = _start(ctx, sm_arn, payload)
    desc = _wait_terminal(ctx, exec_arn)
    expected_cause = (
        "An error occurred while executing the state 'W' (entered at the event id #2). The "
        f"TimestampPath parameter does not reference an input value: {expected_path}"
    )
    assert desc["status"] == "FAILED", (
        f"[{label}] must FAIL the execution; got {desc['status']!r} output={desc.get('output')!r}"
    )
    assert desc.get("error") == _EXPECTED_ERROR, (
        f"[{label}] the execution error must be exactly {_EXPECTED_ERROR!r}; got "
        f"{desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    assert desc.get("cause") == expected_cause, (
        f"[{label}] the execution cause must be exactly {expected_cause!r}; got {desc.get('cause')!r}"
    )
    events = _history(ctx, exec_arn)
    assert len(_entered(events, "W")) == 1, (
        f"[{label}] the run must reach the Wait exactly once; history {[e['type'] for e in events]!r}"
    )
    assert _exited(events, "W") == [], (
        f"[{label}] the Wait must never exit when its path does not resolve; history "
        f"{[e['type'] for e in events]!r}"
    )
    assert _entered(events, "Done") == [], (
        f"[{label}] no state after the Wait may run; history {[e['type'] for e in events]!r}"
    )
    assert desc.get("output") is None, (
        f"[{label}] a failed execution carries no output; got {desc.get('output')!r}"
    )


_TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


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


def _create_state_machine(ctx, role_arn, definition) -> str:
    """CreateStateMachine, bounded-retrying only the AccessDeniedException raised while the fresh
    role's trust propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sfn-interp-sm-")
    deadline = time.monotonic() + 120.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
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


def _wait_terminal(ctx, exec_arn, timeout_s=60.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


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
