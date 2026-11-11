"""deep-sfn-wait-secondspath-array-index-unresolved-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-wait-secondspath-array-index-unresolved-rejected"
GROUP = "wait_state"
SERVICES = ["stepfunctions"]

_EXPECTED_ERROR = "States.Runtime"
_EXPECTED_CAUSE = (
    "An error occurred while executing the state 'W' (entered at the event id #2). The "
    "SecondsPath parameter does not reference an input value: $.seconds[0]"
)
_DEFINITION = {
    "StartAt": "W",
    "States": {
        "W": {"Type": "Wait", "SecondsPath": "$.seconds[0]", "Next": "Done"},
        "Done": {"Type": "Pass", "End": True},
    },
}
_GOOD_SECONDS = 20
_TRUNCATION_SLACK_S = 5.0  # whole-second resolution of the Wait plus history event stamping


# timing:real-time — workflow: 20 s https://docs.aws.amazon.com/step-functions/latest/dg/state-wait.html
@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Wait SecondsPath of `$.seconds[0]` fails the execution with States.Runtime, naming the
    exact unresolved path, when the input carries no `seconds` array to index; the same machine
    given `{"seconds": [N]}` resolves the index and genuinely waits N seconds.
    """
    role_arn = _sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _DEFINITION)

    good_exec = _start(ctx, sm_arn, {"seconds": [_GOOD_SECONDS]})
    good = _wait_terminal(ctx, good_exec)
    assert good["status"] == "SUCCEEDED", (
        f'the positive control (SecondsPath "$.seconds[0]" == {_GOOD_SECONDS}) must SUCCEED; got '
        f"{good['status']!r} error={good.get('error')!r} cause={good.get('cause')!r}"
    )
    assert json.loads(good["output"]) == {"seconds": [_GOOD_SECONDS]}, (
        f"the positive control's output must be its own input; got {good['output']!r}"
    )
    g_in, g_out = _state_span(_history(ctx, good_exec), "W")
    g_held = (g_out - g_in).total_seconds()
    assert g_held >= _GOOD_SECONDS - _TRUNCATION_SLACK_S, (
        f'a Wait with SecondsPath "$.seconds[0]" resolving to {_GOOD_SECONDS} must genuinely wait '
        f"~{_GOOD_SECONDS}s; it sat in the Wait {g_held:.2f}s"
    )

    bad_exec = _start(ctx, sm_arn, {})
    bad = _wait_terminal(ctx, bad_exec)
    assert bad["status"] == "FAILED", (
        f"SecondsPath $.seconds[0] with no `seconds` field in the input must FAIL the "
        f"execution; got {bad['status']!r} output={bad.get('output')!r}"
    )
    assert bad.get("error") == _EXPECTED_ERROR, (
        f"the execution error must be exactly {_EXPECTED_ERROR!r}; got {bad.get('error')!r} "
        f"cause={bad.get('cause')!r}"
    )
    assert bad.get("cause") == _EXPECTED_CAUSE, (
        f"the execution cause must be exactly {_EXPECTED_CAUSE!r}; got {bad.get('cause')!r}"
    )
    events = _history(ctx, bad_exec)
    assert len(_entered(events, "W")) == 1, (
        f"the unresolved run must reach the Wait exactly once; history {[e['type'] for e in events]!r}"
    )
    assert _exited(events, "W") == [], (
        f"the Wait must never exit when its SecondsPath does not resolve; history "
        f"{[e['type'] for e in events]!r}"
    )
    assert _entered(events, "Done") == [], (
        f"no state after the Wait may run; history {[e['type'] for e in events]!r}"
    )
    assert bad.get("output") is None, f"a failed execution carries no output; got {bad.get('output')!r}"


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
