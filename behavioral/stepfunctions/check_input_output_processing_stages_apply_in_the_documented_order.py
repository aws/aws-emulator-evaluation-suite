"""input-output-processing-stages-apply-in-the-documented-order."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "input-output-processing-stages-apply-in-the-documented-order"
GROUP = "input_output_processing"
SERVICES = ["stepfunctions"]

_STATE = "Probe"
_OUTER = "OUTER_HIDDEN_FROM_TASK_BY_INPUTPATH"
_KEPT = "KEPT_BY_INPUTPATH"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """InputPath, Parameters, ResultSelector, ResultPath and OutputPath compose in the
    documented order on one Task state, each stage's effect proved from history.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-input-output-filtering.html
    """
    _role_name, role_arn = _create_sfn_role(ctx)

    full_arn = _create_state_machine(ctx, role_arn, _definition(with_output_path=True))
    # The twin differs by exactly ONE field: OutputPath is absent. Its output is what the
    # full machine's output would be if OutputPath ran BEFORE ResultPath, or not at all.
    no_output_path_arn = _create_state_machine(
        ctx, role_arn, _definition(with_output_path=False)
    )

    payload = {"outer": _OUTER, "payload": {"limit": 1, "keep": _KEPT}}

    full_exec, full = _run_to_terminal(ctx, full_arn, payload, timeout_s=120.0)
    twin_exec, twin = _run_to_terminal(ctx, no_output_path_arn, payload, timeout_s=120.0)

    for label, desc in (("full", full), ("no-OutputPath twin", twin)):
        assert desc["status"] == "SUCCEEDED", (
            f"the {label} execution must SUCCEED — a failure here usually means Parameters "
            f"resolved against the raw input instead of the InputPath result; got "
            f"{desc['status']} error={desc.get('error')!r} cause={desc.get('cause')!r}"
        )

    # --- Stage 5 (OutputPath) ran LAST, on the ResultPath-merged document ---------------
    full_output = json.loads(full["output"])
    assert full_output == {"count": 1}, (
        'OutputPath "$.probe" must select the node ResultPath had just grafted, so the '
        f'execution output must be exactly {{"count": 1}}; got {full_output!r}. An '
        "interpreter that applies OutputPath before ResultPath cannot produce this."
    )

    # --- Stage 4 (ResultPath) merged into the RAW EXECUTION INPUT, not the InputPath result.
    # AWS's own worked example (input-output-example.html) grafts a Lambda ResultPath onto
    # "the original state machine input", not onto the InputPath-narrowed value handed to the
    # task — an "extra" sibling of the InputPath'd node survives into the merged output. Our
    # 'outer' key plays that role here.
    twin_output = json.loads(twin["output"])
    assert twin_output == {
        "outer": _OUTER,
        "payload": {"limit": 1, "keep": _KEPT},
        "probe": {"count": 1},
    }, (
        "with OutputPath removed and nothing else changed, the output must be the RAW "
        "execution input with the ResultSelector output grafted at $.probe — ResultPath "
        "merges into the state's ORIGINAL input, not the value InputPath narrowed the task "
        f'to: {{"outer": {_OUTER!r}, "payload": {{"limit": 1, "keep": {_KEPT!r}}}, "probe": '
        f'{{"count": 1}}}}; got {twin_output!r}'
    )
    assert twin_output.get("outer") == _OUTER, (
        "ResultPath must merge into the RAW state input, so the 'outer' key that InputPath "
        f"kept away from the task must still be present, unchanged, in the merged output; "
        f"the twin's output was {twin_output!r}"
    )
    assert _OUTER not in json.dumps(full_output), (
        f"the full machine's OutputPath \"$.probe\" must select only what ResultPath just "
        f"grafted, so {_OUTER!r} — which survives ResultPath's merge into the raw input — "
        f"must not survive OutputPath's narrowing; got {full_output!r}"
    )

    events = _history(ctx, full_exec)

    # --- Stage 2 (Parameters) was built from the InputPath result ------------------------
    scheduled = _only(events, "TaskScheduled")
    sent = json.loads(scheduled["taskScheduledEventDetails"]["parameters"])
    assert sent == {"MaxResults": 1}, (
        'Parameters must send exactly {"MaxResults": 1}, resolved from "$.limit" — a path '
        "that exists ONLY in the InputPath result, never in the raw execution input; the "
        f"scheduled parameters were {sent!r}"
    )

    # --- Stage 3 (ResultSelector) demonstrably had something to drop ---------------------
    succeeded = _only(events, "TaskSucceeded")
    raw_result = json.loads(succeeded["taskSucceededEventDetails"]["output"])
    assert "StateMachines" in raw_result, (
        "the raw task result must contain StateMachines, otherwise ResultSelector had "
        f"nothing to drop and the narrowing assertions prove nothing; the raw result keys "
        f"were {sorted(raw_result)}"
    )
    assert len(raw_result["StateMachines"]) == 1, (
        "MaxResults=1 must be honoured by the SDK-integration call, so the raw result must "
        f"list exactly one state machine; it listed {len(raw_result['StateMachines'])}"
    )

    # --- The state's own exit output shows stages 3-5 already applied --------------------
    exited = [
        e for e in events if e.get("stateExitedEventDetails", {}).get("name") == _STATE
    ]
    assert len(exited) == 1, (
        f"history must record the {_STATE} state exited exactly once; got {len(exited)} "
        f"out of {[e['type'] for e in events]}"
    )
    state_output = json.loads(exited[0]["stateExitedEventDetails"]["output"])
    assert state_output == {"count": 1}, (
        f'the {_STATE} state must EXIT with {{"count": 1}} — ResultSelector narrowed, '
        f"ResultPath grafted, OutputPath selected, in that order; it exited with "
        f"{state_output!r} while the raw task result was {sorted(raw_result)}"
    )
    assert set(state_output) == {"count"}, (
        "ResultSelector must have dropped every field of the raw response except the one "
        f"it computed; the state exited with keys {sorted(state_output)} and the raw "
        f"response had {sorted(raw_result)}"
    )

    # --- The state's entry input shows stage 1 already applied --------------------------
    entered = [
        e for e in events if e.get("stateEnteredEventDetails", {}).get("name") == _STATE
    ]
    assert len(entered) == 1, (
        f"history must record the {_STATE} state entered exactly once; got {len(entered)}"
    )
    state_input = json.loads(entered[0]["stateEnteredEventDetails"]["input"])
    assert state_input == payload, (
        "the state-entered event records the state's input BEFORE InputPath is applied, so "
        f"it must still be the whole execution input {payload!r}; got {state_input!r}. If "
        "this is already narrowed, the interpreter applies InputPath earlier than "
        "documented, which is itself the divergence worth reporting."
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


def _definition(*, with_output_path: bool) -> str:
    """One Task carrying every processing field. The SDK integration is chosen because its
    response has fields worth discarding and honours a Parameter derived from the input."""
    state = {
        "Type": "Task",
        "Resource": "arn:aws:states:::aws-sdk:sfn:listStateMachines",
        "InputPath": "$.payload",
        "Parameters": {"MaxResults.$": "$.limit"},
        "ResultSelector": {"count.$": "States.ArrayLength($.StateMachines)"},
        "ResultPath": "$.probe",
        "End": True,
    }
    if with_output_path:
        state["OutputPath"] = "$.probe"
    return json.dumps(
        {
            "Comment": "five-stage input/output processing on a single Task",
            "StartAt": _STATE,
            "States": {_STATE: state},
        }
    )


def _create_sfn_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnio-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Path="/sim2real/",
        Description="SimParity draft: input/output processing order",
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
                        "Action": ["states:ListStateMachines"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return name, arn


def _create_state_machine(ctx, role_arn: str, definition: str) -> str:
    """CreateStateMachine, bounded-retrying only the AccessDeniedException raised while
    the freshly created role's PassRole grant propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnio-")
    deadline = time.monotonic() + 120.0
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
            time.sleep(5.0)
    raise AssertionError(
        f"CreateStateMachine still AccessDenied 120s after the role was created. "
        f"Last error: {last}"
    )


def _start(ctx, sm_arn: str, payload: dict) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps(payload)
    )["executionArn"]
    ctx.on_cleanup(lambda a=exec_arn: sfn.stop_execution(executionArn=a))
    return exec_arn


def _wait_terminal(ctx, exec_arn: str, *, timeout_s: float) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(
        f"execution {exec_arn} still RUNNING after {timeout_s}s for a single "
        f"ListStateMachines task. Last: {last!r}"
    )


def _run_to_terminal(
    ctx, sm_arn: str, payload: dict, *, timeout_s: float
) -> tuple[str, dict]:
    """Start an execution and wait for it to finish, retrying with a fresh execution only if
    it failed because the new role is not yet assumable: Step Functions checks the role again
    when each execution starts, which can fail after CreateStateMachine succeeded."""
    left = ctx.time_left()
    deadline = time.monotonic() + (40.0 if left is None else min(40.0, left))
    attempts = 0
    while True:
        exec_arn = _start(ctx, sm_arn, payload)
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        attempts += 1
        cause = desc.get("cause") or ""
        if desc["status"] != "FAILED" or "not authorized to assume" not in cause:
            return exec_arn, desc
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"execution on {sm_arn} still fails with a role-assumption error across {attempts} "
                f"fresh attempts; IAM propagation should have finished well before now. Last: {desc!r}"
            )
        time.sleep(2.0)


def _history(ctx, exec_arn: str) -> list[dict]:
    sfn = ctx.client("stepfunctions")
    events: list[dict] = []
    kwargs = {"executionArn": exec_arn}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return sorted(events, key=lambda e: e["id"])
        kwargs["nextToken"] = token


def _only(events: list[dict], want_type: str) -> dict:
    matching = [e for e in events if e["type"] == want_type]
    assert len(matching) == 1, (
        f"history must contain exactly one {want_type} event for a single-task execution; "
        f"got {len(matching)} out of {[e['type'] for e in events]}"
    )
    return matching[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
