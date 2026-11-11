"""test-state-runtime-cause-omits-execution-prefix."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-runtime-cause-omits-execution-prefix"
GROUP = "test_state"
SERVICES = ["stepfunctions"]

_STATE_NAME = "BadPass"
_BAD_OUTPUT_PATH = "$.missing"


def _trust_policy() -> str:
    return json.dumps(
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


def _pass_state(output_path: str | None) -> dict:
    state = {"Type": "Pass", "Result": {"present": True}, "End": True}
    if output_path is not None:
        state["OutputPath"] = output_path
    return state


def _create_sfn_role(ctx):
    """An execution role this check creates for its own state machine."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_trust_policy(),
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_express_state_machine(ctx, role_arn: str, state: dict) -> str:
    """An EXPRESS state machine wrapping `state` as its only state, retrying only the
    AccessDeniedException raised while the freshly created role's assume-role grant propagates,
    polling every 2s against a deadline."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnteststate-")
    definition = json.dumps({"StartAt": _STATE_NAME, "States": {_STATE_NAME: state}})
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=definition,
                roleArn=role_arn,
                type="EXPRESS",
                tags=[{"key": "sim2real", "value": "1"}, {"key": "sim2real-check", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
    raise AssertionError(
        f"CreateStateMachine(type=EXPRESS) still AccessDenied 120s after the role was created. "
        f"Last error: {last}"
    )


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """TestState's States.Runtime cause for a bad OutputPath omits the "An error occurred while
    executing the state..." prefix that the same failure carries inside a real execution."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    bad_state_def = json.dumps(_pass_state(_BAD_OUTPUT_PATH))
    good_state_def = json.dumps(_pass_state(None))

    # Positive control: TestState on the same state shape with no OutputPath succeeds.
    ts_good = sfn.test_state(definition=good_state_def, input=json.dumps({"mode": "ok"}))
    assert ts_good["status"] == "SUCCEEDED", (
        f"positive control: TestState on a Pass with no OutputPath must report SUCCEEDED, "
        f"got {ts_good['status']!r}"
    )

    # Subject (standalone): TestState on the same OutputPath failure, outside any execution.
    ts_bad = sfn.test_state(definition=bad_state_def, input=json.dumps({"mode": "bad"}))
    assert ts_bad["status"] == "FAILED", (
        f"TestState on a Pass whose OutputPath selects an absent field must report FAILED, "
        f"got {ts_bad['status']!r}"
    )
    assert ts_bad.get("error") == "States.Runtime", (
        f"expected TestState error 'States.Runtime', got {ts_bad.get('error')!r}"
    )
    tail = f"Invalid path '{_BAD_OUTPUT_PATH}' : No results for path: $['missing']"
    assert ts_bad.get("cause") == tail, (
        f"expected TestState cause {tail!r} (no execution prefix), got {ts_bad.get('cause')!r}"
    )

    # Subject (inside a real execution): the identical failure, run for real.
    sm_arn = _create_express_state_machine(ctx, role_arn, _pass_state(_BAD_OUTPUT_PATH))

    # Positive control: a real execution of the same state shape with no OutputPath succeeds.
    control_arn = _create_express_state_machine(ctx, role_arn, _pass_state(None))
    control_exec = sfn.start_sync_execution(
        stateMachineArn=control_arn, input=json.dumps({"mode": "ok"})
    )
    assert control_exec["status"] == "SUCCEEDED", (
        f"positive control: a real execution of the no-OutputPath state must report SUCCEEDED, "
        f"got {control_exec['status']!r}"
    )

    real_exec = sfn.start_sync_execution(stateMachineArn=sm_arn, input=json.dumps({"mode": "bad"}))
    assert real_exec["status"] == "FAILED", (
        f"a real execution of the OutputPath failure must report FAILED, got {real_exec['status']!r}"
    )
    assert real_exec.get("error") == "States.Runtime", (
        f"expected real-execution error 'States.Runtime', got {real_exec.get('error')!r}"
    )
    expected_real_cause = (
        f"An error occurred while executing the state '{_STATE_NAME}' "
        f"(entered at the event id #2). {tail}"
    )
    assert real_exec.get("cause") == expected_real_cause, (
        f"expected real-execution cause {expected_real_cause!r}, got {real_exec.get('cause')!r}"
    )

    # The contrast itself: TestState's cause is exactly the real execution's cause with the
    # "An error occurred while executing the state..." prefix stripped off.
    assert expected_real_cause.endswith(ts_bad["cause"]), (
        f"expected the real execution's cause to end with TestState's cause {ts_bad['cause']!r}; "
        f"got {expected_real_cause!r}"
    )
    assert expected_real_cause != ts_bad["cause"], (
        "TestState's cause must omit the execution prefix that the real execution's cause carries, "
        "but the two causes are identical"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
