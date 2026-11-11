"""map-maxconcurrency-runtime-overflow-and-negative-path-fail-with-states-runtime."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "map-maxconcurrency-runtime-overflow-and-negative-path-fail-with-states-runtime"
GROUP = "map_state"
SERVICES = ["stepfunctions"]

_MAP_STATE = "M"
_JAVA_LONG_MAX = 9223372036854775807
_TOO_BIG = _JAVA_LONG_MAX + 1

_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _create_sfn_role(ctx) -> str:
    """A Step Functions execution role this check creates and deletes."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnmcrt-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _definition(*, mode: str, max_concurrency=None, max_concurrency_path=None) -> dict:
    processor_config = {"Mode": mode}
    if mode == "DISTRIBUTED":
        processor_config["ExecutionType"] = "STANDARD"
    state = {
        "Type": "Map",
        "ItemsPath": "$.items",
        "ItemProcessor": {
            "ProcessorConfig": processor_config,
            "StartAt": "Hold",
            "States": {"Hold": {"Type": "Wait", "Seconds": 2, "End": True}},
        },
        "End": True,
    }
    if max_concurrency is not None:
        state["MaxConcurrency"] = max_concurrency
    if max_concurrency_path is not None:
        state["MaxConcurrencyPath"] = max_concurrency_path
    return {"StartAt": _MAP_STATE, "States": {_MAP_STATE: state}}


def _create_state_machine(ctx, role_arn: str, definition: dict) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnmcrt-")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD"
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_to_terminal(ctx, sm_arn: str, input_data: dict, *, timeout_s=30.0) -> dict:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(input_data))["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _assert_states_runtime(desc: dict, expected_cause: str, label: str) -> None:
    assert desc["status"] == "FAILED", f"{label}: expected FAILED, got {desc['status']}: {desc!r}"
    assert desc.get("error") == "States.Runtime", f"{label}: expected error States.Runtime, got {desc.get('error')!r}"
    assert desc.get("cause") == expected_cause, f"{label}: unexpected cause: {desc.get('cause')!r}"


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A literal Map MaxConcurrency above a Java long fails the execution with States.Runtime
    identically in INLINE and DISTRIBUTED mode; a MaxConcurrencyPath resolving negative (INLINE)
    or above a Java long (DISTRIBUTED) fails the same way, each cause naming the field and value."""
    role_arn = _create_sfn_role(ctx)

    # Positive control: a MaxConcurrencyPath resolving to a small positive integer succeeds.
    valid_sm = _create_state_machine(ctx, role_arn, _definition(mode="INLINE", max_concurrency_path="$.mc"))
    control = _run_to_terminal(ctx, valid_sm, {"items": [1, 2, 3], "mc": 2})
    assert control["status"] == "SUCCEEDED", (
        f"positive control: a valid MaxConcurrencyPath value must succeed, got "
        f"{control['status']} error={control.get('error')!r} cause={control.get('cause')!r}"
    )

    # Literal above a Java long: INLINE.
    literal_inline_sm = _create_state_machine(ctx, role_arn, _definition(mode="INLINE", max_concurrency=_TOO_BIG))
    desc = _run_to_terminal(ctx, literal_inline_sm, {"items": [1]})
    _assert_states_runtime(
        desc,
        f"An error occurred while executing the state '{_MAP_STATE}' (entered at the event id #2). "
        f"The MaxConcurrency field cannot be parsed as an integer value: {_TOO_BIG}",
        "literal overflow, INLINE",
    )

    # Literal above a Java long: DISTRIBUTED -- the same failure, mode-independent.
    literal_dist_sm = _create_state_machine(ctx, role_arn, _definition(mode="DISTRIBUTED", max_concurrency=_TOO_BIG))
    desc = _run_to_terminal(ctx, literal_dist_sm, {"items": [1]})
    _assert_states_runtime(
        desc,
        f"An error occurred while executing the state '{_MAP_STATE}' (entered at the event id #2). "
        f"The MaxConcurrency field cannot be parsed as an integer value: {_TOO_BIG}",
        "literal overflow, DISTRIBUTED",
    )

    # MaxConcurrencyPath resolving negative: INLINE, with the exact documented message.
    path_sm = _create_state_machine(ctx, role_arn, _definition(mode="INLINE", max_concurrency_path="$.mc"))
    desc = _run_to_terminal(ctx, path_sm, {"items": [1], "mc": -5})
    _assert_states_runtime(
        desc,
        f"An error occurred while executing the state '{_MAP_STATE}' (entered at the event id #2). "
        "MaxConcurrency cannot be negative but was: -5",
        "negative MaxConcurrencyPath, INLINE",
    )

    # MaxConcurrencyPath resolving above a Java long: DISTRIBUTED.
    path_dist_sm = _create_state_machine(ctx, role_arn, _definition(mode="DISTRIBUTED", max_concurrency_path="$.mc"))
    desc = _run_to_terminal(ctx, path_dist_sm, {"items": [1], "mc": _TOO_BIG})
    _assert_states_runtime(
        desc,
        f"An error occurred while executing the state '{_MAP_STATE}' (entered at the event id #2). "
        f'The MaxConcurrencyPath field refers to value "{_TOO_BIG}" which is not a valid integer: $.mc',
        "MaxConcurrencyPath overflow, DISTRIBUTED",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
