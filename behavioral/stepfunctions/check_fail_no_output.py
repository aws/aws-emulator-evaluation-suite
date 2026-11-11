"""fail-no-output."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fail-no-output"
GROUP = 'fail_state'
SERVICES = ['stepfunctions']

def _role_arn(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=_role_arn(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A failed execution has no output field; a succeeded twin (same instant) does."""
    fail_definition = {
        "StartAt": "F",
        "States": {"F": {"Type": "Fail", "Error": "E", "Cause": "C"}},
    }
    pass_definition = {
        "StartAt": "P",
        "States": {"P": {"Type": "Pass", "Result": {"ok": True}, "End": True}},
    }
    fail_sm_arn = _create_state_machine(ctx, fail_definition)
    pass_sm_arn = _create_state_machine(ctx, pass_definition)

    fail_exec_arn = _start_execution(ctx, fail_sm_arn, input_data={})
    pass_exec_arn = _start_execution(ctx, pass_sm_arn, input_data={})

    fail_result = _wait_execution_complete(ctx, fail_exec_arn)
    pass_result = _wait_execution_complete(ctx, pass_exec_arn)

    # Positive control: a succeeded twin, started in the same run, must carry output —
    # otherwise a target that never populates `output` at all would pass the negative below.
    assert pass_result["status"] == "SUCCEEDED", (
        f"expected control execution SUCCEEDED, got {pass_result['status']!r}"
    )
    assert json.loads(pass_result.get("output") or "null") == {"ok": True}, (
        f"expected control output {{'ok': True}}, got {pass_result.get('output')!r}"
    )

    assert fail_result["status"] == "FAILED", (
        f"expected FAILED, got {fail_result['status']!r}"
    )
    assert fail_result.get("output") is None, (
        f"expected no output on a failed execution, got {fail_result.get('output')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
