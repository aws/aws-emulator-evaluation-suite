"""describe-state-machine-for-execution-matches-started."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-state-machine-for-execution-matches-started"
GROUP = 'execution_lifecycle'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and owns, so the
    outcome never rests on an execution role the account happens to carry."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_state_machine(ctx, definition, role_arn, *, name=None, sm_type="STANDARD"):
    """CreateStateMachine, retrying only the AccessDeniedException a freshly created role
    returns until IAM propagates it."""
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
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


def _wait_execution_status(ctx, exec_arn, statuses, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in statuses:
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not in {statuses} within {timeout_s}s: {last!r}")


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStateMachineForExecution returns the exact definition and roleArn active when the
    execution started, even after the state machine's definition is later updated.
    """
    sfn = ctx.client("stepfunctions")
    def_v1 = _asl_pass({"frozen": "v1"})
    def_v2 = _asl_pass({"frozen": "v2-active"})
    role_arn = _create_sfn_role(ctx)
    arn = _create_state_machine(ctx, def_v1, role_arn)
    exec_arn = _start_execution(ctx, arn, input_data={"in": 1})
    _wait_execution_status(
        ctx, exec_arn, {"RUNNING", "SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"}, timeout_s=20
    )

    # Mutate the base state machine's ACTIVE definition AFTER the execution started.
    sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(def_v2))

    for_exec = sfn.describe_state_machine_for_execution(executionArn=exec_arn)
    assert for_exec["stateMachineArn"] == arn, f"expected stateMachineArn == {arn}, got {for_exec}"
    assert for_exec["roleArn"] == role_arn, f"expected roleArn to match, got {for_exec}"
    frozen_definition = json.loads(for_exec["definition"])
    assert frozen_definition == def_v1, (
        f"DescribeStateMachineForExecution must return the exact definition active AT START TIME (v1), got {frozen_definition}"
    )

    # Sanity: the base (unqualified) state machine's OWN Describe now shows v2.
    current = sfn.describe_state_machine(stateMachineArn=arn)
    current_definition = json.loads(current["definition"])
    assert current_definition == def_v2, (
        f"expected the base state machine's current definition to be exactly v2, got {current_definition}"
    )

    _wait_execution_status(ctx, exec_arn, {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"}, timeout_s=30)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
