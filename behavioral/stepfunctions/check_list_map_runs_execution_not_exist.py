"""list-map-runs-execution-not-exist."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-map-runs-execution-not-exist"
GROUP = 'errors'
SERVICES = ['stepfunctions']


_ROLE_ARNS = {}


def _execution_role_arn(ctx):
    """Create one Step Functions execution role per check run and register its cleanup."""
    key = id(ctx)
    if key in _ROLE_ARNS:
        return _ROLE_ARNS[key]
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
    ctx.on_cleanup(lambda: _ROLE_ARNS.pop(key, None))
    _ROLE_ARNS[key] = arn
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retried while a just-created role is still propagating in IAM."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(definition),
        roleArn=_execution_role_arn(ctx),
        type=sm_type,
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _fake_execution_arn(state_machine_arn, suffix="never-existed"):
    """A syntactically well-formed but nonexistent executionArn, derived from a real
    stateMachineArn so the account/region/partition segments are realistic."""
    return state_machine_arn.replace(":stateMachine:", ":execution:") + f":{suffix}-{uuid.uuid4().hex[:8]}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListMapRuns on a well-formed but never-created executionArn raises ExecutionDoesNotExist,
    while the same call on a real execution of the same state machine returns an empty list.
    """
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass())

    real_exec_arn = sfn.start_execution(stateMachineArn=arn)["executionArn"]
    positive = sfn.list_map_runs(executionArn=real_exec_arn)
    assert positive["mapRuns"] == [], (
        f"expected an empty mapRuns list for a real execution with no Map state, got {positive['mapRuns']!r}"
    )

    bogus = _fake_execution_arn(arn)
    code, message = _error(lambda: sfn.list_map_runs(executionArn=bogus))
    assert code == "ExecutionDoesNotExist", f"expected ExecutionDoesNotExist, got {code}"
    assert message == f"Execution Does Not Exist: '{bogus}'", f"unexpected ExecutionDoesNotExist message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
