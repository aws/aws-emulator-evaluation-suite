"""describe-map-run-not-found."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-map-run-not-found"
GROUP = 'errors'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

# A Distributed Map runs its child workflow executions with the parent's execution role.
_SFN_MAP_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["states:StartExecution", "states:DescribeExecution", "states:StopExecution"],
        "Resource": "*",
    }],
})


def _create_sfn_role(ctx):
    """A states.amazonaws.com-assumable execution role this check creates and owns, allowed to
    run the Distributed Map's child executions."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]

    def _delete_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-map-children")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-map-children", PolicyDocument=_SFN_MAP_POLICY)
    return role_arn


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


def _asl_distributed_map():
    return {
        "Comment": "behavioral-map",
        "StartAt": "Map",
        "States": {
            "Map": {
                "Type": "Map",
                "ItemsPath": "$.items",
                "MaxConcurrency": 1,
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                    "StartAt": "Item",
                    "States": {"Item": {"Type": "Pass", "End": True}},
                },
                "End": True,
            }
        },
    }


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
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because a call AWS refuses must not pass as a mere mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _fake_map_run_arn(state_machine_arn):
    """A syntactically well-formed but nonexistent mapRunArn, derived from a real
    stateMachineArn (mapRunArn shape is arn:...:mapRun:<name>/<label>:<id>)."""
    base = state_machine_arn.replace(":stateMachine:", ":mapRun:")
    return f"{base}/fakeLabel:{uuid.uuid4()}"


def _stop_if_running(sfn, exec_arn):
    try:
        sfn.stop_execution(executionArn=exec_arn)
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _real_map_run_arn(ctx, sfn, role_arn, *, timeout_s=60, interval_s=1.0):
    """Start a real Distributed Map execution and return the mapRunArn Step
    Functions assigns to it. The Map Run entity is created as soon as the
    parent execution reaches the Map state."""
    arn = _create_state_machine(ctx, _asl_distributed_map(), role_arn)
    exec_arn = sfn.start_execution(
        stateMachineArn=arn, input=json.dumps({"items": [1]})
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        found = sfn.list_map_runs(executionArn=exec_arn).get("mapRuns", [])
        if found:
            return exec_arn, found[0]["mapRunArn"]
        time.sleep(interval_s)
    raise AssertionError(f"no Map Run scheduled for execution {exec_arn} within {timeout_s}s")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeMapRun on a well-formed but never-created mapRunArn raises ResourceNotFound,
    while a positive control first proves it succeeds on a Map Run Step Functions created."""
    sfn = ctx.client("stepfunctions")

    role_arn = _create_sfn_role(ctx)
    exec_arn, real_map_run_arn = _real_map_run_arn(ctx, sfn, role_arn)
    real = sfn.describe_map_run(mapRunArn=real_map_run_arn)
    assert real["executionArn"] == exec_arn, (
        f"expected the real Map Run's executionArn to be {exec_arn}, got {real}"
    )

    arn = _create_state_machine(ctx, _asl_pass(), role_arn)
    bogus = _fake_map_run_arn(arn)

    code, message = _error(lambda: sfn.describe_map_run(mapRunArn=bogus))
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code}"
    expected = f"Resource not found: '{bogus}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
