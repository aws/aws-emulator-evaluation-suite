"""redrive-and-express-sync-start-rejected-while-state-machine-deleting."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-and-express-sync-start-rejected-while-state-machine-deleting"
GROUP = "data-plane"
SERVICES = ["stepfunctions"]

_FAIL_DEFINITION = json.dumps(
    {"Comment": "sim2real redrive-deleting", "StartAt": "F", "States": {"F": {"Type": "Fail", "Error": "Boom", "Cause": "boom"}}}
)
_PASS_DEFINITION = json.dumps(
    {"Comment": "sim2real express-deleting", "StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}}
)

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

DELETING_POLL_TIMEOUT_S = 60.0


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RedriveExecution on a failed execution of a mid-deletion state machine is rejected
    ExecutionNotRedrivable naming the DELETING state, and StartSyncExecution on the version or
    alias ARN of a mid-deletion EXPRESS machine is rejected StateMachineDeleting naming that ARN.
    """
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    # --- RedriveExecution -------------------------------------------------------------------
    standard_arn = _create_state_machine(ctx, sfn, role_arn, "std-", _FAIL_DEFINITION)
    failed_exec_arn = sfn.start_execution(stateMachineArn=standard_arn, input="{}")["executionArn"]
    desc = _poll_until(
        lambda: sfn.describe_execution(executionArn=failed_exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
    )
    assert desc["status"] == "FAILED", f"setup: expected the execution to FAIL, got {desc['status']!r}"

    sfn.delete_state_machine(stateMachineArn=standard_arn)
    ctx.on_cleanup(lambda: _wait_gone(sfn, standard_arn))
    _poll_until(
        lambda: sfn.describe_state_machine(stateMachineArn=standard_arn)["status"],
        lambda status: status == "DELETING",
        timeout_s=DELETING_POLL_TIMEOUT_S,
    )

    err = _error(lambda: sfn.redrive_execution(executionArn=failed_exec_arn))
    expected = f"Execution {failed_exec_arn} invalid for redrive as: State machine is DELETING"
    assert err == {"Code": "ExecutionNotRedrivable", "Message": expected}, (
        f"RedriveExecution on a deleting state machine's failed execution: expected {expected!r}, got {err!r}"
    )

    # --- StartSyncExecution via a qualified ARN ---------------------------------------------
    express_arn = _create_state_machine(ctx, sfn, role_arn, "expr-", _PASS_DEFINITION, sm_type="EXPRESS")
    express_v1 = sfn.publish_state_machine_version(stateMachineArn=express_arn)["stateMachineVersionArn"]
    express_alias_arn = sfn.create_state_machine_alias(
        name=ctx.unique_name("sim2real-behav-alias-"),
        routingConfiguration=[{"stateMachineVersionArn": express_v1, "weight": 100}],
    )["stateMachineAliasArn"]

    baseline = sfn.start_sync_execution(stateMachineArn=express_alias_arn, input="{}")
    assert baseline["status"] == "SUCCEEDED", f"setup: baseline sync execution must succeed, got {baseline['status']!r}"

    sfn.delete_state_machine(stateMachineArn=express_arn)
    ctx.on_cleanup(lambda: _wait_gone(sfn, express_arn))
    _poll_until(
        lambda: sfn.describe_state_machine(stateMachineArn=express_arn)["status"],
        lambda status: status == "DELETING",
        timeout_s=DELETING_POLL_TIMEOUT_S,
    )

    err = _error(lambda: sfn.start_sync_execution(stateMachineArn=express_v1, input="{}"))
    expected = f"State Machine is being deleted: '{express_v1}'"
    assert err == {"Code": "StateMachineDeleting", "Message": expected}, (
        f"StartSyncExecution via the version ARN of a deleting state machine: expected {expected!r}, got {err!r}"
    )

    err = _error(lambda: sfn.start_sync_execution(stateMachineArn=express_alias_arn, input="{}"))
    expected = f"State Machine is being deleted: '{express_alias_arn}'"
    assert err == {"Code": "StateMachineDeleting", "Message": expected}, (
        f"StartSyncExecution via the alias ARN of a deleting state machine: expected {expected!r}, got {err!r}"
    )



def _wait_gone(sfn, sm_arn: str) -> None:
    deadline = time.monotonic() + 240.0
    while time.monotonic() < deadline:
        try:
            sfn.describe_state_machine(stateMachineArn=sm_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "StateMachineDoesNotExist":
                return
            raise
        time.sleep(5.0)
    raise AssertionError(f"state machine {sm_arn!r} still deleting after 240s")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn) -> dict:
    """The AWS error `fn` raises, as {"Code", "Message"}; raises on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"Code": err.get("Code"), "Message": err.get("Message")}
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return role_arn


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_state_machine(ctx, sfn, role_arn: str, tag: str, definition: str, *, sm_type: str = "STANDARD") -> str:
    """CreateStateMachine, retrying AccessDeniedException while the fresh role's trust propagates."""
    name = ctx.unique_name(f"sim2real-behav-sfn-{tag}")
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn, type=sm_type)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
