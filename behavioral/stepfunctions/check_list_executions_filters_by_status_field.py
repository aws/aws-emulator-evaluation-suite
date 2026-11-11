"""list-executions-filters-by-status-field."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-executions-filters-by-status-field"
GROUP = 'execution_lifecycle'
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


def _asl_fail(error="Err", cause="Cause"):
    return {
        "Comment": "behavioral-fail",
        "StartAt": "F",
        "States": {"F": {"Type": "Fail", "Error": error, "Cause": cause}},
    }


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(definition),
        roleArn=_execution_role_arn(ctx),
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


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListExecutions with statusFilter returns exactly the executions in that status: the SUCCEEDED
    filter lists both successful executions, the FAILED filter excludes them, and the failing state
    machine's FAILED filter lists its failed execution."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass({"ok": True}))
    fail_arn = _create_state_machine(ctx, _asl_fail("BadInput", "deliberate"))

    ok1 = _start_execution(ctx, arn)
    ok2 = _start_execution(ctx, arn)
    bad1 = _start_execution(ctx, fail_arn)

    for e in (ok1, ok2):
        r = _wait_execution_complete(ctx, e)
        assert r["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {r}"
    bad_final = _wait_execution_complete(ctx, bad1)
    assert bad_final["status"] == "FAILED", f"expected FAILED, got {bad_final}"

    # DescribeExecution reports SUCCEEDED as soon as the execution finishes, but the
    # ListExecutions status index is eventually consistent — a status-filtered list made
    # immediately after completion can lag by a few seconds and return an empty/partial set.
    # Poll until both succeeded executions surface under the SUCCEEDED filter.
    def _succeeded_arns():
        listed = sfn.list_executions(stateMachineArn=arn, statusFilter="SUCCEEDED")["executions"]
        return {e["executionArn"] for e in listed}

    deadline = time.monotonic() + 30
    succeeded_arns = _succeeded_arns()
    while not ({ok1, ok2} <= succeeded_arns) and time.monotonic() < deadline:
        time.sleep(1.0)
        succeeded_arns = _succeeded_arns()
    assert {ok1, ok2} <= succeeded_arns, (
        f"expected both succeeded executions listed, got {succeeded_arns}"
    )

    failed_list = sfn.list_executions(stateMachineArn=arn, statusFilter="FAILED")["executions"]
    assert not any(e["executionArn"] in {ok1, ok2} for e in failed_list), (
        f"expected the FAILED filter on the SUCCEEDING state machine's arn to exclude its succeeded runs, "
        f"got {failed_list}"
    )

    failed_on_fail_sm = sfn.list_executions(stateMachineArn=fail_arn, statusFilter="FAILED")["executions"]
    assert any(e["executionArn"] == bad1 for e in failed_on_fail_sm), (
        f"expected the FAILED filter on the failing state machine's arn to include it, got {failed_on_fail_sm}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
