"""deep-sfn-language-fail-error-path-cause-path-intrinsics-and-context."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-fail-error-path-cause-path-intrinsics-and-context"
GROUP = 'fail_state'
SERVICES = ['stepfunctions']


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Fail state's ErrorPath may itself be an intrinsic (States.JsonToString) and its
    CausePath's States.Format may read the $$.State.Name/$$.StateMachine.Name context object,
    scoped to the state actually executing even from inside a Parallel branch.
    """
    fail = {"Type": "Fail", "ErrorPath": "States.JsonToString($.a)",
            "CausePath": "States.Format('{} in {} failed', $$.State.Name, $$.StateMachine.Name)"}
    role = _create_sfn_role(ctx)
    direct_arn, direct_name = _create_state_machine(ctx, {"StartAt": "F", "States": {"F": dict(fail)}}, role)
    par_arn, par_name = _create_state_machine(ctx, {
        "StartAt": "Par",
        "States": {
            "Par": {"Type": "Parallel", "Next": "After", "Branches": [
                {"StartAt": "BF", "States": {"BF": dict(fail)}},
                {"StartAt": "Slow", "States": {
                    "Slow": {"Type": "Wait", "Seconds": 60, "Next": "SlowDone"},
                    "SlowDone": {"Type": "Succeed"}}},
            ]},
            "After": {"Type": "Pass", "End": True},
        },
    }, role)

    payload = {"a": {"orderId": 42, "reason": "no stock"}}
    want_error = json.dumps(payload["a"], separators=(",", ":"))

    for arn, name, state_name in ((direct_arn, direct_name, "F"), (par_arn, par_name, "BF")):
        desc = _run_execution(ctx, arn, payload)
        want_cause = f"{state_name} in {name} failed"
        assert desc["status"] == "FAILED", f"{name}: expected FAILED, got {desc['status']!r}"
        assert desc.get("error") == want_error, (
            f"ErrorPath's States.JsonToString must land verbatim as the execution error, "
            f"expected {want_error!r}, got {desc.get('error')!r}"
        )
        assert desc.get("cause") == want_cause, (
            f"CausePath's States.Format must resolve $$.State.Name/$$.StateMachine.Name to "
            f"{want_cause!r}, got {desc.get('cause')!r}"
        )
        events = _history(ctx, desc["executionArn"])
        failed = [e["executionFailedEventDetails"] for e in events if e["type"] == "ExecutionFailed"]
        assert failed == [{"error": want_error, "cause": want_cause}], (
            f"the ExecutionFailed event must carry the same error/cause, got {failed!r}"
        )


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _create_sfn_role(ctx, statements=None):
    """An execution role this check owns. Pass/Choice/Wait/Fail/Parallel machines need no
    permissions, but CreateStateMachine still requires a role Step Functions can assume."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnlang-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn language check role",
        Tags=[{"Key": "sim2real", "Value": "sfn-language"}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=f"{role_name}-policy",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    """Create a STANDARD machine, absorbing IAM trust propagation with a bounded retry.
    Returns (arn, name): the name is load-bearing for the $$.StateMachine.Name assertion.
    """
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnlang-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "sfn-language"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn, name
    raise AssertionError(f"CreateStateMachine kept refusing the freshly created role: {last!r}")


def _stop_if_running(sfn, exec_arn):
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn, error="sim2real.cleanup")


def _run_execution(ctx, sm_arn, payload, *, timeout_s=150.0):
    """Start one execution and poll DescribeExecution until it is terminal."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-x-"), input=json.dumps(payload)
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] in _TERMINAL:
            return desc
        time.sleep(2)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {desc!r}")


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events = []
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        events.extend(page["events"])
    return events


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
