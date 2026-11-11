"""deep-sfn-language-fail-error-path-cause-path-reach-execution."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-fail-error-path-cause-path-reach-execution"
GROUP = 'fail_state'
SERVICES = ['stepfunctions']


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Fail state's ErrorPath and States.Format CausePath are evaluated and land verbatim in the
    execution error/cause and ExecutionFailed event, also from inside a Parallel branch, which fails
    the Parallel without reaching the next state.
    """
    fail = {"Type": "Fail", "ErrorPath": "$.code",
            "CausePath": "States.Format('order {} failed: {}', $.id, $.why)"}
    role = _create_sfn_role(ctx)
    direct_arn = _create_state_machine(ctx, {"StartAt": "F", "States": {"F": dict(fail)}}, role)
    par_arn = _create_state_machine(ctx, {
        "StartAt": "Par",
        "States": {
            "Par": {"Type": "Parallel", "Next": "After", "Branches": [
                {"StartAt": "BF", "States": {"BF": dict(fail)}},
                # The sibling's long Wait must not keep the execution alive once BF fails.
                {"StartAt": "Slow", "States": {
                    "Slow": {"Type": "Wait", "Seconds": 60, "Next": "SlowDone"},
                    "SlowDone": {"Type": "Succeed"}}},
            ]},
            "After": {"Type": "Pass", "End": True},
        },
    }, role)

    for arn, code, oid in ((direct_arn, "Order.Rejected", 42), (par_arn, "Branch.Dynamic", 77)):
        desc = _run_execution(ctx, arn, {"code": code, "id": oid, "why": "no stock"})
        want_cause = f"order {oid} failed: no stock"
        assert desc["status"] == "FAILED", f"{code}: expected FAILED, got {desc['status']!r}"
        assert desc.get("error") == code, (
            f"DescribeExecution.error must be the ErrorPath value {code!r}, got {desc.get('error')!r}"
        )
        assert desc.get("cause") == want_cause, (
            f"DescribeExecution.cause must be the evaluated CausePath {want_cause!r}, "
            f"got {desc.get('cause')!r}"
        )
        events = _history(ctx, desc["executionArn"])
        failed = [e["executionFailedEventDetails"] for e in events if e["type"] == "ExecutionFailed"]
        assert failed == [{"error": code, "cause": want_cause}], (
            f"the ExecutionFailed event must carry the same error/cause, got {failed!r}"
        )
        if arn == par_arn:
            assert "After" not in _entered(events), (
                f"a failed branch must fail the Parallel; 'After' was entered: {_entered(events)!r}"
            )
            par_failed = [e for e in events if e["type"] == "ParallelStateFailed"]
            assert len(par_failed) == 1, (
                f"expected one ParallelStateFailed event, got types "
                f"{[e['type'] for e in events]!r}"
            )


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _create_sfn_role(ctx, statements=None):
    """An execution role this check owns. Pass/Choice/Wait/Fail machines need no permissions,
    but CreateStateMachine still requires a role Step Functions can assume."""
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
    """Create a STANDARD machine, absorbing IAM trust propagation with a bounded retry."""
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
        return arn
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
        time.sleep(1)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {desc!r}")


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events = []
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        events.extend(page["events"])
    return events


def _entered(events):
    """Names of every state entered, in history order."""
    return [e["stateEnteredEventDetails"]["name"] for e in events
            if e["type"].endswith("StateEntered")]


def _exited(events):
    return [e["stateExitedEventDetails"]["name"] for e in events
            if e["type"].endswith("StateExited")]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
