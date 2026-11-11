"""pass-state-result-builder-reads-variable-before-its-own-assign-commits."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pass-state-result-builder-reads-variable-before-its-own-assign-commits"
GROUP = "variables"
SERVICES = ["iam", "stepfunctions"]

_PROPAGATION_MARKERS = ("authorized to assume the provided role", "cannot be assumed")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A state's own result builder reads a variable its own Assign is setting as the value
    from BEFORE this state (Assign and the result run in parallel); the next state sees the new
    value. True in both JSONata (Output) and JSONPath (Parameters)."""
    role_arn = _create_role(ctx)

    nata_arn = _create_state_machine(ctx, _jsonata_definition(), role_arn)
    nata_out = _run(ctx, nata_arn)
    assert nata_out == {"seen": 1, "nextSeen": 2}, (
        f"JSONata: {nata_out!r}, expected the Mutate state's own Output to read $x==1 (set by "
        f"the earlier state) and the next state to read $x==2 (set by Mutate's own Assign)"
    )

    path_arn = _create_state_machine(ctx, _jsonpath_definition(), role_arn)
    path_out = _run(ctx, path_arn)
    assert path_out == {"seen": 1, "nextSeen": 2}, (
        f"JSONPath: {path_out!r}, expected the same parallel Assign/result-builder relationship"
    )


# ===== helpers =====
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _jsonata_definition():
    return {
        "QueryLanguage": "JSONata",
        "StartAt": "Seed",
        "States": {
            "Seed": {"Type": "Pass", "Assign": {"x": 1}, "Next": "Mutate"},
            "Mutate": {
                "Type": "Pass", "Assign": {"x": 2}, "Output": {"seen": "{% $x %}"}, "Next": "Next2",
            },
            "Next2": {"Type": "Pass", "Output": {"seen": "{% $states.input.seen %}",
                                                   "nextSeen": "{% $x %}"}, "End": True},
        },
    }


def _jsonpath_definition():
    return {
        "StartAt": "Seed",
        "States": {
            "Seed": {"Type": "Pass", "Assign": {"x": 1}, "Next": "Mutate"},
            "Mutate": {
                "Type": "Pass", "Assign": {"x": 2}, "Parameters": {"seen.$": "$x"}, "Next": "Next2",
            },
            "Next2": {"Type": "Pass",
                      "Parameters": {"seen.$": "$.seen", "nextSeen.$": "$x"}, "End": True},
        },
    }


def _run(ctx, sm_arn, *, timeout_s=60.0):
    exec_arn, desc = _run_to_terminal(ctx, sm_arn, timeout_s=timeout_s)
    assert desc["status"] == "SUCCEEDED", (
        f"execution {desc['status']!r}: {desc.get('error')!r} {desc.get('cause')!r}"
    )
    return json.loads(desc["output"])


def _create_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnv-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    })
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn variables execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    """CreateStateMachine, retried while the just-created role is still propagating in IAM."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnv-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or not any(
                m in exc.response["Error"]["Message"] for m in _PROPAGATION_MARKERS
            ):
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


def _run_to_terminal(ctx, sm_arn, *, timeout_s, attempts=6):
    """Start a fresh execution while the failure is IAM-trust propagation, not the probe's own."""
    sfn = ctx.client("stepfunctions")
    for _ in range(attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _poll_terminal(ctx, exec_arn, timeout_s=timeout_s)
        if desc["status"] != "FAILED" or not any(
            m in (desc.get("cause") or "") for m in _PROPAGATION_MARKERS
        ):
            return exec_arn, desc
        time.sleep(5)
    raise AssertionError("the execution role's trust policy never finished propagating")


def _poll_terminal(ctx, exec_arn, *, timeout_s, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} did not reach terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="SimCleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
