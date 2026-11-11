"""deep-sfn-2-sfn-jsonata-pass-states-result-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-2-sfn-jsonata-pass-states-result-rejected"
GROUP = 'jsonata'
SERVICES = ['stepfunctions']


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A JSONata Pass state reading $states.result is rejected at create (an
    UNSUPPORTED_JSONATA_EXPRESSION diagnostic, InvalidDefinition, no machine); the same expression
    in a Task validates, and the Pass state reading $states.input creates and runs."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_role(ctx)

    def machine(state):
        return {"QueryLanguage": "JSONata", "StartAt": "Seed", "States": {
            "Seed": {"Type": "Pass", "Output": {"n": "{% $states.input.n + 1 %}"}, "Next": "P"},
            "P": state,
        }}

    broken = machine({"Type": "Pass", "Output": {"x": "{% $states.result %}"}, "End": True})
    in_task = machine({
        "Type": "Task", "Resource": "arn:aws:states:::aws-sdk:sts:getCallerIdentity",
        "Arguments": {}, "Output": {"x": "{% $states.result %}"}, "End": True,
    })
    fixed = machine({"Type": "Pass", "Output": {"x": "{% $states.input.n * 10 %}"}, "End": True})

    v = sfn.validate_state_machine_definition(definition=json.dumps(broken), type="STANDARD")
    diags = [(d["severity"], d["code"], d["location"]) for d in v["diagnostics"]]
    assert v["result"] == "FAIL", f"ValidateStateMachineDefinition result {v['result']!r}: {v!r}"
    assert diags == [("ERROR", "UNSUPPORTED_JSONATA_EXPRESSION", "/States/P/Output/x")], (
        f"diagnostics {diags!r}"
    )
    assert v["diagnostics"][0]["message"] == "Field '$states.result' does not exist.", (
        f"unexpected diagnostic message {v['diagnostics'][0]['message']!r}"
    )

    ok_task = sfn.validate_state_machine_definition(definition=json.dumps(in_task), type="STANDARD")
    assert (ok_task["result"], ok_task["diagnostics"]) == ("OK", []), (
        f"$states.result in a Task's Output must validate, got {ok_task!r}"
    )

    name = ctx.unique_name("sim2real-behav-sfnj-")
    code, message = _create_error(ctx, name, broken, role_arn)
    assert code == "InvalidDefinition", f"CreateStateMachine with $states.result in a Pass: {code!r}"
    assert message == (
        "Invalid State Machine Definition: 'UNSUPPORTED_JSONATA_EXPRESSION: Field "
        "'$states.result' does not exist. at /States/P/Output/x'"
    ), f"unexpected InvalidDefinition message {message!r}"
    absent_arn = _sm_arn(ctx, role_arn, name)
    absent, absent_message = _describe_error(ctx, absent_arn)
    assert absent == "StateMachineDoesNotExist", (
        f"a rejected definition must leave no state machine; describe returned {absent!r}"
    )
    assert absent_message == f"State Machine Does Not Exist: '{absent_arn}'", (
        f"unexpected StateMachineDoesNotExist message {absent_message!r}"
    )

    # Positive control: the same machine, the Pass state reading $states.input instead.
    sm_arn = _create_state_machine(ctx, fixed, role_arn, name)
    exe = _run_to_terminal(ctx, sm_arn, {"n": 4}, timeout_s=60)
    assert exe["status"] == "SUCCEEDED", (
        f"positive control {exe['status']!r}: error={exe.get('error')!r} cause={exe.get('cause')!r}"
    )
    assert json.loads(exe["output"]) == {"x": 50}, f"positive control output {exe['output']!r}"


# ===== helpers =====
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
_PROPAGATION_MARKERS = ("not authorized", "AccessDenied", "cannot be assumed", "States.Permissions")


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}]


def _create_role(ctx):
    """A bare execution role: the positive control runs only Pass states."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnj-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn jsonata execution role", Tags=_tags_kv(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _sm_arn(ctx, role_arn, name):
    partition = role_arn.split(":")[1]
    account = role_arn.split(":")[4]
    return f"arn:{partition}:states:{ctx.region}:{account}:stateMachine:{name}"


def _create_error(ctx, name, definition, role_arn):
    """The error (code, message) CreateStateMachine raised. A create that SUCCEEDS is torn down and failed."""
    sfn = ctx.client("stepfunctions")
    try:
        arn = sfn.create_state_machine(
            name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
            tags=[{"key": "sim2real", "value": CHECK}],
        )["stateMachineArn"]
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    raise AssertionError(f"CreateStateMachine accepted a definition real AWS rejects: {arn!r}")


def _describe_error(ctx, sm_arn):
    """The error (code, message) DescribeStateMachine raised. A describe that succeeds fails."""
    try:
        resp = ctx.client("stepfunctions").describe_state_machine(stateMachineArn=sm_arn)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"state machine {sm_arn!r} exists with status {resp.get('status')!r}")


def _create_state_machine(ctx, definition, role_arn, name):
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_state_machine(
        name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
        tags=[{"key": "sim2real", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_to_terminal(ctx, sm_arn, input_data, *, timeout_s, max_attempts=4):
    """Start an execution and poll it to terminal; restart only on the IAM-propagation race."""
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(max_attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(input_data),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return desc
        time.sleep(5)
    return desc


def _wait_terminal(ctx, exec_arn, *, timeout_s, interval_s=1.0):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
