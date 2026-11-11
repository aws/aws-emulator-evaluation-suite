"""deep-sfn-2-sfn-jsonata-jsonpath-state-under-jsonata-machine-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-2-sfn-jsonata-jsonpath-state-under-jsonata-machine-rejected"
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
    """A JSONPath state inside a JSONata machine is rejected at create (one SCHEMA_VALIDATION_FAILED
    diagnostic, InvalidDefinition, no machine), while the mirror image (JSONPath machine with a
    JSONata state) validates and runs each state in its own language."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_role(ctx)

    broken = {"QueryLanguage": "JSONata", "StartAt": "P", "States": {
        "P": {"Type": "Pass", "QueryLanguage": "JSONPath", "Next": "Q"},
        "Q": {"Type": "Pass", "Output": {"v": "{% $states.input.v %}"}, "End": True},
    }}
    no_override = {"QueryLanguage": "JSONata", "StartAt": "P", "States": {
        "P": {"Type": "Pass", "Next": "Q"},
        "Q": {"Type": "Pass", "Output": {"v": "{% $states.input.v %}"}, "End": True},
    }}
    mirror = {"QueryLanguage": "JSONPath", "StartAt": "P", "States": {
        "P": {"Type": "Pass", "Parameters": {"v.$": "$.v"}, "Next": "Q"},
        "Q": {"Type": "Pass", "QueryLanguage": "JSONata",
              "Output": {"v": "{% $states.input.v & '-nata' %}"}, "End": True},
    }}

    v = sfn.validate_state_machine_definition(definition=json.dumps(broken), type="STANDARD")
    diags = [(d["severity"], d["code"], d["location"]) for d in v["diagnostics"]]
    assert v["result"] == "FAIL", f"ValidateStateMachineDefinition result {v['result']!r}: {v!r}"
    assert diags == [("ERROR", "SCHEMA_VALIDATION_FAILED", "/States/P")], f"diagnostics {diags!r}"
    assert v["diagnostics"][0]["message"] == (
        "'QueryLanguage' can not be 'JSONPath' if set to 'JSONata' for whole state machine"
    ), f"unexpected diagnostic message {v['diagnostics'][0]['message']!r}"

    for label, definition in (("no-override", no_override), ("mirror", mirror)):
        ok = sfn.validate_state_machine_definition(definition=json.dumps(definition), type="STANDARD")
        assert (ok["result"], ok["diagnostics"]) == ("OK", []), f"{label} must validate, got {ok!r}"

    name = ctx.unique_name("sim2real-behav-sfnj-")
    code, message = _create_error(ctx, name, broken, role_arn)
    assert code == "InvalidDefinition", f"CreateStateMachine with a JSONPath override: {code!r}"
    assert message == (
        "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: 'QueryLanguage' can not be "
        "'JSONPath' if set to 'JSONata' for whole state machine at /States/P'"
    ), f"unexpected InvalidDefinition message {message!r}"
    absent_arn = _sm_arn(ctx, role_arn, name)
    absent, absent_message = _describe_error(ctx, absent_arn)
    assert absent == "StateMachineDoesNotExist", (
        f"a rejected definition must leave no state machine; describe returned {absent!r}"
    )
    assert absent_message == f"State Machine Does Not Exist: '{absent_arn}'", (
        f"unexpected StateMachineDoesNotExist message {absent_message!r}"
    )

    # Positive control: the permitted direction creates and runs, each state in its own language.
    sm_arn = _create_state_machine(ctx, mirror, role_arn, name)
    exe = _run_to_terminal(ctx, sm_arn, {"v": "x", "drop": 1}, timeout_s=60)
    assert exe["status"] == "SUCCEEDED", (
        f"positive control {exe['status']!r}: error={exe.get('error')!r} cause={exe.get('cause')!r}"
    )
    assert json.loads(exe["output"]) == {"v": "x-nata"}, f"positive control output {exe['output']!r}"
    described = ctx.client("stepfunctions").describe_state_machine(stateMachineArn=sm_arn)
    assert json.loads(described["definition"]) == mirror, (
        f"the stored definition does not round-trip: {described['definition']!r}"
    )


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
