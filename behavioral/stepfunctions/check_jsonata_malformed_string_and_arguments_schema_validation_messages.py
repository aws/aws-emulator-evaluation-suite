"""jsonata-malformed-string-and-arguments-schema-validation-messages."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "jsonata-malformed-string-and-arguments-schema-validation-messages"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


# ===== helpers =====
def _create_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnj-")
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
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn jsonata validation execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
            name=name,
            definition=json.dumps(definition),
            roleArn=role_arn,
            type="STANDARD",
            tags=[{"key": "sim2real", "value": CHECK}],
        )["stateMachineArn"]
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    raise AssertionError(f"CreateStateMachine accepted a definition it rejects: {arn!r}")


def _describe_error(ctx, sm_arn):
    try:
        resp = ctx.client("stepfunctions").describe_state_machine(stateMachineArn=sm_arn)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"state machine {sm_arn!r} exists with status {resp.get('status')!r}")


def _create_state_machine(ctx, definition, role_arn, name):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] != "AccessDeniedException"
                or time.monotonic() > deadline
            ):
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_to_terminal(ctx, sm_arn, input_data, *, timeout_s=60):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps(input_data),
    )["executionArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_arn))
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="cleanup", cause="sim2real cleanup"
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


# ===== end helpers =====


def _diag_fail(sfn, definition):
    v = sfn.validate_state_machine_definition(definition=json.dumps(definition), type="STANDARD")
    assert v["result"] == "FAIL", f"ValidateStateMachineDefinition result {v['result']!r}: {v!r}"
    return [(d["severity"], d["code"], d["location"], d["message"]) for d in v["diagnostics"]]


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """ValidateStateMachineDefinition reports one SCHEMA_VALIDATION_FAILED diagnostic per malformed
    JSONata field, with the exact location and one of four distinct messages: a plain string where
    only JSONata is permitted, an unclosed `{% ... %}`, a non-object Arguments, a null Arguments.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-amazon-states-language.html
    """
    sfn = ctx.client("stepfunctions")

    def route_machine(condition):
        return {
            "QueryLanguage": "JSONata",
            "StartAt": "Route",
            "States": {
                "Route": {
                    "Type": "Choice",
                    "Choices": [{"Condition": condition, "Next": "A"}],
                    "Default": "B",
                },
                "A": {"Type": "Pass", "End": True},
                "B": {"Type": "Pass", "End": True},
            },
        }

    def task_machine(arguments):
        return {
            "QueryLanguage": "JSONata",
            "StartAt": "T",
            "States": {
                "T": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::aws-sdk:sts:getCallerIdentity",
                    "Arguments": arguments,
                    "End": True,
                }
            },
        }

    plain_string = route_machine("true")
    assert _diag_fail(sfn, plain_string) == [
        (
            "ERROR",
            "SCHEMA_VALIDATION_FAILED",
            "/States/Route/Choices[0]/Condition",
            "Only JSONata strings starting with {% and ending with %} are permitted",
        )
    ], f"plain-string Condition diagnostics: {_diag_fail(sfn, plain_string)!r}"

    unclosed = route_machine("{% true")
    assert _diag_fail(sfn, unclosed) == [
        (
            "ERROR",
            "SCHEMA_VALIDATION_FAILED",
            "/States/Route/Choices[0]/Condition",
            "JSONata string must start with {% and end with %}",
        )
    ], f"unclosed Condition diagnostics: {_diag_fail(sfn, unclosed)!r}"

    non_object_args = task_machine(5)
    assert _diag_fail(sfn, non_object_args) == [
        (
            "ERROR",
            "SCHEMA_VALIDATION_FAILED",
            "/States/T/Arguments",
            "The value for the field 'Arguments' must be a JSON object or a JSONata string",
        )
    ], f"non-object Arguments diagnostics: {_diag_fail(sfn, non_object_args)!r}"

    null_args = task_machine(None)
    assert _diag_fail(sfn, null_args) == [
        (
            "ERROR",
            "SCHEMA_VALIDATION_FAILED",
            "/States/T/Arguments",
            "The value for the 'Arguments' field cannot be null",
        )
    ], f"null Arguments diagnostics: {_diag_fail(sfn, null_args)!r}"

    valid = route_machine("{% true %}")
    v_ok = sfn.validate_state_machine_definition(definition=json.dumps(valid), type="STANDARD")
    assert (v_ok["result"], v_ok["diagnostics"]) == ("OK", []), (
        f"a correctly wrapped JSONata string must validate cleanly, got {v_ok!r}"
    )

    # CreateStateMachine mirrors the static check and leaves no state machine behind.
    role_arn = _create_role(ctx)
    name = ctx.unique_name("sim2real-behav-sfnj-")
    code, message = _create_error(ctx, name, null_args, role_arn)
    assert code == "InvalidDefinition", f"CreateStateMachine with null Arguments: {code!r}"
    assert message == (
        "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: The value for the "
        "'Arguments' field cannot be null at /States/T/Arguments'"
    ), f"unexpected InvalidDefinition message {message!r}"
    absent_arn = _sm_arn(ctx, role_arn, name)
    absent, absent_message = _describe_error(ctx, absent_arn)
    assert absent == "StateMachineDoesNotExist", (
        f"a rejected definition must leave no state machine; describe returned {absent!r}"
    )
    assert absent_message == f"State Machine Does Not Exist: '{absent_arn}'", (
        f"unexpected StateMachineDoesNotExist message {absent_message!r}"
    )

    # Positive control: the valid Condition both creates and routes.
    sm_arn = _create_state_machine(ctx, valid, role_arn, name)
    exe = _run_to_terminal(ctx, sm_arn, {})
    assert exe["status"] == "SUCCEEDED", (
        f"positive control {exe['status']!r}: error={exe.get('error')!r} cause={exe.get('cause')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
