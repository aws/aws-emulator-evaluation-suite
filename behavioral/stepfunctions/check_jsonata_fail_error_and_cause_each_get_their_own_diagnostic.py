"""jsonata-fail-error-and-cause-each-get-their-own-diagnostic."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "jsonata-fail-error-and-cause-each-get-their-own-diagnostic"
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
        Description="sim2real-behav sfn jsonata fail-state execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _sm_arn(ctx, role_arn, name):
    partition = role_arn.split(":")[1]
    account = role_arn.split(":")[4]
    return f"arn:{partition}:states:{ctx.region}:{account}:stateMachine:{name}"


def _create_error(ctx, name, definition, role_arn):
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
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


# ===== end helpers =====


def _diag(sfn, definition):
    v = sfn.validate_state_machine_definition(definition=json.dumps(definition), type="STANDARD")
    return v["result"], [
        (d["severity"], d["code"], d["location"], d["message"]) for d in v["diagnostics"]
    ]


_UNCLOSED = "JSONata string must start with {% and end with %}"


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
    """A Fail state's `Error` and `Cause` are validated independently: breaking one produces
    exactly one diagnostic naming that field, and breaking both produces two, never one
    diagnostic standing in for the other.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/amazon-states-language-fail-state.html
    """
    sfn = ctx.client("stepfunctions")

    def fail_machine(error, cause):
        return {
            "QueryLanguage": "JSONata",
            "StartAt": "F",
            "States": {"F": {"Type": "Fail", "Error": error, "Cause": cause}},
        }

    only_error_bad = fail_machine("{% bad", "plain cause")
    result, diags = _diag(sfn, only_error_bad)
    assert result == "FAIL", f"expected FAIL, got {result!r}: {diags!r}"
    assert diags == [("ERROR", "SCHEMA_VALIDATION_FAILED", "/States/F/Error", _UNCLOSED)], (
        f"a bad Error alone must produce exactly one diagnostic naming /States/F/Error: {diags!r}"
    )

    only_cause_bad = fail_machine("plain error", "{% bad")
    result, diags = _diag(sfn, only_cause_bad)
    assert result == "FAIL", f"expected FAIL, got {result!r}: {diags!r}"
    assert diags == [("ERROR", "SCHEMA_VALIDATION_FAILED", "/States/F/Cause", _UNCLOSED)], (
        f"a bad Cause alone must produce exactly one diagnostic naming /States/F/Cause: {diags!r}"
    )

    both_bad = fail_machine("{% bad", "{% alsobad")
    result, diags = _diag(sfn, both_bad)
    assert result == "FAIL", f"expected FAIL, got {result!r}: {diags!r}"
    assert diags == [
        ("ERROR", "SCHEMA_VALIDATION_FAILED", "/States/F/Error", _UNCLOSED),
        ("ERROR", "SCHEMA_VALIDATION_FAILED", "/States/F/Cause", _UNCLOSED),
    ], f"a bad Error and a bad Cause must each get their own diagnostic, in field order: {diags!r}"

    valid = fail_machine("MyError", "my cause text")
    v_ok = sfn.validate_state_machine_definition(definition=json.dumps(valid), type="STANDARD")
    assert (v_ok["result"], v_ok["diagnostics"]) == ("OK", []), (
        f"plain Error/Cause strings need no {{% %}} wrapping, got {v_ok!r}"
    )

    role_arn = _create_role(ctx)
    name = ctx.unique_name("sim2real-behav-sfnj-")
    code, message = _create_error(ctx, name, both_bad, role_arn)
    assert code == "InvalidDefinition", f"CreateStateMachine with both fields bad: {code!r}"
    assert message == (
        "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: JSONata string must start "
        "with {% and end with %} at /States/F/Error, SCHEMA_VALIDATION_FAILED: JSONata string "
        "must start with {% and end with %} at /States/F/Cause'"
    ), f"unexpected InvalidDefinition message {message!r}"
    absent_arn = _sm_arn(ctx, role_arn, name)
    absent, absent_message = _describe_error(ctx, absent_arn)
    assert absent == "StateMachineDoesNotExist", (
        f"a rejected definition must leave no state machine; describe returned {absent!r}"
    )
    assert absent_message == f"State Machine Does Not Exist: '{absent_arn}'", (
        f"unexpected StateMachineDoesNotExist message {absent_message!r}"
    )

    # Positive control: the valid Fail state creates, runs, and carries its literal Error/Cause.
    sm_arn = _create_state_machine(ctx, valid, role_arn, name)
    exe = _run_to_terminal(ctx, sm_arn, {})
    assert exe["status"] == "FAILED", f"a Fail state must terminate FAILED, got {exe['status']!r}"
    assert exe.get("error") == "MyError", f"expected error 'MyError', got {exe.get('error')!r}"
    assert exe.get("cause") == "my cause text", (
        f"expected cause 'my cause text', got {exe.get('cause')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
