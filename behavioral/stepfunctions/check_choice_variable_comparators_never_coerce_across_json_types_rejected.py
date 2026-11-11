"""choice-variable-comparators-never-coerce-across-json-types-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "choice-variable-comparators-never-coerce-across-json-types-rejected"
GROUP = 'choice_state'
SERVICES = ['stepfunctions']


_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _execution_role(ctx):
    """A permissionless execution role: Choice and Pass never assume it, but CreateStateMachine
    still requires a passable role ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-choice-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST),
        Description="sim2real-choice: throwaway Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "choice"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-choice-sm-")
    deadline = time.monotonic() + 60
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "choice"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_execution(ctx, sm_arn, input_data, *, timeout_s=60):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn,
        name=ctx.unique_name("sim2real-choice-ex-"),
        input=json.dumps(input_data),
    )["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] != "RUNNING":
            break
        time.sleep(0.5)
    else:
        raise AssertionError(
            f"execution for input {input_data!r} never reached a terminal status within "
            f"{timeout_s}s; last describe was {desc!r}"
        )
    return desc


def _output(desc):
    raw = desc.get("output")
    return None if raw is None else json.loads(raw)


def _one_rule_machine(ctx, role_arn, *, assign, rule):
    """A Seed (Assign) -> one-rule Choice -> Matched/Fallback machine."""
    definition = {
        "StartAt": "Seed",
        "States": {
            "Seed": {"Type": "Pass", "Assign": assign, "Next": "Route"},
            "Route": {
                "Type": "Choice",
                "Choices": [{**rule, "Next": "Matched"}],
                "Default": "Fallback",
            },
            "Matched": {"Type": "Pass", "Result": "matched", "End": True},
            "Fallback": {"Type": "Pass", "Result": "fell-back", "End": True},
        },
    }
    return _create_state_machine(ctx, definition, role_arn)


def _assert_no_coerce(ctx, sm_arn, input_data, why):
    """The rule must evaluate to false (fall through, SUCCEEDED, no error) -- never throw."""
    desc = _run_execution(ctx, sm_arn, input_data)
    assert desc["status"] == "SUCCEEDED", (
        f"a type mismatch on a variable comparator must evaluate to false and fall through to "
        f"Default, not fail the execution; input {input_data!r} gave status={desc.get('status')} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r} -- {why}"
    )
    assert desc.get("error") is None, (
        f"a type-mismatched variable comparison must carry no error; input {input_data!r} "
        f"reported error={desc.get('error')!r} cause={desc.get('cause')!r} -- {why}"
    )
    assert _output(desc) == "fell-back", (
        f"input {input_data!r} must NOT match; expected Default output 'fell-back', got "
        f"{_output(desc)!r} -- {why}"
    )


def _assert_matched(ctx, sm_arn, input_data, why):
    desc = _run_execution(ctx, sm_arn, input_data)
    assert desc["status"] == "SUCCEEDED", (
        f"input {input_data!r} control must succeed, got status={desc.get('status')} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r} -- {why}"
    )
    assert _output(desc) == "matched", (
        f"input {input_data!r} control routed to {_output(desc)!r}, expected 'matched' -- {why}"
    )


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Choice `*EqualsPath` comparator on a variable matches only its own JSON type -- no
    `"10" == 10`, no `1 == true` -- whether the mismatch is on the variable side, the literal
    side, or both sides are variables; a type mismatch is a silent non-match, never a failure.
    """
    role_arn = _execution_role(ctx)

    # ----- variable-to-literal: $v compared to a literal of a DIFFERENT JSON type -----
    var_to_literal_cases = [
        ("NumericEquals", 10, [("val", "10"), ("val", True), ("val", None), ("val", [10])]),
        ("StringEquals", "10", [("val", 10), ("val", 10.0), ("val", True), ("val", None)]),
        ("BooleanEquals", True, [("val", "true"), ("val", 1), ("val", None)]),
    ]
    for comparator, operand, mismatches in var_to_literal_cases:
        sm = _one_rule_machine(
            ctx, role_arn, assign={"v.$": "$.val"}, rule={"Variable": "$v", comparator: operand},
        )
        _assert_matched(
            ctx, sm, {"val": operand},
            f"{comparator}:{operand!r} control: $v={operand!r} must match the same-typed literal",
        )
        for key, value in mismatches:
            _assert_no_coerce(
                ctx, sm, {key: value},
                f"{comparator}:{operand!r} on $v={value!r} (type {type(value).__name__})",
            )

    # ----- literal-to-variable: $.x compared against a variable of a DIFFERENT JSON type -----
    sm_lit_to_var = _one_rule_machine(
        ctx, role_arn, assign={"v.$": "$.val"}, rule={"Variable": "$.x", "NumericEqualsPath": "$v"},
    )
    _assert_matched(
        ctx, sm_lit_to_var, {"x": 10, "val": 10},
        "NumericEqualsPath literal-to-variable control: $.x=10 must equal $v=10",
    )
    _assert_no_coerce(
        ctx, sm_lit_to_var, {"x": 10, "val": "10"},
        "NumericEqualsPath literal-to-variable: $.x=10 (number) must not equal $v='10' (string)",
    )

    # ----- variable-to-variable: both sides are variables, of different JSON types -----
    sm_var_to_var = _one_rule_machine(
        ctx, role_arn, assign={"v1.$": "$.a", "v2.$": "$.b"},
        rule={"Variable": "$v1", "BooleanEqualsPath": "$v2"},
    )
    _assert_matched(
        ctx, sm_var_to_var, {"a": True, "b": True},
        "BooleanEqualsPath variable-to-variable control: $v1=true must equal $v2=true",
    )
    _assert_no_coerce(
        ctx, sm_var_to_var, {"a": True, "b": 1},
        "BooleanEqualsPath variable-to-variable: $v1=true (boolean) must not equal $v2=1 (number)",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
