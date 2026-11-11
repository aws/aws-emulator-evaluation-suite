"""choice-jsonata-evaluation-order-condition-output-assign."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "choice-jsonata-evaluation-order-condition-output-assign"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


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
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: _ROLE_ARNS.pop(key, None))
    _ROLE_ARNS[key] = arn
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retried while a just-created role is still propagating in IAM."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn, name=name, definition=json.dumps(definition), roleArn=_execution_role_arn(ctx),
        type="STANDARD", tags=[{"key": "sim2real", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run(ctx, sm_arn, input_data, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(input_data))["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] != "RUNNING":
            break
        time.sleep(0.5)
    else:
        raise AssertionError(f"execution for input {input_data!r} never reached terminal: {desc!r}")
    return desc


_EVAL_ERROR = "States.QueryEvaluationError"
_BAD_LEFT_SIDE = 'T2001: The left side of the "+" operator must evaluate to a number'


def _assert_evaluation_error(desc, *, location, expr, field_label):
    assert desc["status"] == "FAILED", f"expected FAILED for the {field_label} case, got {desc!r}"
    assert desc.get("error") == _EVAL_ERROR, f"expected {_EVAL_ERROR!r}, got {desc.get('error')!r}"
    cause = desc.get("cause") or ""
    assert f"specified for the field '{location}'" in cause, (
        f"expected the {field_label} case to name field {location!r}, got cause {cause!r}"
    )
    assert f"The JSONata expression '{expr}'" in cause, (
        f"expected the {field_label} case to quote expression {expr!r}, got cause {cause!r}"
    )
    assert _BAD_LEFT_SIDE in cause, f"expected the {field_label} case cause to end in {_BAD_LEFT_SIDE!r}, got {cause!r}"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A JSONata Choice state with several bad fields reports the FIRST one in evaluation order:
    on a matched rule, Condition, then Output, then Assign; on the Default path (no per-rule
    Output/Assign to evaluate), the state's own Output before its Assign.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/state-choice.html
    """
    cond_expr = "$states.input.condBad ? ($states.input.c + 1) : true"
    out_expr = "$states.input.outBad ? ($states.input.o + 1) : 'rule-output'"
    assign_expr = "$states.input.assignBad ? ($states.input.a + 1) : 'rule-assign'"
    rule_definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "C",
        "States": {
            "C": {
                "Type": "Choice",
                "Choices": [
                    {
                        "Condition": "{% " + cond_expr + " %}",
                        "Output": "{% " + out_expr + " %}",
                        "Assign": {"z": "{% " + assign_expr + " %}"},
                        "Next": "Done",
                    }
                ],
                "Default": "Done",
            },
            "Done": {"Type": "Pass", "Output": "{% {'out': $states.input, 'z': $z} %}", "End": True},
        },
    }
    sm_rule = _create_state_machine(ctx, rule_definition)
    base_input = {"c": "bad", "o": "bad", "a": "bad"}

    # Positive control: nothing bad, the rule matches, and both the rule's Output and its Assign
    # are visible downstream.
    desc = _run(ctx, sm_rule, {**base_input, "condBad": False, "outBad": False, "assignBad": False})
    assert desc["status"] == "SUCCEEDED", f"the control execution must succeed, got {desc!r}"
    assert json.loads(desc["output"]) == {"out": "rule-output", "z": "rule-assign"}, (
        f"expected the rule's Output and Assign to both reach Done, got {desc.get('output')!r}"
    )

    # Condition, Output and Assign are all bad: Condition is reported, since it evaluates first.
    desc = _run(ctx, sm_rule, {**base_input, "condBad": True, "outBad": True, "assignBad": True})
    _assert_evaluation_error(desc, location="Choices[0]/Condition", expr=cond_expr, field_label="all-three-bad")

    # Condition is good (matches); Output and Assign are both bad: Output is reported before
    # Assign.
    desc = _run(ctx, sm_rule, {**base_input, "condBad": False, "outBad": True, "assignBad": True})
    _assert_evaluation_error(desc, location="Choices[0]/Output", expr=out_expr, field_label="output-and-assign-bad")

    # Condition and Output are both good; only Assign is bad: Assign is reported.
    desc = _run(ctx, sm_rule, {**base_input, "condBad": False, "outBad": False, "assignBad": True})
    _assert_evaluation_error(desc, location="Choices[0]/Assign/z", expr=assign_expr, field_label="only-assign-bad")

    # On the Default path there is no per-rule Output/Assign to evaluate; the state's own Output
    # and Assign apply instead, in the same order: Output before Assign.
    default_out_expr = "$states.input.outBad ? ($states.input.o + 1) : 'default-output'"
    default_assign_expr = "$states.input.assignBad ? ($states.input.a + 1) : 'default-assign'"
    default_definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "C",
        "States": {
            "C": {
                "Type": "Choice",
                "Choices": [{"Condition": "{% false %}", "Next": "Done"}],
                "Default": "Done",
                "Output": "{% " + default_out_expr + " %}",
                "Assign": {"z": "{% " + default_assign_expr + " %}"},
            },
            "Done": {"Type": "Pass", "Output": "{% {'out': $states.input, 'z': $z} %}", "End": True},
        },
    }
    sm_default = _create_state_machine(ctx, default_definition)

    desc = _run(ctx, sm_default, {"outBad": False, "assignBad": False, "o": "bad", "a": "bad"})
    assert desc["status"] == "SUCCEEDED", f"the default-path control execution must succeed, got {desc!r}"
    assert json.loads(desc["output"]) == {"out": "default-output", "z": "default-assign"}, (
        f"expected the Default state's own Output and Assign to both reach Done, got {desc.get('output')!r}"
    )

    desc = _run(ctx, sm_default, {"outBad": True, "assignBad": True, "o": "bad", "a": "bad"})
    _assert_evaluation_error(desc, location="Output", expr=default_out_expr, field_label="default-output-and-assign-bad")

    desc = _run(ctx, sm_default, {"outBad": False, "assignBad": True, "o": "bad", "a": "bad"})
    _assert_evaluation_error(desc, location="Assign/z", expr=default_assign_expr, field_label="default-only-assign-bad")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
