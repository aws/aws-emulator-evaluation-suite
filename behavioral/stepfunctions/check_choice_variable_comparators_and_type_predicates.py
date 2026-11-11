"""choice-variable-comparators-and-type-predicates."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "choice-variable-comparators-and-type-predicates"
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
    """Start one execution, wait for a terminal status, return (describe, entered_state_names)."""
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
    return desc, _entered_states(ctx, exec_arn)


def _entered_states(ctx, exec_arn):
    """Every state name the execution ENTERED, in order, from the paginated history."""
    sfn = ctx.client("stepfunctions")
    events = []
    token = None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        token = page.get("nextToken")
        if not token:
            break
    return [
        e["stateEnteredEventDetails"]["name"]
        for e in events
        if "stateEnteredEventDetails" in e
    ]


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


def _assert_matched(ctx, sm_arn, input_data, why):
    desc, entered = _run_execution(ctx, sm_arn, input_data)
    assert desc["status"] == "SUCCEEDED", (
        f"input {input_data!r} must succeed, got status={desc.get('status')} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r} -- {why}"
    )
    assert _output(desc) == "matched", (
        f"input {input_data!r} routed to {_output(desc)!r}, expected 'matched' -- {why}"
    )
    assert entered == ["Seed", "Route", "Matched"], (
        f"input {input_data!r} history entered {entered!r}, expected "
        f"['Seed', 'Route', 'Matched'] -- {why}"
    )


def _assert_fell_back(ctx, sm_arn, input_data, why):
    desc, entered = _run_execution(ctx, sm_arn, input_data)
    assert desc["status"] == "SUCCEEDED", (
        f"input {input_data!r} must succeed, got status={desc.get('status')} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r} -- {why}"
    )
    assert _output(desc) == "fell-back", (
        f"input {input_data!r} routed to {_output(desc)!r}, expected 'fell-back' -- {why}"
    )
    assert entered == ["Seed", "Route", "Fallback"], (
        f"input {input_data!r} history entered {entered!r}, expected "
        f"['Seed', 'Route', 'Fallback'] -- {why}"
    )


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Choice `Variable` may itself be `$v`; `*EqualsPath` compares a variable to a literal, a
    literal to a variable, or a variable to a variable; `IsPresent` reads a variable's root, a
    valid path and a missing path; and the `Is*` predicates classify a variable's JSON type.
    """
    role_arn = _execution_role(ctx)

    # ----- *EqualsPath across variable-to-literal, literal-to-variable, variable-to-variable -----
    type_cases = [
        ("Numeric", 10),
        ("String", "ten"),
        ("Boolean", True),
        ("Timestamp", "2024-01-01T00:00:00Z"),
    ]
    for type_name, value in type_cases:
        literal_comparator = f"{type_name}Equals"
        path_comparator = f"{type_name}EqualsPath"

        # variable-to-literal: Variable is a variable, operand is a literal.
        sm = _one_rule_machine(
            ctx, role_arn,
            assign={"v.$": "$.val"},
            rule={"Variable": "$v", literal_comparator: value},
        )
        _assert_matched(
            ctx, sm, {"val": value},
            f"{path_comparator} var-to-literal: $v={value!r} must equal the literal {value!r}",
        )

        # literal-to-variable: Variable is a plain input path, operand path is a variable.
        sm = _one_rule_machine(
            ctx, role_arn,
            assign={"v.$": "$.val2"},
            rule={"Variable": "$.x", path_comparator: "$v"},
        )
        _assert_matched(
            ctx, sm, {"x": value, "val2": value},
            f"{path_comparator} literal-to-variable: $.x={value!r} must equal $v={value!r}",
        )

        # variable-to-variable: both sides are variables.
        sm = _one_rule_machine(
            ctx, role_arn,
            assign={"v1.$": "$.val", "v2.$": "$.val2"},
            rule={"Variable": "$v1", path_comparator: "$v2"},
        )
        _assert_matched(
            ctx, sm, {"val": value, "val2": value},
            f"{path_comparator} variable-to-variable: $v1={value!r} must equal $v2={value!r}",
        )

    # ----- IsPresent on a variable's root, a valid nested path, and a missing nested path -----
    obj_assign = {"v.$": "$.obj"}
    obj_input = {"obj": {"a": {"b": 1}}}

    sm_root = _one_rule_machine(
        ctx, role_arn, assign=obj_assign, rule={"Variable": "$v", "IsPresent": True},
    )
    _assert_matched(ctx, sm_root, obj_input, "an assigned variable's root is always IsPresent:true")

    sm_valid_nested = _one_rule_machine(
        ctx, role_arn, assign=obj_assign, rule={"Variable": "$v.a.b", "IsPresent": True},
    )
    _assert_matched(ctx, sm_valid_nested, obj_input, "$v.a.b exists in the assigned object")

    sm_invalid_nested = _one_rule_machine(
        ctx, role_arn, assign=obj_assign, rule={"Variable": "$v.a.c", "IsPresent": False},
    )
    _assert_matched(
        ctx, sm_invalid_nested, obj_input,
        "$v.a.c does not exist in the assigned object, so IsPresent:false must match",
    )

    sm_invalid_nested_true = _one_rule_machine(
        ctx, role_arn, assign=obj_assign, rule={"Variable": "$v.a.c", "IsPresent": True},
    )
    _assert_fell_back(
        ctx, sm_invalid_nested_true, obj_input,
        "$v.a.c does not exist, so IsPresent:true must NOT match and must fall through to Default",
    )

    # ----- Is{Null,Numeric,String,Boolean,Timestamp} classify a variable's JSON type -----
    predicate_definition = {
        "StartAt": "Seed",
        "States": {
            "Seed": {"Type": "Pass", "Assign": {"v.$": "$.v"}, "Next": "Classify"},
            "Classify": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$v", "IsNull": True, "Next": "Null"},
                    {"Variable": "$v", "IsNumeric": True, "Next": "Numeric"},
                    {"Variable": "$v", "IsBoolean": True, "Next": "Boolean"},
                    {"Variable": "$v", "IsTimestamp": True, "Next": "Timestamp"},
                    {"Variable": "$v", "IsString": True, "Next": "Str"},
                ],
                "Default": "Unclassified",
            },
            "Null": {"Type": "Pass", "Result": "null", "End": True},
            "Numeric": {"Type": "Pass", "Result": "numeric", "End": True},
            "Boolean": {"Type": "Pass", "Result": "boolean", "End": True},
            "Timestamp": {"Type": "Pass", "Result": "timestamp", "End": True},
            "Str": {"Type": "Pass", "Result": "string", "End": True},
            "Unclassified": {"Type": "Pass", "Result": "unclassified", "End": True},
        },
    }
    sm_predicate = _create_state_machine(ctx, predicate_definition, role_arn)

    predicate_cases = [
        ({"v": None}, "null", "a variable holding a JSON null must satisfy IsNull"),
        ({"v": 7}, "numeric", "a variable holding an integer must satisfy IsNumeric"),
        ({"v": 1.5}, "numeric", "a variable holding a float must satisfy IsNumeric"),
        ({"v": True}, "boolean", "a variable holding a boolean is IsBoolean, never IsNumeric"),
        (
            {"v": "2024-01-01T00:00:00Z"},
            "timestamp",
            "a variable holding an RFC3339 string must satisfy IsTimestamp (ordered before IsString)",
        ),
        ({"v": "hello"}, "string", "a variable holding a non-RFC3339 string is IsString only"),
        ({"v": {"nested": 1}}, "unclassified", "a variable holding an object matches none"),
        ({"v": [1, 2]}, "unclassified", "a variable holding an array matches none"),
    ]
    for input_data, expected, why in predicate_cases:
        desc, _entered = _run_execution(ctx, sm_predicate, input_data)
        assert desc["status"] == "SUCCEEDED", (
            f"input {input_data!r} did not reach SUCCEEDED: {desc.get('status')} "
            f"error={desc.get('error')} cause={desc.get('cause')}"
        )
        got = _output(desc)
        assert got == expected, f"input {input_data!r} routed to {got!r}, expected {expected!r} -- {why}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
