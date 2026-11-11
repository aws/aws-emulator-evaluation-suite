"""sfn-jsonata-undefined-result-query-evaluation-error."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-jsonata-undefined-result-query-evaluation-error"
GROUP = 'jsonata'
SERVICES = ['stepfunctions']

_UNDEFINED = "{% $states.input.missing %}"
_EVAL_ERROR = "States.QueryEvaluationError"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A JSONata expression that evaluates to undefined fails the execution with
    States.QueryEvaluationError naming the field that returned nothing, in Output, Assign or
    Arguments, at the field's top level, inside an array or inside an object.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/concepts-variables.html
    """
    role_arn = _execution_role(ctx)
    fake_target_arn = (
        f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:"
        f"{ctx.unique_name('sim2real-behav-undef-target-')}"
    )

    cases = [
        ("Output/top-level", _pass_def({"Output": _UNDEFINED}), "Output"),
        ("Output/array", _pass_def({"Output": [_UNDEFINED]}), "Output[0]"),
        ("Output/object", _pass_def({"Output": {"field": _UNDEFINED}}), "Output/field"),
        ("Assign/top-level", _pass_def({"Assign": {"v": _UNDEFINED}}), "Assign/v"),
        ("Assign/array", _pass_def({"Assign": {"v": [_UNDEFINED]}}), "Assign/v[0]"),
        ("Assign/object", _pass_def({"Assign": {"v": {"field": _UNDEFINED}}}), "Assign/v/field"),
        ("Arguments/top-level", _task_def(
            "arn:aws:states:::aws-sdk:sts:getCallerIdentity", _UNDEFINED), "Arguments"),
        ("Arguments/array", _task_def(
            "arn:aws:states:::aws-sdk:sfn:tagResource",
            {"ResourceArn": fake_target_arn, "Tags": [{"Key": "k", "Value": _UNDEFINED}]}),
            "Arguments/Tags[0]/Value"),
        ("Arguments/object", _task_def(
            "arn:aws:states:::states:startExecution",
            {"StateMachineArn": fake_target_arn, "Input": {"field": _UNDEFINED}}),
            "Arguments/Input/field"),
    ]

    for label, definition, expected_location in cases:
        sm_arn = _create_state_machine(ctx, definition, role_arn)
        desc = _run_to_terminal(ctx, sm_arn)
        assert desc["status"] == "FAILED", (
            f"[{label}] an undefined result must FAIL the execution, got {desc['status']!r} "
            f"output={desc.get('output')!r}"
        )
        assert desc.get("error") == _EVAL_ERROR, (
            f"[{label}] expected error {_EVAL_ERROR!r}, got {desc.get('error')!r} "
            f"(cause={desc.get('cause')!r})"
        )
        cause = desc.get("cause") or ""
        assert "returned nothing (undefined)" in cause, (
            f"[{label}] the cause must say the expression returned nothing; got {cause!r}"
        )
        assert desc.get("output") is None, (
            f"[{label}] a rejected execution must carry no output, got {desc.get('output')!r}"
        )
        events = _eval_failed(ctx, desc["executionArn"])
        assert len(events) == 1, f"[{label}] expected one EvaluationFailed, got {events!r}"
        assert events[0]["location"] == expected_location, (
            f"[{label}] EvaluationFailed location {events[0]['location']!r}, expected "
            f"{expected_location!r}"
        )
        assert events[0]["error"] == _EVAL_ERROR, f"[{label}] EvaluationFailed {events[0]!r}"
        assert events[0]["cause"] == cause, (
            f"[{label}] DescribeExecution cause {cause!r} and the history event's cause "
            f"{events[0]['cause']!r} must agree"
        )

    # Positive controls: the same three field kinds, defined, actually succeed.
    output_ok_arn = _create_state_machine(
        ctx, _pass_def({"Output": "{% 'defined' %}"}), role_arn)
    output_ok = _run_to_terminal(ctx, output_ok_arn)
    assert output_ok["status"] == "SUCCEEDED", (
        f"Output positive control ended {output_ok['status']!r}: "
        f"{output_ok.get('error')!r} {output_ok.get('cause')!r}"
    )
    assert output_ok["output"] == json.dumps("defined"), (
        f"Output positive control output {output_ok.get('output')!r}"
    )

    # A state's own Assign takes effect for states entered AFTER it, never its own Output.
    assign_ok_arn = _create_state_machine(ctx, {
        "QueryLanguage": "JSONata",
        "StartAt": "A",
        "States": {
            "A": {"Type": "Pass", "Assign": {"v": "{% 'defined' %}"}, "Next": "B"},
            "B": {"Type": "Pass", "Output": "{% $v %}", "End": True},
        },
    }, role_arn)
    assign_ok = _run_to_terminal(ctx, assign_ok_arn)
    assert assign_ok["status"] == "SUCCEEDED", (
        f"Assign positive control ended {assign_ok['status']!r}: "
        f"{assign_ok.get('error')!r} {assign_ok.get('cause')!r}"
    )
    assert assign_ok["output"] == json.dumps("defined"), (
        f"Assign positive control output {assign_ok.get('output')!r}"
    )

    args_ok_arn = _create_state_machine(
        ctx, _task_def("arn:aws:states:::aws-sdk:sts:getCallerIdentity", "{% {} %}"), role_arn)
    args_ok = _run_to_terminal(ctx, args_ok_arn)
    assert args_ok["status"] == "SUCCEEDED", (
        f"Arguments positive control ended {args_ok['status']!r}: "
        f"{args_ok.get('error')!r} {args_ok.get('cause')!r}"
    )
    assert json.loads(args_ok["output"])["Account"] == ctx.account, (
        f"Arguments positive control output {args_ok.get('output')!r} did not name "
        f"this account"
    )


def _pass_def(state_extra: dict) -> dict:
    state = {"Type": "Pass", "End": True}
    state.update(state_extra)
    return {"QueryLanguage": "JSONata", "StartAt": "A", "States": {"A": state}}


def _task_def(resource: str, arguments) -> dict:
    return {
        "QueryLanguage": "JSONata",
        "StartAt": "A",
        "States": {"A": {
            "Type": "Task", "Resource": resource, "Arguments": arguments, "End": True,
        }},
    }


# ===== helpers =====
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
_IAM_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform",
    "States.Permissions",
    "AccessDeniedException",
)


def _execution_role(ctx):
    """A bare execution role: every case here either never reaches a real SDK call, or calls
    sts:GetCallerIdentity, which needs no IAM grant."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnundef-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn jsonata undefined-result execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnundef-sm-")
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
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    try:
        ctx.client("stepfunctions").stop_execution(
            executionArn=exec_arn, error="SimCleanup", cause="sim2real cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _run_to_terminal(ctx, sm_arn, *, timeout_s=60, attempts=6):
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"), input="{}",
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _poll(lambda: sfn.describe_execution(executionArn=exec_arn),
                     lambda d: d["status"] in _TERMINAL, timeout_s=timeout_s,
                     what=f"execution {exec_arn} terminal")
        desc["executionArn"] = exec_arn
        blob = (desc.get("error") or "") + (desc.get("cause") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _IAM_RACE_MARKERS):
            return desc
        time.sleep(5)
    return desc


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, kwargs = [], {"executionArn": exec_arn, "maxResults": 1000}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if not resp.get("nextToken"):
            return events
        kwargs["nextToken"] = resp["nextToken"]


def _eval_failed(ctx, exec_arn):
    return [e["evaluationFailedEventDetails"] for e in _history(ctx, exec_arn)
            if e["type"] == "EvaluationFailed"]


def _poll(probe, predicate, *, timeout_s, what, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what}: not reached within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
