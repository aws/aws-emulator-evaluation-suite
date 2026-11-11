"""sfn-jsonata-evaluation-failed-location-truncated-over-256-chars."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-jsonata-evaluation-failed-location-truncated-over-256-chars"
GROUP = 'jsonata'
SERVICES = ['stepfunctions']

_UNDEFINED_EXPR = "{% $states.input.missing %}"


def _nested(levels: list[str]):
    """Wrap ``_UNDEFINED_EXPR`` in nested single-key objects, outermost key first in ``levels``."""
    value = _UNDEFINED_EXPR
    for key in reversed(levels):
        value = {key: value}
    return value


def _assign_path(levels: list[str]) -> str:
    return "Assign/variable/" + "/".join(levels)


# 119 one-char levels plus one two-char level: "Assign/variable/" + 119*"k/" + "kk" == 256 chars.
_AT_LIMIT_LEVELS = ["k"] * 119 + ["kk"]
# 121 one-char levels: "Assign/variable/" + 121*"k/"[:-1] == 257 chars, one over the limit.
_OVER_LIMIT_LEVELS = ["k"] * 121


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """An EvaluationFailed location of 256 chars or fewer is reported in full; a 257-char one is
    cut to the base field name, while the cause keeps the full path either way.

    Reference: https://docs.aws.amazon.com/step-functions/latest/apireference/API_EvaluationFailedEventDetails.html
    """
    role_arn = _execution_role(ctx)

    at_limit_path = _assign_path(_AT_LIMIT_LEVELS)
    assert len(at_limit_path) == 256, f"test construction bug: path is {len(at_limit_path)} chars"
    over_limit_path = _assign_path(_OVER_LIMIT_LEVELS)
    assert len(over_limit_path) == 257, f"test construction bug: path is {len(over_limit_path)} chars"

    at_limit_arn = _create_state_machine(ctx, _definition(_AT_LIMIT_LEVELS), role_arn)
    over_limit_arn = _create_state_machine(ctx, _definition(_OVER_LIMIT_LEVELS), role_arn)

    at_limit = _run_to_terminal(ctx, at_limit_arn)
    assert at_limit["status"] == "FAILED", f"at-limit execution ended {at_limit['status']!r}"
    assert at_limit.get("error") == "States.QueryEvaluationError", (
        f"at-limit error {at_limit.get('error')!r}"
    )
    at_limit_cause = at_limit.get("cause") or ""
    assert at_limit_path in at_limit_cause, (
        f"the cause must carry the full 256-char path; got {at_limit_cause!r}"
    )
    at_limit_events = _eval_failed(ctx, at_limit["executionArn"])
    assert len(at_limit_events) == 1, f"expected one EvaluationFailed, got {at_limit_events!r}"
    assert at_limit_events[0]["location"] == at_limit_path, (
        f"a 256-char location must be kept in full; got "
        f"{at_limit_events[0]['location']!r} (length {len(at_limit_events[0]['location'])})"
    )
    assert at_limit_events[0]["cause"] == at_limit_cause, (
        f"DescribeExecution cause {at_limit_cause!r} and the history event's cause "
        f"{at_limit_events[0]['cause']!r} must agree"
    )

    over_limit = _run_to_terminal(ctx, over_limit_arn)
    assert over_limit["status"] == "FAILED", f"over-limit execution ended {over_limit['status']!r}"
    assert over_limit.get("error") == "States.QueryEvaluationError", (
        f"over-limit error {over_limit.get('error')!r}"
    )
    over_limit_cause = over_limit.get("cause") or ""
    assert over_limit_path in over_limit_cause, (
        f"the cause must still carry the full 257-char path even though the location is cut; "
        f"got {over_limit_cause!r}"
    )
    over_limit_events = _eval_failed(ctx, over_limit["executionArn"])
    assert len(over_limit_events) == 1, f"expected one EvaluationFailed, got {over_limit_events!r}"
    assert over_limit_events[0]["location"] == "Assign", (
        f"a location over 256 chars must be cut to the base field name 'Assign'; got "
        f"{over_limit_events[0]['location']!r}"
    )
    assert over_limit_events[0]["cause"] == over_limit_cause, (
        f"DescribeExecution cause {over_limit_cause!r} and the history event's cause "
        f"{over_limit_events[0]['cause']!r} must agree"
    )

    # Positive control, same role and machine shape: a shallow, defined Assign still succeeds.
    # A state's own Assign takes effect for states entered AFTER it, never its own Output.
    ok_arn = _create_state_machine(ctx, {
        "QueryLanguage": "JSONata",
        "StartAt": "A",
        "States": {
            "A": {"Type": "Pass", "Assign": {"variable": "{% 'defined' %}"}, "Next": "B"},
            "B": {"Type": "Pass", "Output": "{% $variable %}", "End": True},
        },
    }, role_arn)
    ok = _run_to_terminal(ctx, ok_arn)
    assert ok["status"] == "SUCCEEDED", (
        f"positive control ended {ok['status']!r}: {ok.get('error')!r} {ok.get('cause')!r}"
    )
    assert ok["output"] == json.dumps("defined"), f"positive control output {ok.get('output')!r}"


def _definition(levels: list[str]) -> dict:
    return {
        "QueryLanguage": "JSONata",
        "StartAt": "A",
        "States": {"A": {
            "Type": "Pass", "Assign": {"variable": _nested(levels)}, "End": True,
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
    """A bare execution role: this check never reaches a real SDK call."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnloc-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn jsonata location execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnloc-sm-")
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
