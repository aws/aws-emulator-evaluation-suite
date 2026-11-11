"""deep-sfn-2-sfn-jsonata-mixed-query-language-state-override."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-2-sfn-jsonata-mixed-query-language-state-override"
GROUP = 'jsonata'
SERVICES = ['stepfunctions']


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """In a JSONPath machine, one state's `QueryLanguage: JSONata` switches the evaluator for that
    state alone: each hop emits exactly the document the next consumes, joined to the
    PassStateExited history events."""
    role_arn = _create_role(ctx)
    definition = {
        "StartAt": "PathIn",
        "States": {
            "PathIn": {
                "Type": "Pass",
                "Parameters": {"x.$": "$.a", "lit": "{% $states.input.a %}"},
                "ResultPath": "$.p",
                "Next": "Nata",
            },
            "Nata": {
                "Type": "Pass",
                "QueryLanguage": "JSONata",
                "Output": {
                    "doubled": "{% $states.input.p.x * 2 %}",
                    "lit": "{% $states.input.p.lit %}",
                    "isLiteral": "{% $states.input.p.lit = '{' & '% $states.input.a %' & '}' %}",
                    "a": "{% $states.input.a %}",
                },
                "Next": "PathOut",
            },
            "PathOut": {
                "Type": "Pass",
                "Parameters": {"v.$": "$.doubled", "notEvaluated": "{% 1 + 1 %}"},
                "ResultPath": "$.c",
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)

    exe = _run_to_terminal(ctx, sm_arn, {"a": 21}, timeout_s=60)
    assert exe["status"] == "SUCCEEDED", (
        f"execution {exe['status']!r}: error={exe.get('error')!r} cause={exe.get('cause')!r}"
    )
    out = json.loads(exe["output"])
    expected = {
        "doubled": 42,
        "lit": "{% $states.input.a %}",
        "isLiteral": True,
        "a": 21,
        "c": {"v": 42, "notEvaluated": "{% 1 + 1 %}"},
    }
    assert out == expected, (
        f"mixed-language output {out!r}, expected {expected!r}: '{{% %}}' must be literal in the "
        f"JSONPath states and evaluated only in the JSONata-overridden one"
    )

    events = _history(ctx, exe["executionArn"])
    exited = [(e["stateExitedEventDetails"]["name"], json.loads(e["stateExitedEventDetails"]["output"]))
              for e in events if e["type"] == "PassStateExited"]
    assert [n for n, _ in exited] == ["PathIn", "Nata", "PathOut"], (
        f"Pass states exited {[n for n, _ in exited]!r}"
    )
    assert exited[0][1] == {"a": 21, "p": {"x": 21, "lit": "{% $states.input.a %}"}}, (
        f"the JSONPath state's output was {exited[0][1]!r}"
    )
    assert exited[1][1] == {k: expected[k] for k in ("doubled", "lit", "isLiteral", "a")}, (
        f"the JSONata state's output was {exited[1][1]!r}: Output REPLACES the document in JSONata"
    )


# ===== helpers =====
_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
_PROPAGATION_MARKERS = ("not authorized", "AccessDenied", "cannot be assumed", "States.Permissions")


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}]


def _create_role(ctx):
    """A bare execution role: Pass states call no service."""
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


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnj-")
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


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 1000}
        if token:
            kwargs["nextToken"] = token
        page = sfn.get_execution_history(**kwargs)
        events.extend(page["events"])
        token = page.get("nextToken")
        if not token:
            return events


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
