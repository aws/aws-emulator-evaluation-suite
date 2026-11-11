"""deep-sfn-2-sfn-jsonata-states-context-execution-name-and-entered-time."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-2-sfn-jsonata-states-context-execution-name-and-entered-time"
GROUP = 'jsonata'
SERVICES = ['stepfunctions']


# timing:real-time — workflow: 1 s https://docs.aws.amazon.com/step-functions/latest/dg/state-wait.html
@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c3",
    "timing:real-time",
)
def run(ctx) -> None:
    """JSONata `$states.context` carries the chosen execution name, execution ARN and state names.

    State.EnteredTime matches the history's PassStateEntered timestamps and advances across a Wait.
    """
    # The 1-second Wait between the Pass states pins EnteredTime as a real per-state clock.
    role_arn = _create_role(ctx)
    sm_name = ctx.unique_name("sim2real-behav-sfnj-")
    definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "First",
        "States": {
            "First": {
                "Type": "Pass",
                "Output": {
                    "name": "{% $states.context.Execution.Name %}",
                    "execId": "{% $states.context.Execution.Id %}",
                    "marker": "{% $states.context.Execution.Input.marker %}",
                    "sm": "{% $states.context.StateMachine.Name %}",
                    "state": "{% $states.context.State.Name %}",
                    "entered": "{% $states.context.State.EnteredTime %}",
                },
                "Next": "Hold",
            },
            "Hold": {"Type": "Wait", "Seconds": 1, "Next": "Second"},
            "Second": {
                "Type": "Pass",
                "Output": (
                    "{% $merge([$states.input, {"
                    "'state2': $states.context.State.Name, "
                    "'entered2': $states.context.State.EnteredTime, "
                    "'gapMs': $toMillis($states.context.State.EnteredTime) - $toMillis($states.input.entered)"
                    "}]) %}"
                ),
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn, sm_name)

    exec_name = ctx.unique_name("sim2real-behav-ctx-")
    marker = ctx.unique_name("m-")
    exe = _run_to_terminal(ctx, sm_arn, exec_name, {"marker": marker}, timeout_s=60)
    assert exe["status"] == "SUCCEEDED", (
        f"execution {exe['status']!r}: error={exe.get('error')!r} cause={exe.get('cause')!r}"
    )
    out = json.loads(exe["output"])
    ident = {k: out.get(k) for k in ("name", "execId", "marker", "sm", "state", "state2")}
    # _run_to_terminal already asserted DescribeExecution's name is the one this check chose.
    expected = {"name": exe["name"], "execId": exe["executionArn"], "marker": marker,
                "sm": sm_name, "state": "First", "state2": "Second"}
    assert ident == expected, f"$states.context identity fields {ident!r}, expected {expected!r}"

    entered = {e["stateEnteredEventDetails"]["name"]: e["timestamp"]
               for e in _history(ctx, exe["executionArn"]) if e["type"] == "PassStateEntered"}
    assert set(entered) == {"First", "Second"}, f"PassStateEntered events for {sorted(entered)!r}"
    first, second = _parse(out["entered"]), _parse(out["entered2"])
    assert _ms(first) == _ms(entered["First"]) and _ms(second) == _ms(entered["Second"]), (
        f"State.EnteredTime {out['entered']!r}/{out['entered2']!r} disagrees with the history's "
        f"PassStateEntered timestamps {entered['First']!r}/{entered['Second']!r}"
    )
    assert out["gapMs"] == _ms(second) - _ms(first), (
        f"$toMillis gap computed in JSONata {out['gapMs']!r} != {_ms(second) - _ms(first)!r}"
    )
    assert out["gapMs"] >= 1000, (
        f"a 1-second Wait separates the states, yet EnteredTime advanced only {out['gapMs']!r} ms"
    )
    assert exe["startDate"] <= first < second <= exe["stopDate"], (
        f"EnteredTimes {first!r}, {second!r} fall outside the execution window "
        f"{exe['startDate']!r}..{exe['stopDate']!r}"
    )


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
_PROPAGATION_MARKERS = ("not authorized", "AccessDenied", "cannot be assumed", "States.Permissions")


def _parse(stamp):
    """ISO-8601 with a trailing Z, as the context object renders it."""
    assert isinstance(stamp, str) and stamp.endswith("Z"), f"EnteredTime {stamp!r} is not ISO-8601 Z"
    return datetime.fromisoformat(stamp[:-1] + "+00:00").astimezone(timezone.utc)


def _ms(dt):
    return int(round(dt.timestamp() * 1000))


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}]


def _create_role(ctx):
    """A bare execution role: Pass and Wait states call no service."""
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


def _create_state_machine(ctx, definition, role_arn, name):
    sfn = ctx.client("stepfunctions")
    arn = sfn.create_state_machine(
        name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
        tags=[{"key": "sim2real", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _run_to_terminal(ctx, sm_arn, exec_name, input_data, *, timeout_s, max_attempts=4):
    """Start an execution and poll it to terminal; restart only on the IAM-propagation race."""
    sfn = ctx.client("stepfunctions")
    desc = None
    for attempt in range(max_attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=exec_name if attempt == 0 else f"{exec_name}-r{attempt}",
            input=json.dumps(input_data),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            assert desc["name"] == (exec_name if attempt == 0 else f"{exec_name}-r{attempt}"), (
                f"DescribeExecution name {desc['name']!r}"
            )
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
