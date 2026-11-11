"""retry-error-name-specificity-not-retried."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retry-error-name-specificity-not-retried"
GROUP = 'error_handling'
SERVICES = ['stepfunctions']


# ===== helpers =====
_SFN_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_sfn_role(ctx):
    """An execution role this check creates, trusted by states.amazonaws.com."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_SFN_TRUST),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retrying AccessDeniedException while a fresh role's trust propagates."""
    deadline = time.monotonic() + 90.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(definition),
        roleArn=_create_sfn_role(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _get_history_events(ctx, exec_arn, *, reverse=False):
    sfn = ctx.client("stepfunctions")
    events = []
    kwargs = {"executionArn": exec_arn, "reverseOrder": reverse}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if "nextToken" not in resp:
            break
        kwargs["nextToken"] = resp["nextToken"]
    return events
# ===== end helpers =====


def _machine(retry_on):
    """A Parallel state whose only branch fails with 'BranchBoom', guarded by one retrier."""
    return {
        "StartAt": "Guarded",
        "States": {
            "Guarded": {
                "Type": "Parallel",
                "Branches": [
                    {
                        "StartAt": "Boom",
                        "States": {
                            "Boom": {
                                "Type": "Fail",
                                "Error": "BranchBoom",
                                "Cause": "deliberate failure",
                            }
                        },
                    }
                ],
                "Retry": [
                    {
                        "ErrorEquals": [retry_on],
                        "IntervalSeconds": 1,
                        "MaxAttempts": 2,
                        "BackoffRate": 2.0,
                    }
                ],
                "End": True,
            }
        },
    }


def _attempts(ctx, exec_arn):
    """How many times the guarded state actually ran, counted from history.

    On AWS a retry re-runs the state WITHOUT emitting a second StateEntered event. A Parallel state retried to exhaustion produces the history

        ExecutionStarted, ParallelStateEntered,
        ParallelStateStarted, FailStateEntered,     <- attempt 1
        ParallelStateStarted, FailStateEntered,     <- attempt 2 (retry 1)
        ParallelStateStarted, FailStateEntered,     <- attempt 3 (retry 2)
        ParallelStateFailed, ExecutionFailed

    so ParallelStateEntered appears exactly ONCE however many attempts run, and
    ParallelStateStarted is the per-attempt event. Both counts are returned: the entered count is
    itself asserted below, because "entering a state" and "starting an attempt at it" are distinct
    events in real AWS and an emulator that conflates them (re-emitting StateEntered per retry) is
    wrong in a way that breaks any consumer counting attempts from history.
    """
    events = _get_history_events(ctx, exec_arn)
    return (
        len([e for e in events if e["type"] == "ParallelStateEntered"]),
        len([e for e in events if e["type"] == "ParallelStateStarted"]),
        len(
            [
                e
                for e in events
                if e.get("stateEnteredEventDetails", {}).get("name") == "Boom"
            ]
        ),
        [e["type"] for e in events],
    )


# timing:real-time — workflow: 1 s https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Retry whose ErrorEquals does not name the raised error does not retry, while the exact name
    and States.ALL retry to MaxAttempts; attempts are counted from ParallelStateStarted in history,
    and ParallelStateEntered appears once however many attempts run.
    """
    # Negative: the retrier names an error the branch never raises.
    mismatch_arn = _start_execution(
        ctx, _create_state_machine(ctx, _machine("SomeOtherError")), input_data={}
    )
    mismatch = _wait_execution_complete(ctx, mismatch_arn, timeout_s=90)
    assert mismatch["status"] == "FAILED", (
        f"an unretried, uncaught branch failure must FAIL the execution, got "
        f"{mismatch.get('status')}"
    )
    assert mismatch.get("error") == "BranchBoom", (
        f"the execution must fail with the branch's own error name, got {mismatch.get('error')!r}"
    )
    parallel_entries, parallel_starts, boom_entries, types = _attempts(ctx, mismatch_arn)
    assert parallel_starts == 1, (
        f"a retrier on 'SomeOtherError' must NOT retry a 'BranchBoom' failure: the guarded state "
        f"was attempted {parallel_starts} times (expected 1). History: {types}"
    )
    assert parallel_entries == 1, (
        f"the guarded state must be entered exactly once, got {parallel_entries}. History: {types}"
    )
    assert boom_entries == 1, (
        f"the failing branch must run exactly once when the retrier does not match, ran "
        f"{boom_entries} times. History: {types}"
    )
    mismatch_elapsed = (mismatch["stopDate"] - mismatch["startDate"]).total_seconds()

    # Control 1: the retrier names the raised error exactly -> 1 initial attempt + 2 retries.
    match_arn = _start_execution(
        ctx, _create_state_machine(ctx, _machine("BranchBoom")), input_data={}
    )
    match = _wait_execution_complete(ctx, match_arn, timeout_s=120)
    assert match["status"] == "FAILED", (
        f"retries eventually exhaust and the execution still fails, got {match.get('status')}"
    )
    assert match.get("error") == "BranchBoom", (
        f"after exhausting retries the error name is unchanged, got {match.get('error')!r}"
    )
    m_entered, m_started, m_boom, m_types = _attempts(ctx, match_arn)
    assert m_started == 3 and m_boom == 3, (
        f"MaxAttempts=2 means 1 initial attempt + 2 retries = 3 runs of the guarded state; got "
        f"parallel_started={m_started} boom_entered={m_boom}. History: {m_types}"
    )
    # The retry is NOT a re-entry: real AWS emits ParallelStateEntered once and reports each
    # subsequent attempt as another ParallelStateStarted. An emulator that re-enters the state per
    # retry would report 3 here and mis-state the history any consumer reads attempts from.
    assert m_entered == 1, (
        f"a retried state is entered once and re-STARTED per attempt, so ParallelStateEntered must "
        f"appear exactly once across {m_started} attempts; got {m_entered}. History: {m_types}"
    )
    # IntervalSeconds=1 with BackoffRate=2 means the retries wait 1s then 2s.
    match_elapsed = (match["stopDate"] - match["startDate"]).total_seconds()
    assert match_elapsed >= 2.5, (
        f"BackoffRate must actually delay the retries (>=1s + 2s), but the retried execution took "
        f"only {match_elapsed:.1f}s (the non-retried one took {mismatch_elapsed:.1f}s)"
    )

    # Control 2: States.ALL matches a custom error name too.
    all_arn = _start_execution(
        ctx, _create_state_machine(ctx, _machine("States.ALL")), input_data={}
    )
    all_desc = _wait_execution_complete(ctx, all_arn, timeout_s=120)
    assert all_desc["status"] == "FAILED", (
        f"States.ALL retries then still fails, got {all_desc.get('status')}"
    )
    a_entered, a_started, a_boom, a_types = _attempts(ctx, all_arn)
    assert a_started == 3 and a_boom == 3, (
        f"a States.ALL retrier must match the custom error 'BranchBoom' and retry twice; got "
        f"parallel_started={a_started} boom_entered={a_boom}. History: {a_types}"
    )
    assert a_entered == 1, (
        f"ParallelStateEntered must appear once under States.ALL retries too; got {a_entered}. "
        f"History: {a_types}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
