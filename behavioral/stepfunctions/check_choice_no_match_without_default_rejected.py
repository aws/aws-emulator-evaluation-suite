"""choice-no-match-without-default-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "choice-no-match-without-default-rejected"
GROUP = 'choice_state'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_sfn_role(ctx):
    """An execution role this check creates for its own state machine."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=role_name)))
    return arn


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    # A fresh role takes a few seconds before Step Functions may assume it.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
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


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)


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


# A Choice that matches nothing and has no Default fails with error `States.Runtime`, not the
# `States.NoChoiceMatched` name the ASL specification lists (a Choice state supports neither Retry
# nor Catch, so no other name can surface). The cause string is the distinguishing signal:
#   error: States.Runtime
#   cause: "An error occurred while executing the state 'Route' (entered at the event id #2).
#           Failed to transition out of the state. The state does not point to a next state."
_RUNTIME_ERROR = "States.Runtime"
_NO_MATCH_CAUSE = (
    "Failed to transition out of the state. The state does not point to a next state."
)
_INVALID_PATH_CAUSE = "The choice state's condition path references an invalid value."


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Choice with no Default and no matching rule fails States.Runtime with a cause naming the
    stuck state, distinct from an unresolvable-path cause, and leaves no output; the same machine
    WITH a Default routes the same input to the fallback.
    """
    definition = {
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.kind", "StringEquals": "known", "Next": "Matched"},
                ],
                # deliberately NO "Default"
            },
            "Matched": {"Type": "Pass", "Result": "matched", "End": True},
        },
    }
    sm_arn = _create_state_machine(ctx, definition)

    # Control: the rule matches, so the machine works.
    ok = _wait_execution_complete(
        ctx, _start_execution(ctx, sm_arn, input_data={"kind": "known"}), timeout_s=60
    )
    assert ok["status"] == "SUCCEEDED", (
        f"control execution must succeed, got {ok.get('status')} cause={ok.get('cause')}"
    )
    assert _get_output(ok) == "matched", f"control output wrong: {_get_output(ok)!r}"

    # Negative: break exactly one thing -- the input no longer matches any rule.
    bad_arn = _start_execution(ctx, sm_arn, input_data={"kind": "unknown"})
    bad = _wait_execution_complete(ctx, bad_arn, timeout_s=60)
    assert bad["status"] == "FAILED", (
        f"a Choice with no Default and no matching rule must FAIL the execution, "
        f"got status={bad.get('status')} output={bad.get('output')!r}"
    )
    assert bad.get("error") == _RUNTIME_ERROR, (
        f"expected error {_RUNTIME_ERROR!r}, got {bad.get('error')!r} "
        f"(cause={bad.get('cause')!r})"
    )
    no_match_cause = bad.get("cause") or ""
    assert _NO_MATCH_CAUSE in no_match_cause, (
        f"the cause must say the state could not transition, so a caller can tell an unmatched "
        f"Choice apart from any other States.Runtime failure; got {no_match_cause!r}"
    )
    assert "'Route'" in no_match_cause, (
        f"the cause must name the state that got stuck; got {no_match_cause!r}"
    )
    # Effect absent: no output, and the branch target was never entered.
    assert "output" not in bad or bad.get("output") is None, (
        f"a failed execution must not carry output, got {bad.get('output')!r}"
    )
    events = _get_history_events(ctx, bad_arn)
    types = [e["type"] for e in events]
    assert "ChoiceStateEntered" in types, (
        f"the Choice state must still be entered before failing, history types were {types}"
    )
    entered_names = [
        e["stateEnteredEventDetails"]["name"] for e in events if "stateEnteredEventDetails" in e
    ]
    assert "Matched" not in entered_names, (
        f"the non-matching execution must never enter 'Matched'; entered states were {entered_names}"
    )
    failed = [e for e in events if e["type"] == "ExecutionFailed"]
    assert failed, f"history must contain ExecutionFailed, got {types}"
    assert failed[-1].get("executionFailedEventDetails", {}).get("error") == _RUNTIME_ERROR, (
        f"ExecutionFailed must name the error, got "
        f"{failed[-1].get('executionFailedEventDetails')!r}"
    )
    assert _NO_MATCH_CAUSE in (
        failed[-1].get("executionFailedEventDetails", {}).get("cause") or ""
    ), (
        f"the history event must carry the same cause DescribeExecution reports, got "
        f"{failed[-1].get('executionFailedEventDetails')!r}"
    )

    # A DIFFERENT Choice failure, same error name: the condition path does not resolve at all. This
    # is what makes the cause assertion above load-bearing -- an emulator that answers every Choice
    # problem with one generic States.Runtime cause fails here.
    unresolved = _wait_execution_complete(
        ctx, _start_execution(ctx, sm_arn, input_data={"other": 1}), timeout_s=60
    )
    assert unresolved["status"] == "FAILED", (
        f"a condition path that does not resolve must fail the execution, got "
        f"{unresolved.get('status')} output={unresolved.get('output')!r}"
    )
    assert unresolved.get("error") == _RUNTIME_ERROR, (
        f"an unresolvable condition path is also States.Runtime, got {unresolved.get('error')!r}"
    )
    unresolved_cause = unresolved.get("cause") or ""
    assert _INVALID_PATH_CAUSE in unresolved_cause, (
        f"the cause must identify the unresolvable condition path; got {unresolved_cause!r}"
    )
    assert unresolved_cause != no_match_cause, (
        "an unmatched Choice and an unresolvable condition path are different failures and must "
        f"not collapse into one byte-identical cause; both said {no_match_cause!r}"
    )

    # The failure is attributable to the MISSING Default, not to the input: the same non-matching
    # input against a machine differing only by a Default routes cleanly to the fallback.
    with_default = {
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.kind", "StringEquals": "known", "Next": "Matched"},
                ],
                "Default": "Fallback",
            },
            "Matched": {"Type": "Pass", "Result": "matched", "End": True},
            "Fallback": {"Type": "Pass", "Result": "fell-back", "End": True},
        },
    }
    default_arn = _create_state_machine(ctx, with_default)
    fell_back = _wait_execution_complete(
        ctx, _start_execution(ctx, default_arn, input_data={"kind": "unknown"}), timeout_s=60
    )
    assert fell_back["status"] == "SUCCEEDED", (
        f"adding a Default must make the identical non-matching input succeed, got "
        f"{fell_back.get('status')} error={fell_back.get('error')!r} cause={fell_back.get('cause')!r}"
    )
    assert _get_output(fell_back) == "fell-back", (
        f"the non-matching input must be routed to the Default target, got "
        f"{_get_output(fell_back)!r}"
    )

    # The control case still works after the failure -- the state machine was not poisoned.
    again = _wait_execution_complete(
        ctx, _start_execution(ctx, sm_arn, input_data={"kind": "known"}), timeout_s=60
    )
    assert again["status"] == "SUCCEEDED" and _get_output(again) == "matched", (
        f"the matching path must still work after a no-match failure, got "
        f"{again.get('status')} / {_get_output(again)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
