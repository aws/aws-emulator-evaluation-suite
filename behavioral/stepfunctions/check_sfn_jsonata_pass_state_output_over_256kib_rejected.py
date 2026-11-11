"""sfn-jsonata-pass-state-output-over-256kib-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-jsonata-pass-state-output-over-256kib-rejected"
GROUP = 'jsonata'
SERVICES = ['stepfunctions']

_UNDER_HALF = 100 * 1024   # doubled below, well under the 256 KiB result limit
_OVER_HALF = 150 * 1024    # doubled above it
_STATE_NAME = "PassState"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3",
)
def run(ctx) -> None:
    """A JSONata Pass state whose Output evaluates over the 256 KiB state result limit fails
    with States.DataLimitExceeded naming the STATE, not a resource, as the 256 KiB Lambda-result
    check does; a result just under the limit still succeeds intact.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/limits-overview.html
    """
    role_arn = _execution_role(ctx)
    sm_arn = _create_state_machine(ctx, {
        "QueryLanguage": "JSONata",
        "StartAt": _STATE_NAME,
        "States": {_STATE_NAME: {
            "Type": "Pass",
            # Concatenating two already-materialized strings keeps evaluation cheap; building the
            # same size with a string-generating function trips JSONata's own evaluation-memory
            # guard well before the state result limit, which is a different failure mode.
            "Output": "{% $states.input.blob & $states.input.blob %}",
            "End": True,
        }},
    }, role_arn)

    ok = _run_to_terminal(ctx, sm_arn, {"blob": "x" * _UNDER_HALF})
    assert ok["status"] == "SUCCEEDED", (
        f"positive control: a doubled {_UNDER_HALF}-char result ended {ok['status']!r}: "
        f"{ok.get('error')!r} {ok.get('cause')!r}"
    )
    assert ok["output"] == json.dumps("x" * (2 * _UNDER_HALF)), (
        f"positive control: the doubled result did not arrive intact "
        f"(output length {len(ok.get('output') or '')!r})"
    )

    bad = _run_to_terminal(ctx, sm_arn, {"blob": "x" * _OVER_HALF})
    assert bad["status"] == "FAILED", (
        f"a doubled {_OVER_HALF}-char result ended {bad['status']!r}, expected FAILED"
    )
    assert bad.get("error") == "States.DataLimitExceeded", (
        f"the oversize result failed with {bad.get('error')!r} ({bad.get('cause')!r}), "
        f"expected States.DataLimitExceeded"
    )
    expected_cause = (
        f"The state/task '{_STATE_NAME}' returned a result with a size exceeding the maximum "
        "number of bytes service limit."
    )
    assert bad.get("cause") == expected_cause, (
        f"expected cause {expected_cause!r}, got {bad.get('cause')!r} -- a Pass state names "
        f"itself, unlike a Task, which names the resource it invoked"
    )
    assert bad.get("output") is None, "the refused execution produced output"

    events = _history(ctx, bad["executionArn"])
    types = [e["type"] for e in events]
    assert types.count("PassStateExited") == 0, (
        f"the oversize result was recorded as a state result: {types!r}"
    )
    eval_failed = [e["evaluationFailedEventDetails"] for e in events if e["type"] == "EvaluationFailed"]
    assert len(eval_failed) == 1, f"expected exactly one EvaluationFailed event, got {eval_failed!r}"
    assert eval_failed[0].get("error") == "States.DataLimitExceeded", (
        f"EvaluationFailed carried {eval_failed[0]!r}"
    )
    assert eval_failed[0].get("cause") == expected_cause, (
        f"EvaluationFailed cause {eval_failed[0].get('cause')!r}, expected {expected_cause!r}"
    )
    assert eval_failed[0].get("location") == "Output", (
        f"EvaluationFailed location {eval_failed[0].get('location')!r}, expected 'Output'"
    )
    assert eval_failed[0].get("state") == _STATE_NAME, (
        f"EvaluationFailed state {eval_failed[0].get('state')!r}, expected {_STATE_NAME!r}"
    )
    failed = [e["executionFailedEventDetails"] for e in events if e["type"] == "ExecutionFailed"]
    assert len(failed) == 1 and failed[0].get("error") == "States.DataLimitExceeded", (
        f"ExecutionFailed was {failed!r}"
    )
    assert failed[0].get("cause") == expected_cause, (
        f"expected ExecutionFailed cause {expected_cause!r}, got {failed[0].get('cause')!r}"
    )

    # Positive control again, same machine: the earlier failure did not poison it.
    ok2 = _run_to_terminal(ctx, sm_arn, {"blob": "y" * _UNDER_HALF})
    assert ok2["status"] == "SUCCEEDED", (
        f"repeat positive control ended {ok2['status']!r}: {ok2.get('error')!r} {ok2.get('cause')!r}"
    )


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
    name = ctx.unique_name("sim2real-behav-sfnj-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                       "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn jsonata execution role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, definition, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnj-sm-")
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


def _run_to_terminal(ctx, sm_arn, payload, *, timeout_s=60, attempts=6):
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(payload),
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
