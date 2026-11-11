"""e2e-retry-with-backoff."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-retry-with-backoff"
GROUP = 'e2e_workflows'
SERVICES = ['stepfunctions']

def _create_sfn_role(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=_create_sfn_role(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": "e2e-retry-with-backoff"}],
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

_RETRY_INTERVAL_S = 2
_RETRY_MAX_ATTEMPTS = 2
_RETRY_BACKOFF_RATE = 2.0


# timing:real-time — workflow: 2 s https://docs.aws.amazon.com/step-functions/latest/dg/concepts-error-handling.html
@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Retry with exponential backoff: a failing branch is retried with a growing interval
    before retries are exhausted and Catch routes to a fallback recovery path."""
    definition = {
        "StartAt": "attempt_operation",
        "States": {
            "attempt_operation": {
                "Type": "Parallel",
                "Branches": [
                    {
                        "StartAt": "do_work",
                        "States": {
                            "do_work": {
                                "Type": "Fail",
                                "Error": "ServiceUnavailable",
                                "Cause": "Downstream service timeout",
                            }
                        },
                    }
                ],
                "Retry": [
                    {
                        "ErrorEquals": ["ServiceUnavailable"],
                        "IntervalSeconds": _RETRY_INTERVAL_S,
                        "MaxAttempts": _RETRY_MAX_ATTEMPTS,
                        "BackoffRate": _RETRY_BACKOFF_RATE,
                    }
                ],
                "Catch": [
                    {
                        "ErrorEquals": ["ServiceUnavailable"],
                        "ResultPath": "$.errorInfo",
                        "Next": "fallback_handler",
                    }
                ],
                "Next": "final",
            },
            "fallback_handler": {
                "Type": "Pass",
                "Result": "recovered_via_fallback",
                "ResultPath": "$.recovery",
                "Next": "final",
            },
            "final": {
                "Type": "Succeed",
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition)
    exec_arn = _start_execution(ctx, sm_arn, input_data={"requestId": "req-789"})
    result = _wait_execution_complete(ctx, exec_arn, timeout_s=60)
    assert result["status"] == "SUCCEEDED", (
        f"expected SUCCEEDED via retry-then-catch, got {result.get('status')}: {result!r}"
    )
    output = _get_output(result)
    assert output["recovery"] == "recovered_via_fallback", (
        f"expected fallback recovery after retries exhausted, got {output!r}"
    )
    # Verify error info was captured
    assert output["errorInfo"]["Error"] == "ServiceUnavailable", (
        f"expected the caught error name to survive to $.errorInfo, got {output.get('errorInfo')!r}"
    )

    # Check execution history shows the error was caught
    events = _get_history_events(ctx, exec_arn)
    types = [e["type"] for e in events]
    assert "ExecutionSucceeded" in types, f"expected ExecutionSucceeded, got types={types}"

    # The Retry block must actually have run: the failing branch is entered once per attempt
    # (1 initial + MaxAttempts retries), and the gap between attempts must grow -- the
    # observable signature of exponential backoff, not just a plain fixed-interval retry.
    attempt_ts = [
        e["timestamp"]
        for e in events
        if e["type"] == "FailStateEntered"
        and e.get("stateEnteredEventDetails", {}).get("name") == "do_work"
    ]
    expected_attempts = _RETRY_MAX_ATTEMPTS + 1
    assert len(attempt_ts) == expected_attempts, (
        f"expected {expected_attempts} attempts (1 initial + {_RETRY_MAX_ATTEMPTS} retries) "
        f"at do_work, got {len(attempt_ts)}: types={types}"
    )
    gaps = [
        (attempt_ts[i + 1] - attempt_ts[i]).total_seconds() for i in range(len(attempt_ts) - 1)
    ]
    assert gaps[0] >= _RETRY_INTERVAL_S * 0.5, (
        f"first retry gap {gaps[0]}s is too short for IntervalSeconds={_RETRY_INTERVAL_S}"
    )
    for prev, nxt in zip(gaps, gaps[1:]):
        assert nxt > prev, (
            f"retry gaps did not grow ({gaps}) -- expected BackoffRate={_RETRY_BACKOFF_RATE} "
            f"to increase the interval on each successive attempt"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
