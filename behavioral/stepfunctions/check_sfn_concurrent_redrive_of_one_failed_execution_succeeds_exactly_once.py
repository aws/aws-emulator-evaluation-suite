"""sfn-concurrent-redrive-of-one-failed-execution-succeeds-exactly-once."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sfn-concurrent-redrive-of-one-failed-execution-succeeds-exactly-once"
GROUP = 'concurrency'
SERVICES = ['stepfunctions']

_THREADS = 6
#: The ASL error name real AWS reports for aws-sdk:sfn:describeStateMachine on an absent ARN.
_ERROR_NAME = "Sfn.StateMachineDoesNotExistException"


@tags("axis:happy-path", "concern:representation", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """Six threads redriving one FAILED execution produce exactly one redrive: every loser fails
    ExecutionNotRedrivable with the exact "is RUNNING" message, redriveCount ends at 1, and the history
    holds one ExecutionRedriven event and keeps the original failure."""
    sfn = ctx.client("stepfunctions")

    _role_name, role_arn = _create_sfn_role(
        ctx, [{"Effect": "Allow", "Action": "states:DescribeStateMachine", "Resource": "*"}]
    )
    # The Retry makes the failing state take ~15 s, so the redriven attempt is still RUNNING
    # while the losers call; otherwise a loser could legitimately redrive the re-failed execution.
    definition = {
        "Comment": "a task that always fails, slowly enough to keep a redrive in flight",
        "StartAt": "Describe",
        "States": {
            "Describe": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:sfn:describeStateMachine",
                "Parameters": {"StateMachineArn.$": "$.target"},
                "Retry": [{
                    "ErrorEquals": [_ERROR_NAME],
                    "MaxAttempts": 3,
                    "IntervalSeconds": 5,
                    "BackoffRate": 1.0,
                }],
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn)
    absent_arn = sm_arn.rsplit(":", 1)[0] + ":sim2real-behav-absent-sm"

    failed = _run_to_terminal(ctx, sm_arn, {"target": absent_arn}, timeout_s=180.0)
    assert failed["status"] == "FAILED", (
        f'the execution to be redriven was {failed["status"]!r}, expected FAILED: '
        f'{failed.get("error")!r} {failed.get("cause")!r}'
    )
    exec_arn = failed["executionArn"]
    history_before = _full_history(ctx, exec_arn)
    failed_event_ids_before = {
        e["id"] for e in history_before if e["type"] == "ExecutionFailed"
    }
    assert failed_event_ids_before, (
        f"no ExecutionFailed event in the original history: "
        f'{[e["type"] for e in history_before]!r}'
    )

    def _redrive(_i):
        try:
            sfn.redrive_execution(executionArn=exec_arn)
            return True, None, None
        except ClientError as exc:
            return False, exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    with ThreadPoolExecutor(max_workers=_THREADS) as pool:
        results = list(pool.map(_redrive, range(_THREADS)))

    successes = [r for r in results if r[0]]
    loser_codes = sorted({r[1] for r in results if not r[0]})
    assert len(successes) == 1, (
        f"{len(successes)!r} of {_THREADS!r} concurrent redrives succeeded; the loser codes "
        f"were {loser_codes!r}"
    )
    assert loser_codes == ["ExecutionNotRedrivable"], (
        f"the losing threads reported {loser_codes!r}, expected every one of them to be "
        f"exactly ExecutionNotRedrivable"
    )
    # The winner's redrive has already moved the execution back to RUNNING when a loser is refused.
    expected = f"Execution {exec_arn} invalid for redrive as: Execution is RUNNING and cannot be redriven"
    loser_messages = sorted({r[2] for r in results if not r[0]})
    assert loser_messages == [expected], f"expected every loser's message to be {expected!r}, got {loser_messages!r}"

    redriven = _wait_terminal(ctx, exec_arn, timeout_s=180.0)
    assert redriven["redriveCount"] == 1, (
        f'redriveCount is {redriven["redriveCount"]!r} after {_THREADS!r} concurrent redrives, '
        f"expected exactly 1"
    )

    history_after = _full_history(ctx, exec_arn)
    redriven_events = [e for e in history_after if e["type"] == "ExecutionRedriven"]
    assert len(redriven_events) == 1, (
        f"{len(redriven_events)!r} ExecutionRedriven events in the history after "
        f"{_THREADS!r} concurrent redrives; event types were "
        f'{[e["type"] for e in history_after]!r}'
    )
    assert failed_event_ids_before <= {e["id"] for e in history_after}, (
        f"the redrive erased the original failure from the history: ids "
        f"{sorted(failed_event_ids_before)!r} are gone"
    )


def _create_sfn_role(ctx, statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real-behav sfn execution role",
    )["Role"]["Arn"]
    policy_name = f"{role_name}-policy"

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation exposes no condition to poll; the bounded retries in _create_state_machine
    # and _run_to_terminal absorb it.
    return role_name, role_arn


def _create_state_machine(ctx, definition, role_arn, *, sm_type="STANDARD",
                          name_prefix="sim2real-behav-sm-"):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name(name_prefix)
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type=sm_type
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the role: {last!r}")


_TRUST_RACE_MARKERS = (
    "not authorized to assume",
    "cannot be assumed",
    "is not authorized to perform: sts:AssumeRole",
    "States.Permissions",
)


def _run_to_terminal(ctx, sm_arn, input_payload, *, timeout_s=120.0, max_attempts=6):
    """Start an execution and poll to terminal, retrying only when the failure cause is the IAM
    propagation race rather than the induced ASL error (this check wants a FAILED execution)."""
    sfn = ctx.client("stepfunctions")
    desc = None
    for _ in range(max_attempts):
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn,
            name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(input_payload),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _best_effort_stop(ctx, a))
        desc = _wait_terminal(ctx, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if not any(m in blob for m in _TRUST_RACE_MARKERS):
            return desc
        time.sleep(5)
    return desc


def _wait_terminal(ctx, exec_arn, *, timeout_s=120.0, interval_s=1.5):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} was not terminal within {timeout_s}s: {last!r}")


def _best_effort_stop(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    try:
        sfn.stop_execution(executionArn=exec_arn, error="cleanup", cause="sim2real cleanup")
    except ClientError as exc:
        # StopExecution is a no-op on a terminal execution; only a vanished one is not an error.
        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
            raise


def _full_history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events, token = [], None
    while True:
        kwargs = {"executionArn": exec_arn, "maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return events


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
