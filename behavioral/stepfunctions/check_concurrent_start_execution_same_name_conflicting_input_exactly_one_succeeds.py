"""concurrent-start-execution-same-name-conflicting-input-exactly-one-succeeds."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-start-execution-same-name-conflicting-input-exactly-one-succeeds"
GROUP = 'execution_lifecycle'
SERVICES = ['stepfunctions']


_ROLE_ARNS = {}


def _execution_role_arn(ctx):
    """Create one Step Functions execution role per check run and register its cleanup."""
    key = id(ctx)
    if key in _ROLE_ARNS:
        return _ROLE_ARNS[key]
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
    ctx.on_cleanup(lambda: _ROLE_ARNS.pop(key, None))
    _ROLE_ARNS[key] = arn
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retried while a just-created role is still propagating in IAM."""
    deadline = time.monotonic() + 60.0
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
        roleArn=_execution_role_arn(ctx),
        type=sm_type,
        tags=[{"key": "sim2real", "value": "1"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _asl_wait(seconds):
    return {
        "Comment": "behavioral-wait",
        "StartAt": "W",
        "States": {"W": {"Type": "Wait", "Seconds": seconds, "End": True}},
    }


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:rejection", "cap:c2", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Six concurrent StartExecution calls with the same name but different inputs yield exactly one
    execution, listed under the winner's ARN; every other racer fails ExecutionAlreadyExists with the
    exact message naming that ARN."""
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_wait(15))
    exec_name = ctx.unique_name("sim2real-behav-race-conflict-")

    def make_racer(i: int):
        def racer():
            return sfn.start_execution(stateMachineArn=arn, name=exec_name, input=json.dumps({"racer": i}))

        return racer

    racers = [make_racer(i) for i in range(6)]
    results = _run_concurrent(racers)

    successes = _concurrent_successes(results)
    assert successes == 1, f"expected exactly one racer to win the name, got {successes} successes: {results}"

    error_codes = _concurrent_error_codes(results)
    assert all(c == "ExecutionAlreadyExists" for c in error_codes), (
        f"expected every losing racer to get ExecutionAlreadyExists, got {error_codes}"
    )
    assert len(error_codes) == len(results) - 1, f"expected exactly {len(results) - 1} losers, got {results}"

    winner_arn = next(r["executionArn"] for r in results if not isinstance(r, BaseException))
    expected = f"Execution Already Exists: '{winner_arn}'"
    messages = [r.response["Error"].get("Message") for r in results if isinstance(r, ClientError)]
    assert messages == [expected] * (len(results) - 1), (
        f"expected every losing racer's message to be {expected!r}, got {messages}"
    )

    listed = sfn.list_executions(stateMachineArn=arn)
    matching = [e for e in listed["executions"] if e["name"] == exec_name]
    assert len(matching) == 1, (
        f"expected exactly one execution named {exec_name!r} visible at the destination, found {matching}"
    )
    assert matching[0]["executionArn"] == winner_arn, (
        f"the execution visible via ListExecutions must be the racer that won StartExecution: "
        f"listed={matching[0]['executionArn']!r}, winner={winner_arn!r}"
    )

    sfn.stop_execution(executionArn=winner_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
